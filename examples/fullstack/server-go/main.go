// Command opaque-fullstack-server is an HTTP OPAQUE server implementing the
// full-stack interop contract in ../protocol.md, using
// github.com/bytemare/opaque v0.18.0 (RFC 9807).
//
// Crypto suite: ristretto255-SHA512 (OPRF + AKE), HKDF-SHA512 / HMAC-SHA512 /
// SHA-512, context "opaque-zig-fullstack-v1". The server never runs the KSF.
package main

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque"
)

// contextString is hashed into the AKE transcript; it must match every peer
// implementation byte-for-byte or KE2/KE3 MAC verification fails silently.
const contextString = "opaque-zig-fullstack-v1"

// suiteString is the human-readable suite name reported by /health.
const suiteString = "ristretto255-SHA512"

// newConfiguration builds the shared OPAQUE configuration from the contract.
func newConfiguration() *opaque.Configuration {
	return &opaque.Configuration{
		OPRF:    opaque.RistrettoSha512,
		AKE:     opaque.RistrettoSha512,
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		KSF:     ksf.Argon2id,
		Context: []byte(contextString),
	}
}

// pendingLogin is the per-login state stashed between /login/start and
// /login/finish, keyed by a random login_id.
type pendingLogin struct {
	clientMAC     []byte
	sessionSecret []byte
	username      string
}

// state holds all mutable server state behind a single mutex. The bytemare
// Server itself is thread-safe given fixed key material, so it lives outside
// the lock.
type state struct {
	conf   *opaque.Configuration
	server *opaque.Server

	mu      sync.Mutex
	records map[string]*opaque.ClientRecord // username -> stored record
	pending map[string]*pendingLogin        // login_id -> per-login state
}

// ---- JSON request/response shapes (see protocol.md) ----

type registerStartReq struct {
	Username            string `json:"username"`
	RegistrationRequest string `json:"registration_request"`
}

type registerStartResp struct {
	RegistrationResponse string `json:"registration_response"`
}

type registerFinishReq struct {
	Username           string `json:"username"`
	RegistrationRecord string `json:"registration_record"`
}

type registerFinishResp struct {
	OK bool `json:"ok"`
}

type loginStartReq struct {
	Username string `json:"username"`
	KE1      string `json:"ke1"`
}

type loginStartResp struct {
	LoginID string `json:"login_id"`
	KE2     string `json:"ke2"`
}

type loginFinishReq struct {
	LoginID string `json:"login_id"`
	KE3     string `json:"ke3"`
}

type loginFinishResp struct {
	Authenticated bool `json:"authenticated"`
}

type healthResp struct {
	OK      bool   `json:"ok"`
	Context string `json:"context"`
	Suite   string `json:"suite"`
}

type errorResp struct {
	Error string `json:"error"`
}

// writeJSON serializes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError responds with a non-2xx status and {"error": msg}.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResp{Error: msg})
}

// decodeJSON reads and unmarshals the JSON request body into dst. It returns
// false (and writes a 400) on any failure.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// decodeField base64-decodes (standard, padded) a required field, writing a 400
// and returning ok=false if it is empty or malformed.
func decodeField(w http.ResponseWriter, name, value string) ([]byte, bool) {
	if value == "" {
		writeError(w, http.StatusBadRequest, "missing "+name)
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in "+name)
		return nil, false
	}
	return b, true
}

// newLoginID returns a random URL-safe login identifier.
func newLoginID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// ---- handlers ----

func (s *state) handleRegisterStart(w http.ResponseWriter, r *http.Request) {
	var req registerStartReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "missing username")
		return
	}
	reqBytes, ok := decodeField(w, "registration_request", req.RegistrationRequest)
	if !ok {
		return
	}

	regReq, err := s.server.Deserialize.RegistrationRequest(reqBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid registration_request")
		return
	}
	// nil OPRF key => derive per-credential key from the global seed + username.
	regResp, err := s.server.RegistrationResponse(regReq, []byte(req.Username), nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration response failed")
		return
	}

	writeJSON(w, http.StatusOK, registerStartResp{
		RegistrationResponse: base64.StdEncoding.EncodeToString(regResp.Serialize()),
	})
}

func (s *state) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var req registerFinishReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "missing username")
		return
	}
	recordBytes, ok := decodeField(w, "registration_record", req.RegistrationRecord)
	if !ok {
		return
	}

	rec, err := s.server.Deserialize.RegistrationRecord(recordBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid registration_record")
		return
	}
	stored := &opaque.ClientRecord{
		CredentialIdentifier: []byte(req.Username),
		ClientIdentity:       nil,
		RegistrationRecord:   rec,
	}

	s.mu.Lock()
	s.records[req.Username] = stored
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, registerFinishResp{OK: true})
}

func (s *state) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	var req loginStartReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "missing username")
		return
	}
	ke1Bytes, ok := decodeField(w, "ke1", req.KE1)
	if !ok {
		return
	}

	ke1, err := s.server.Deserialize.KE1(ke1Bytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid ke1")
		return
	}

	// Look up the stored record. For an unknown user, use a fake record so the
	// KE2 is well-formed and indistinguishable (anti-enumeration). Login then
	// fails at the MAC check in /login/finish.
	s.mu.Lock()
	stored, known := s.records[req.Username]
	s.mu.Unlock()

	if !known {
		fake, ferr := s.conf.GetFakeRecord([]byte(req.Username))
		if ferr != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		stored = fake
	}

	ke2, serverOut, err := s.server.GenerateKE2(ke1, stored)
	if err != nil {
		// A malformed-but-deserializable KE1 can still fail here; treat as bad input.
		writeError(w, http.StatusBadRequest, "login start failed")
		return
	}

	loginID, err := newLoginID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.mu.Lock()
	s.pending[loginID] = &pendingLogin{
		clientMAC:     serverOut.ClientMAC,
		sessionSecret: serverOut.SessionSecret,
		username:      req.Username,
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, loginStartResp{
		LoginID: loginID,
		KE2:     base64.StdEncoding.EncodeToString(ke2.Serialize()),
	})
}

func (s *state) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req loginFinishReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.LoginID == "" {
		writeError(w, http.StatusBadRequest, "missing login_id")
		return
	}
	ke3Bytes, ok := decodeField(w, "ke3", req.KE3)
	if !ok {
		return
	}

	// Consume the login_id either way (success or failure).
	s.mu.Lock()
	pl, found := s.pending[req.LoginID]
	if found {
		delete(s.pending, req.LoginID)
	}
	s.mu.Unlock()

	if !found {
		writeError(w, http.StatusBadRequest, "unknown login_id")
		return
	}

	ke3, err := s.server.Deserialize.KE3(ke3Bytes)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, loginFinishResp{Authenticated: false})
		return
	}

	if err := s.server.LoginFinish(ke3, pl.clientMAC); err != nil {
		writeJSON(w, http.StatusUnauthorized, loginFinishResp{Authenticated: false})
		return
	}

	// Authenticated: prove mutual auth by printing the session key to stderr.
	fmt.Fprintf(os.Stderr, "SESSION_KEY %s %s\n", pl.username, hex.EncodeToString(pl.sessionSecret))
	writeJSON(w, http.StatusOK, loginFinishResp{Authenticated: true})
}

func (s *state) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResp{
		OK:      true,
		Context: contextString,
		Suite:   suiteString,
	})
}

// newState builds the OPAQUE configuration, generates the server's long-term
// key material once, and returns a ready-to-serve state.
func newState() (*state, error) {
	conf := newConfiguration()

	server, err := conf.Server()
	if err != nil {
		return nil, fmt.Errorf("create server: %w", err)
	}

	oprfSeed := conf.GenerateOPRFSeed()
	serverSK, serverPK := conf.KeyGen()
	serverPKBytes := serverPK.Encode()

	skm := &opaque.ServerKeyMaterial{
		PrivateKey:     serverSK,
		PublicKeyBytes: serverPKBytes,
		OPRFGlobalSeed: oprfSeed,
		Identity:       nil,
	}
	if err := server.SetKeyMaterial(skm); err != nil {
		return nil, fmt.Errorf("set key material: %w", err)
	}

	return &state{
		conf:    conf,
		server:  server,
		records: make(map[string]*opaque.ClientRecord),
		pending: make(map[string]*pendingLogin),
	}, nil
}

// routes wires the handlers onto a mux.
func (s *state) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/register/start", s.handleRegisterStart)
	mux.HandleFunc("/register/finish", s.handleRegisterFinish)
	mux.HandleFunc("/login/start", s.handleLoginStart)
	mux.HandleFunc("/login/finish", s.handleLoginFinish)
	mux.HandleFunc("/health", s.handleHealth)
	return mux
}

func main() {
	s, err := newState()
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8787"
	}
	addr := ":" + port

	// Log the server public key (hex) so peers/operators can confirm identity.
	pkHex := hex.EncodeToString(s.server.ServerKeyMaterial.PublicKeyBytes)
	log.Printf("server public key (hex): %s", pkHex)
	log.Printf("suite=%s context=%s", suiteString, contextString)

	// The runner waits for this line / for /health to succeed.
	log.Printf("listening on %s", addr)

	if err := http.ListenAndServe(addr, s.routes()); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
