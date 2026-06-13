package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/bytemare/opaque"
)

// testServer spins up the real handlers behind an httptest.Server.
func testServer(t *testing.T) (*httptest.Server, *state) {
	t.Helper()
	s, err := newState()
	if err != nil {
		t.Fatalf("newState: %v", err)
	}
	ts := httptest.NewServer(s.routes())
	t.Cleanup(ts.Close)
	return ts, s
}

// postJSON posts v as JSON to path and decodes the response into out (if non-nil).
// It returns the HTTP status code.
func postJSON(t *testing.T, base, path string, v any, out any) int {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	resp, err := http.Post(base+path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("unmarshal %s response (%q): %v", path, string(raw), err)
		}
	}
	return resp.StatusCode
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64 %q: %v", s, err)
	}
	return b
}

// registerClient runs the full registration flow for a client over the HTTP
// handlers and returns the client's export key.
func registerClient(t *testing.T, base string, conf *opaque.Configuration, username, password string) []byte {
	t.Helper()
	client, err := conf.Client()
	if err != nil {
		t.Fatalf("conf.Client: %v", err)
	}

	regReq, err := client.RegistrationInit([]byte(password))
	if err != nil {
		t.Fatalf("RegistrationInit: %v", err)
	}

	var startResp registerStartResp
	status := postJSON(t, base, "/register/start", registerStartReq{
		Username:            username,
		RegistrationRequest: b64(regReq.Serialize()),
	}, &startResp)
	if status != http.StatusOK {
		t.Fatalf("/register/start status=%d", status)
	}

	respBytes := mustB64(t, startResp.RegistrationResponse)
	if len(respBytes) != 64 {
		t.Fatalf("registration_response length=%d want 64", len(respBytes))
	}
	clientRegResp, err := client.Deserialize.RegistrationResponse(respBytes)
	if err != nil {
		t.Fatalf("client deserialize RegistrationResponse: %v", err)
	}

	// nil identities => default to public keys, per the contract.
	record, exportKey, err := client.RegistrationFinalize(clientRegResp, nil, nil)
	if err != nil {
		t.Fatalf("RegistrationFinalize: %v", err)
	}
	recBytes := record.Serialize()
	if len(recBytes) != 192 {
		t.Fatalf("registration_record length=%d want 192", len(recBytes))
	}

	var finResp registerFinishResp
	status = postJSON(t, base, "/register/finish", registerFinishReq{
		Username:           username,
		RegistrationRecord: b64(recBytes),
	}, &finResp)
	if status != http.StatusOK || !finResp.OK {
		t.Fatalf("/register/finish status=%d ok=%v", status, finResp.OK)
	}
	return exportKey
}

// loginClient runs the login flow over the HTTP handlers and returns the
// authenticated flag, the login_id, and the client-derived session key.
func loginClient(t *testing.T, base string, conf *opaque.Configuration, username, password string) (authenticated bool, loginID string, clientSessionKey []byte) {
	t.Helper()
	client, err := conf.Client()
	if err != nil {
		t.Fatalf("conf.Client: %v", err)
	}

	ke1, err := client.GenerateKE1([]byte(password))
	if err != nil {
		t.Fatalf("GenerateKE1: %v", err)
	}
	ke1Bytes := ke1.Serialize()
	if len(ke1Bytes) != 96 {
		t.Fatalf("ke1 length=%d want 96", len(ke1Bytes))
	}

	var startResp loginStartResp
	status := postJSON(t, base, "/login/start", loginStartReq{
		Username: username,
		KE1:      b64(ke1Bytes),
	}, &startResp)
	if status != http.StatusOK {
		t.Fatalf("/login/start status=%d", status)
	}
	if startResp.LoginID == "" {
		t.Fatalf("/login/start returned empty login_id")
	}
	ke2Bytes := mustB64(t, startResp.KE2)
	if len(ke2Bytes) != 320 {
		t.Fatalf("ke2 length=%d want 320", len(ke2Bytes))
	}

	clientKE2, err := client.Deserialize.KE2(ke2Bytes)
	if err != nil {
		t.Fatalf("client deserialize KE2: %v", err)
	}

	// GenerateKE2 may fail for a fake record on the client side (bad MAC). In
	// that case the login is simply not authenticated; we still want to drive
	// /login/finish to confirm the server rejects it.
	ke3, sessionKey, _, err := client.GenerateKE3(clientKE2, nil, nil)
	if err != nil {
		// Unknown user / wrong password: the client cannot finish. We send a
		// throwaway KE3-shaped message so the server consumes the login_id and
		// reports authenticated=false. Use the (failed) ke3 if present, else a
		// zero KE3.
		ke3Bytes := make([]byte, 64)
		if ke3 != nil {
			ke3Bytes = ke3.Serialize()
		}
		var finResp loginFinishResp
		status = postJSON(t, base, "/login/finish", loginFinishReq{
			LoginID: startResp.LoginID,
			KE3:     b64(ke3Bytes),
		}, &finResp)
		return finResp.Authenticated, startResp.LoginID, nil
	}

	ke3Bytes := ke3.Serialize()
	if len(ke3Bytes) != 64 {
		t.Fatalf("ke3 length=%d want 64", len(ke3Bytes))
	}

	var finResp loginFinishResp
	status = postJSON(t, base, "/login/finish", loginFinishReq{
		LoginID: startResp.LoginID,
		KE3:     b64(ke3Bytes),
	}, &finResp)
	if status != http.StatusOK && status != http.StatusUnauthorized {
		t.Fatalf("/login/finish unexpected status=%d", status)
	}
	return finResp.Authenticated, startResp.LoginID, sessionKey
}

// captureStderr redirects os.Stderr for the duration of fn and returns whatever
// was written. The server prints the SESSION_KEY proof line there.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	_ = w.Close()
	os.Stderr = old
	return <-done
}

// parseSessionKeyLine finds the `SESSION_KEY <username> <hex>` line for a given
// username in captured stderr and returns the hex string.
func parseSessionKeyLine(out, username string) (string, bool) {
	sc := bufio.NewScanner(strings.NewReader(out))
	prefix := fmt.Sprintf("SESSION_KEY %s ", username)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix), true
		}
	}
	return "", false
}

// TestFullRoundTrip exercises a complete register + login over the HTTP
// handlers and asserts the client session key equals the server's SessionSecret
// (captured from the SESSION_KEY proof line on stderr).
func TestFullRoundTrip(t *testing.T) {
	ts, _ := testServer(t)
	conf := newConfiguration()

	const username = "alice"
	const password = "correct horse battery staple"

	registerClient(t, ts.URL, conf, username, password)

	var (
		authenticated    bool
		clientSessionKey []byte
	)
	stderr := captureStderr(t, func() {
		authenticated, _, clientSessionKey = loginClient(t, ts.URL, conf, username, password)
	})

	if !authenticated {
		t.Fatalf("expected authenticated=true for valid login")
	}
	if len(clientSessionKey) != 64 {
		t.Fatalf("client session key length=%d want 64", len(clientSessionKey))
	}

	serverHex, ok := parseSessionKeyLine(stderr, username)
	if !ok {
		t.Fatalf("did not find SESSION_KEY line for %q in stderr:\n%s", username, stderr)
	}
	clientHex := fmt.Sprintf("%x", clientSessionKey)
	if serverHex != clientHex {
		t.Fatalf("session key mismatch:\n  client=%s\n  server=%s", clientHex, serverHex)
	}
	t.Logf("mutual auth confirmed: session key = %s", clientHex)
}

// TestWrongPassword confirms a registered user with the wrong password is
// rejected at /login/finish.
func TestWrongPassword(t *testing.T) {
	ts, _ := testServer(t)
	conf := newConfiguration()

	const username = "bob"
	registerClient(t, ts.URL, conf, username, "the right password")

	authenticated, loginID, _ := loginClient(t, ts.URL, conf, username, "the WRONG password")
	if authenticated {
		t.Fatalf("expected authenticated=false for wrong password")
	}
	if loginID == "" {
		t.Fatalf("expected a real login_id even on failed login")
	}
}

// TestUnknownUserAntiEnumeration confirms /login/start returns a well-formed
// KE2 (200, length 320, real login_id) for an unknown user, but /login/finish
// reports authenticated=false.
func TestUnknownUserAntiEnumeration(t *testing.T) {
	ts, s := testServer(t)
	conf := newConfiguration()

	const username = "ghost"
	client, err := conf.Client()
	if err != nil {
		t.Fatalf("conf.Client: %v", err)
	}
	ke1, err := client.GenerateKE1([]byte("whatever"))
	if err != nil {
		t.Fatalf("GenerateKE1: %v", err)
	}

	var startResp loginStartResp
	status := postJSON(t, ts.URL, "/login/start", loginStartReq{
		Username: username,
		KE1:      b64(ke1.Serialize()),
	}, &startResp)

	// Anti-enumeration: unknown user looks exactly like a known one here.
	if status != http.StatusOK {
		t.Fatalf("/login/start for unknown user status=%d want 200", status)
	}
	if startResp.LoginID == "" {
		t.Fatalf("/login/start for unknown user returned empty login_id")
	}
	ke2Bytes := mustB64(t, startResp.KE2)
	if len(ke2Bytes) != 320 {
		t.Fatalf("unknown-user ke2 length=%d want 320 (must be indistinguishable)", len(ke2Bytes))
	}

	// The server stashed a pending entry just like for a real user.
	s.mu.Lock()
	_, hasPending := s.pending[startResp.LoginID]
	s.mu.Unlock()
	if !hasPending {
		t.Fatalf("expected pending login entry for unknown user")
	}

	// Now finish: even a structurally valid KE3 must be rejected at the MAC.
	ke3Bytes := make([]byte, 64)
	var finResp loginFinishResp
	status = postJSON(t, ts.URL, "/login/finish", loginFinishReq{
		LoginID: startResp.LoginID,
		KE3:     b64(ke3Bytes),
	}, &finResp)
	if status != http.StatusUnauthorized {
		t.Fatalf("/login/finish for unknown user status=%d want 401", status)
	}
	if finResp.Authenticated {
		t.Fatalf("unknown user must not authenticate")
	}

	// The login_id must be consumed.
	s.mu.Lock()
	_, stillPending := s.pending[startResp.LoginID]
	s.mu.Unlock()
	if stillPending {
		t.Fatalf("login_id should be consumed after /login/finish")
	}
}

// TestMalformedInput confirms the handlers reject bad input with 4xx and never
// panic.
func TestMalformedInput(t *testing.T) {
	ts, _ := testServer(t)

	cases := []struct {
		name string
		path string
		body any
	}{
		{"register_start_bad_b64", "/register/start", registerStartReq{Username: "x", RegistrationRequest: "!!!not base64!!!"}},
		{"register_start_short", "/register/start", registerStartReq{Username: "x", RegistrationRequest: b64([]byte{1, 2, 3})}},
		{"register_start_no_user", "/register/start", registerStartReq{RegistrationRequest: b64(make([]byte, 32))}},
		{"register_finish_short", "/register/finish", registerFinishReq{Username: "x", RegistrationRecord: b64([]byte{1, 2, 3})}},
		{"login_start_short", "/login/start", loginStartReq{Username: "x", KE1: b64([]byte{1, 2, 3})}},
		{"login_finish_unknown_id", "/login/finish", loginFinishReq{LoginID: "nope", KE3: b64(make([]byte, 64))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status := postJSON(t, ts.URL, tc.path, tc.body, nil)
			if status < 400 || status >= 500 {
				t.Fatalf("%s: status=%d want 4xx", tc.name, status)
			}
		})
	}
}

// TestHealth checks the health endpoint contract.
func TestHealth(t *testing.T) {
	ts, _ := testServer(t)
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/health status=%d", resp.StatusCode)
	}
	var h healthResp
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatalf("decode /health: %v", err)
	}
	if !h.OK || h.Context != contextString || h.Suite != suiteString {
		t.Fatalf("/health body mismatch: %+v", h)
	}
}
