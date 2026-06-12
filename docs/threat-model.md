# Threat model

This document describes the threat model for `opaque-zig`, a Zig implementation
of the OPAQUE asymmetric password-authenticated key exchange (aPAKE) protocol
specified in [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html). It is
scoped to the guarantees this library can and cannot provide. It is grounded in
RFC 9807, especially the security considerations in §10, and does not claim
properties beyond what the protocol provides.

This is pre-1.0, unaudited software. Read this document alongside `SECURITY.md`.

## What OPAQUE provides

OPAQUE lets a client authenticate to a server using a password without ever
revealing that password (or a password-equivalent value) to the server, and
establishes a shared session key on success. Its central design goal is that the
server never sees the plaintext password and never stores a value that can be
used directly to impersonate the user or to mount an *online-free* (offline)
guessing attack cheaply.

## Actors and trust boundaries

- **Client.** Runs on the user's device, takes the user's password as input,
  and supplies the protocol randomness (see below). The client is trusted to
  handle the password in memory and to use a secure randomness source.
- **Server.** Stores per-user registration records (the "credential file" /
  envelope plus the server-side key material and OPRF seed). The server is
  *not* trusted with the password and learns nothing about it during
  registration or login beyond what is noted under "compromised server."
- **Network / active attacker.** May observe, modify, drop, inject, or replay
  messages. OPAQUE is designed to resist active man-in-the-middle attackers:
  an attacker who does not know the password cannot complete login or derive
  the session key, and the authenticated key exchange binds the transcript.

The trust boundary that matters most is between the client (which holds the
password) and the server (which must function without it). OPAQUE's value is in
keeping the password on the client side of that boundary even across a full
server compromise.

## What a compromised server learns

If an attacker compromises the server and steals the stored registration
records, OPAQUE does **not** hand them the passwords. Instead, per RFC 9807
§10.8, the attacker is forced into an **offline dictionary attack**: for each
stolen record they must guess a candidate password and run the password through
the same key-derivation steps to test it against the stored envelope.

The **key stretching function (KSF)** is the primary defense here. OPAQUE feeds
the password (after the OPRF step) through a configurable KSF — a memory-hard /
computationally expensive password hash such as Argon2 — before the envelope key
is derived. The KSF does not prevent an offline attack; it makes each guess
expensive, so the practical cost of brute-forcing weak passwords scales with the
KSF cost parameters. Consequences that follow:

- The strength of protection for stolen records is bounded by **password
  entropy** and **KSF cost**. Weak or low-entropy passwords remain vulnerable
  to offline guessing no matter what the protocol does.
- Choosing weak KSF parameters (or an identity KSF) materially weakens the
  post-compromise guarantee. Callers should select KSF parameters appropriate
  to their threat model.
- A compromised server also learns the registration records' associated
  metadata it already stores (e.g., which user identifiers are registered) and
  can attempt to impersonate the server to clients going forward; it cannot
  retroactively recover session keys from past sessions it did not actively
  participate in, consistent with the protocol's forward-secrecy properties.

A server that is compromised *before* or *during* a live exchange (an active
attacker in control of the server) is a stronger position than offline theft of
records; OPAQUE protects the password even then, but anything the server is
legitimately entrusted to do after authentication is outside the protocol's
control.

## Caller-supplied randomness

This library requires the **caller to supply all protocol randomness** — OPRF
blinds, nonces, envelope nonces, key-share seeds, server keys, and OPRF seed
material are passed in as explicit byte arrays (see the README "Randomness"
section and `docs/wasm.md`). This is a deliberate design choice that moves a
critical security obligation onto the caller. The consequences of getting it
wrong are severe:

- **Reused randomness.** Reusing a value that must be fresh (an OPRF blind, a
  nonce, an envelope nonce, or a key-share seed) can break the security
  properties the protocol depends on — for example, undermining the blinding
  that hides the password input to the OPRF, or the freshness that prevents
  replay and key reuse. Nonce/seed reuse in key-exchange constructions can leak
  key material or enable transcript/session correlation.
- **Predictable or low-entropy randomness.** If the randomness source is
  predictable, an attacker who can reproduce it can attack the affected values
  directly. Callers must use a cryptographically secure RNG
  (e.g., `crypto.getRandomValues()` in browser/Deno contexts).
- **Swapped or attacker-influenced randomness.** If an attacker can substitute
  the randomness a caller feeds in, they can influence values that are assumed
  to be honestly generated. The library cannot detect that its inputs were
  chosen adversarially; it trusts the caller to generate them securely and to
  never reuse them.

In short: the library is only as safe as the randomness the caller provides.
Treat the randomness inputs as security-critical and never reuse them.

## User enumeration

OPAQUE is designed so that login responses do not trivially reveal whether a
username is registered: the protocol supports responding to a login attempt for
an unknown user in a way that is structurally indistinguishable from a real one
(using a consistent, deterministically derived "fake" record / OPRF response),
so an attacker cannot easily distinguish registered from unregistered accounts
purely from protocol messages. Realizing this property in practice depends on
the *application* around the library:

- The server must respond uniformly for existing and non-existing users —
  including consistent timing and identical error/abort behavior — and avoid
  side channels (distinct error codes, response sizes, latency) that re-expose
  enumeration.
- Registration flows, rate limiting, and account-existence hints elsewhere in
  the application can independently leak whether an account exists; those are
  outside the protocol and must be handled by the caller.

This library provides the cryptographic building blocks; it cannot guarantee
enumeration resistance for an application that leaks existence through its own
behavior.

## Non-goals and explicit limitations

- **Not audited.** This code has not undergone an independent security audit or
  formal verification. Do not use it to protect real secrets yet.
- **No protection against a malicious client beyond the protocol.** A client is
  the party that holds the password by design. OPAQUE does not, and this library
  does not, defend the server against a client who knows the correct password,
  nor against client-side compromise (malware, a keylogger, a hostile device)
  that captures the password directly. Guarantees are limited to those OPAQUE
  itself provides.
- **No defense against weak passwords.** The KSF raises the cost of offline
  guessing but cannot make a weak password safe.
- **Side channels.** Constant-time behavior and resistance to timing or other
  side-channel analysis are not claimed for this implementation at this stage.
- **Application-layer concerns.** Transport security, replay/rate limiting at
  the application layer, secure storage of registration records at rest, secure
  deletion of password material from memory, account lifecycle, and uniform
  server behavior for enumeration resistance are the caller's responsibility.
- **Randomness generation.** As above, the library does not generate randomness;
  it relies entirely on the caller to supply secure, unique values.

## References

- RFC 9807 — The OPAQUE Augmented PAKE Protocol, especially §10 (Security
  Considerations) and §10.8 (offline dictionary attacks against a compromised
  server and the role of the KSF).
