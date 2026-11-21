package service

import (
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestPasskeyWebAuthnOriginAndDiscoverableOptions(t *testing.T) {
	wa, err := PasskeyWebAuthn("https://panel.example.com:8443", "panel.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	options, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Response.AllowedCredentials) != 0 || len(session.UserID) != 0 ||
		session.RelyingPartyID != "panel.example.com" || session.UserVerification != protocol.VerificationRequired ||
		session.Expires.IsZero() {
		t.Fatalf("unexpected discoverable login options: %+v", options.Response)
	}
	if _, err := PasskeyWebAuthn("http://localhost:5173", "localhost:5173"); err != nil {
		t.Fatalf("localhost is a WebAuthn secure context: %v", err)
	}

	for _, input := range [][2]string{
		{"https://panel.example.com:8443", "panel.example.com"},
		{"https://other.example.com", "panel.example.com"},
		{"https://panel.example.com/path", "panel.example.com"},
		{"http://panel.example.com", "panel.example.com"},
		{"https://192.0.2.42", "192.0.2.42"},
		{"", "panel.example.com"},
	} {
		if _, err := PasskeyWebAuthn(input[0], input[1]); !errors.Is(err, ErrPasskeyOrigin) {
			t.Errorf("origin %q for host %q: expected origin rejection, got %v", input[0], input[1], err)
		}
	}
}
