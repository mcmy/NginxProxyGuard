package service

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/bcrypt"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

const passkeyTimeout = 2 * time.Minute

var (
	ErrPasskeyOrigin       = errors.New("passkeys require a same-origin HTTPS request or localhost")
	ErrPasskeyVerification = errors.New("passkey verification failed")
	ErrPasskeyName         = errors.New("invalid passkey name")
)

type passkeyUser struct {
	*model.User
	credentials []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return []byte(u.ID) }
func (u passkeyUser) WebAuthnName() string                       { return u.Username }
func (u passkeyUser) WebAuthnDisplayName() string                { return u.Username }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

type passkeyFlow struct {
	Session            webauthn.SessionData
	Name               string
	PasswordHashDigest string
}

type PasskeyOptions struct {
	FlowID  string `json:"flow_id"`
	Options any    `json:"options"`
}

// PasskeyWebAuthn accepts the browser's Origin only at the HTTP request's
// authority. The UI proxy preserves Host, including any non-default port.
func PasskeyWebAuthn(origin, host string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" ||
		origin != u.Scheme+"://"+u.Host || !strings.EqualFold(u.Host, host) {
		return nil, ErrPasskeyOrigin
	}
	rpID := strings.ToLower(u.Hostname())
	if net.ParseIP(rpID) != nil || (u.Scheme != "https" && !(u.Scheme == "http" && rpID == "localhost")) {
		return nil, ErrPasskeyOrigin
	}
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyTimeout, TimeoutUVD: passkeyTimeout}
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Nginx Proxy Guard",
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
	})
}

func (s *AuthService) savePasskeyFlow(ctx context.Context, kind, origin, sessionHash string, flow passkeyFlow, options any) (*PasskeyOptions, error) {
	id, err := generateToken(tokenLength)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(flow)
	if err != nil {
		return nil, err
	}
	if err := s.repo.SavePasskeyFlow(ctx, hashToken(id), kind, origin, sessionHash, data, flow.Session.Expires); err != nil {
		return nil, err
	}
	return &PasskeyOptions{FlowID: id, Options: options}, nil
}

func (s *AuthService) consumePasskeyFlow(ctx context.Context, id, kind, origin, sessionHash string) (passkeyFlow, error) {
	var flow passkeyFlow
	data, err := s.repo.ConsumePasskeyFlow(ctx, hashToken(id), kind, origin, sessionHash)
	if errors.Is(err, sql.ErrNoRows) {
		return flow, ErrPasskeyVerification
	}
	if err != nil {
		return flow, err
	}
	err = json.Unmarshal(data, &flow)
	return flow, err
}

func (s *AuthService) BeginPasskeyLogin(ctx context.Context, wa *webauthn.WebAuthn) (*PasskeyOptions, error) {
	options, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, err
	}
	return s.savePasskeyFlow(ctx, "login", wa.Config.RPOrigins[0], "", passkeyFlow{Session: *session}, options)
}

func (s *AuthService) FinishPasskeyLogin(ctx context.Context, wa *webauthn.WebAuthn, flowID string, response []byte, ip, userAgent string) (*model.LoginResponse, error) {
	flow, err := s.consumePasskeyFlow(ctx, flowID, "login", wa.Config.RPOrigins[0], "")
	if err != nil {
		return nil, err
	}
	assertion, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, ErrPasskeyVerification
	}
	var revision int64
	var account *model.User
	var lookupErr error
	resolve := func(id, handle []byte) (webauthn.User, error) {
		userID, credential, version, err := s.repo.FindPasskey(ctx, id, wa.Config.RPID)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				lookupErr = err
			}
			return nil, ErrPasskeyVerification
		}
		if !bytes.Equal(handle, []byte(userID)) {
			return nil, ErrPasskeyVerification
		}
		account, lookupErr = s.repo.GetUserByID(ctx, userID)
		if lookupErr != nil || account == nil || account.IsInitialSetup || account.MustChangePassword {
			return nil, ErrPasskeyVerification
		}
		revision = version
		return passkeyUser{account, []webauthn.Credential{credential}}, nil
	}
	_, credential, err := wa.ValidatePasskeyLogin(resolve, flow.Session, assertion)
	if lookupErr != nil {
		return nil, lookupErr
	}
	if err != nil || credential.Authenticator.CloneWarning {
		return nil, ErrPasskeyVerification
	}
	login, err := s.createSessionWith(ctx, account, ip, userAgent, func(ctx context.Context, session *model.AuthSession) error {
		return s.repo.CreatePasskeySession(ctx, session, credential, revision)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPasskeyVerification
	}
	return login, err
}

func (s *AuthService) ListPasskeys(ctx context.Context, userID string) ([]repository.Passkey, error) {
	return s.repo.ListPasskeys(ctx, userID)
}

func (s *AuthService) reauthenticatePasskeyManagement(ctx context.Context, user *model.User, password, code, ip string) error {
	if user.IsInitialSetup || user.MustChangePassword {
		return ErrUnauthorized
	}
	failed, err := s.repo.CountRecentFailedAttempts(ctx, ip, user.Username, time.Now().Add(-lockoutWindow))
	if err != nil {
		return err
	}
	if failed >= maxFailedAttempts {
		return ErrTooManyAttempts
	}
	if password == "" || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil ||
		(user.TOTPEnabled && !ValidateTOTPCode(user.TOTPSecret, code)) {
		if err := s.repo.RecordLoginAttempt(ctx, ip, user.Username, false); err != nil {
			return err
		}
		return ErrInvalidCredentials
	}
	return nil
}

func (s *AuthService) BeginPasskeyRegistration(ctx context.Context, wa *webauthn.WebAuthn, user *model.User, token, name, password, code, ip string) (*PasskeyOptions, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 80 || strings.ContainsFunc(name, unicode.IsControl) {
		return nil, ErrPasskeyName
	}
	if err := s.reauthenticatePasskeyManagement(ctx, user, password, code, ip); err != nil {
		return nil, err
	}
	keys, err := s.repo.ListPasskeys(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	var excluded []protocol.CredentialDescriptor
	for _, key := range keys {
		if key.RPID == wa.Config.RPID {
			excluded = append(excluded, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: key.ID})
		}
	}
	options, session, err := wa.BeginRegistration(passkeyUser{User: user}, webauthn.WithExclusions(excluded))
	if err != nil {
		return nil, err
	}
	return s.savePasskeyFlow(ctx, "register", wa.Config.RPOrigins[0], hashToken(token), passkeyFlow{
		Session: *session, Name: name, PasswordHashDigest: hashToken(user.PasswordHash),
	}, options)
}

func (s *AuthService) FinishPasskeyRegistration(ctx context.Context, wa *webauthn.WebAuthn, user *model.User, token, flowID string, response []byte) error {
	sessionHash := hashToken(token)
	flow, err := s.consumePasskeyFlow(ctx, flowID, "register", wa.Config.RPOrigins[0], sessionHash)
	if err != nil {
		return err
	}
	if flow.PasswordHashDigest != hashToken(user.PasswordHash) {
		return ErrPasskeyVerification
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return ErrPasskeyVerification
	}
	credential, err := wa.CreateCredential(passkeyUser{User: user}, flow.Session, parsed)
	if err != nil {
		return ErrPasskeyVerification
	}
	err = s.repo.CreatePasskey(ctx, user, sessionHash, wa.Config.RPID, flow.Name, credential)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrPasskeyVerification
	}
	return err
}

func (s *AuthService) DeletePasskey(ctx context.Context, user *model.User, id []byte, password, code, ip string) error {
	if err := s.reauthenticatePasskeyManagement(ctx, user, password, code, ip); err != nil {
		return err
	}
	return s.repo.DeletePasskey(ctx, user.ID, id)
}
