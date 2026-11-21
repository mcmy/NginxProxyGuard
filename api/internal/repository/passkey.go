package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"nginx-proxy-guard/internal/model"
)

type Passkey struct {
	ID         protocol.URLEncodedBase64 `json:"id"`
	Name       string                    `json:"name"`
	RPID       string                    `json:"rp_id"`
	CreatedAt  time.Time                 `json:"created_at"`
	LastUsedAt *time.Time                `json:"last_used_at,omitempty"`
}

func (r *AuthRepository) ListPasskeys(ctx context.Context, userID string) ([]Passkey, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, rp_id, created_at, last_used_at
		FROM user_passkeys WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []Passkey{}
	for rows.Next() {
		var key Passkey
		if err := rows.Scan(&key.ID, &key.Name, &key.RPID, &key.CreatedAt, &key.LastUsedAt); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (r *AuthRepository) CreatePasskey(ctx context.Context, user *model.User, sessionHash, rpID, name string, credential *webauthn.Credential) error {
	data, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	var id []byte
	return r.db.QueryRowContext(ctx, `
		WITH owner AS (
			SELECT id FROM users
			WHERE id = $1 AND password_hash = $2 AND NOT is_initial_setup AND NOT must_change_password
			  AND EXISTS (SELECT 1 FROM auth_sessions WHERE user_id = $1 AND token_hash = $3 AND expires_at > now())
			FOR UPDATE
		)
		INSERT INTO user_passkeys (user_id, rp_id, name, id, credential)
		SELECT id, $4, $5, $6, $7 FROM owner
		ON CONFLICT (id) DO NOTHING
		RETURNING id`, user.ID, user.PasswordHash, sessionHash, rpID, name, credential.ID, string(data)).Scan(&id)
}

func (r *AuthRepository) DeletePasskey(ctx context.Context, userID string, id []byte) error {
	var removed []byte
	return r.db.QueryRowContext(ctx, `
		DELETE FROM user_passkeys WHERE id = $1 AND user_id = $2 RETURNING id`, id, userID).Scan(&removed)
}

func (r *AuthRepository) FindPasskey(ctx context.Context, id []byte, rpID string) (string, webauthn.Credential, int64, error) {
	var userID string
	var raw []byte
	var revision int64
	var credential webauthn.Credential
	err := r.db.QueryRowContext(ctx, `
		SELECT user_id, credential, revision FROM user_passkeys WHERE id = $1 AND rp_id = $2`, id, rpID).
		Scan(&userID, &raw, &revision)
	if err == nil {
		err = json.Unmarshal(raw, &credential)
	}
	return userID, credential, revision, err
}

// A login and its counter update commit together. Locking the owner first
// serializes with password recovery, which revokes this user's passkeys.
func (r *AuthRepository) CreatePasskeySession(ctx context.Context, session *model.AuthSession, credential *webauthn.Credential, revision int64) error {
	data, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	return r.db.QueryRowContext(ctx, `
		WITH owner AS (
			SELECT id FROM users WHERE id = $1 AND NOT is_initial_setup AND NOT must_change_password FOR UPDATE
		), used AS (
			UPDATE user_passkeys p SET credential = $7, revision = p.revision + 1, last_used_at = now()
			FROM owner WHERE p.user_id = owner.id AND p.id = $6 AND p.revision = $8
			RETURNING p.user_id
		)
		INSERT INTO auth_sessions (user_id, token_hash, ip_address, user_agent, expires_at)
		SELECT user_id, $2, $3, $4, $5 FROM used
		RETURNING id, created_at`, session.UserID, session.TokenHash, session.IPAddress, session.UserAgent,
		session.ExpiresAt, credential.ID, string(data), revision).Scan(&session.ID, &session.CreatedAt)
}

func (r *AuthRepository) SavePasskeyFlow(ctx context.Context, tokenHash, kind, origin, sessionHash string, data []byte, expires time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO passkey_flows (token_hash, kind, origin, session_hash, data, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, tokenHash, kind, origin, sessionHash, string(data), expires)
	return err
}

func (r *AuthRepository) ConsumePasskeyFlow(ctx context.Context, tokenHash, kind, origin, sessionHash string) ([]byte, error) {
	var data []byte
	err := r.db.QueryRowContext(ctx, `
		DELETE FROM passkey_flows
		WHERE token_hash = $1 AND kind = $2 AND origin = $3 AND session_hash = $4 AND expires_at > now()
		RETURNING data`, tokenHash, kind, origin, sessionHash).Scan(&data)
	return data, err
}

func (r *AuthRepository) CleanExpiredPasskeyFlows(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM passkey_flows WHERE expires_at <= now()")
	return err
}
