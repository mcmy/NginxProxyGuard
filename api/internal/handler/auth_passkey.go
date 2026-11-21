package handler

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/service"
)

type passkeyProof struct {
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

type passkeyFinish struct {
	FlowID     string          `json:"flow_id"`
	Credential json.RawMessage `json:"credential"`
}

func (r passkeyFinish) valid() bool {
	return len(r.FlowID) > 0 && len(r.FlowID) <= 128 && len(r.Credential) > 0
}

func bindPasskeyRequest(c echo.Context, out any) error {
	r := c.Request()
	contentType, _, err := mime.ParseMediaType(r.Header.Get(echo.HeaderContentType))
	if err != nil || contentType != echo.MIMEApplicationJSON {
		return echo.NewHTTPError(http.StatusUnsupportedMediaType, "Expected application/json")
	}
	r.Body = http.MaxBytesReader(c.Response(), r.Body, 128<<10)
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}
	return nil
}

func passkeyError(c echo.Context, err error) error {
	status, code := http.StatusInternalServerError, "failed"
	switch {
	case errors.Is(err, service.ErrPasskeyOrigin):
		status, code = http.StatusBadRequest, "origin"
	case errors.Is(err, service.ErrPasskeyName):
		status, code = http.StatusBadRequest, "invalid_name"
	case errors.Is(err, service.ErrPasskeyVerification):
		status, code = http.StatusUnauthorized, "verification_failed"
	case errors.Is(err, service.ErrInvalidCredentials):
		status, code = http.StatusForbidden, "credentials_invalid"
	case errors.Is(err, service.ErrUnauthorized):
		status, code = http.StatusForbidden, "account_unavailable"
	case errors.Is(err, service.ErrTooManyAttempts):
		status, code = http.StatusTooManyRequests, "rate_limited"
	case errors.Is(err, sql.ErrNoRows):
		status, code = http.StatusNotFound, "not_found"
	default:
		c.Logger().Errorf("Passkey operation failed: %v", err)
	}
	return c.JSON(status, map[string]string{"error": "Passkey operation failed", "code": code})
}

func (h *AuthHandler) BeginPasskeyLogin(c echo.Context) error {
	c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	r := c.Request()
	wa, err := service.PasskeyWebAuthn(r.Header.Get("Origin"), r.Host)
	if err != nil {
		return passkeyError(c, err)
	}
	options, err := h.authService.BeginPasskeyLogin(r.Context(), wa)
	if err != nil {
		return passkeyError(c, err)
	}
	return c.JSON(http.StatusOK, options)
}

func (h *AuthHandler) FinishPasskeyLogin(c echo.Context) error {
	c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	r := c.Request()
	wa, err := service.PasskeyWebAuthn(r.Header.Get("Origin"), r.Host)
	if err != nil {
		return passkeyError(c, err)
	}
	var req passkeyFinish
	if err := bindPasskeyRequest(c, &req); err != nil {
		return err
	}
	if !req.valid() {
		return passkeyError(c, service.ErrPasskeyVerification)
	}
	ip, agent := c.RealIP(), r.UserAgent()
	login, err := h.authService.FinishPasskeyLogin(r.Context(), wa, req.FlowID, req.Credential, ip, agent)
	if err != nil {
		if errors.Is(err, service.ErrPasskeyVerification) {
			_ = h.auditService.LogUserLoginFailed(r.Context(), "passkey", ip, agent, "passkey_verification_failed")
		}
		return passkeyError(c, err)
	}
	c.Set("user_id", login.User.ID)
	c.Set("username", login.User.Username)
	_ = h.auditService.LogUserLogin(service.ContextWithAudit(r.Context(), c), login.User.Username, ip, agent)
	return c.JSON(http.StatusOK, login)
}

func (h *AuthHandler) ListPasskeys(c echo.Context) error {
	c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	user, ok := getUserFromContext(c)
	if !ok || user.IsInitialSetup || user.MustChangePassword {
		return passkeyError(c, service.ErrUnauthorized)
	}
	keys, err := h.authService.ListPasskeys(c.Request().Context(), user.ID)
	if err != nil {
		return passkeyError(c, err)
	}
	return c.JSON(http.StatusOK, keys)
}

func (h *AuthHandler) BeginPasskeyRegistration(c echo.Context) error {
	c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	user, ok := getUserFromContext(c)
	if !ok {
		return passkeyError(c, service.ErrUnauthorized)
	}
	r := c.Request()
	wa, err := service.PasskeyWebAuthn(r.Header.Get("Origin"), r.Host)
	if err != nil {
		return passkeyError(c, err)
	}
	var req struct {
		passkeyProof
		Name string `json:"name"`
	}
	if err := bindPasskeyRequest(c, &req); err != nil {
		return err
	}
	options, err := h.authService.BeginPasskeyRegistration(r.Context(), wa, user, extractToken(c), req.Name, req.Password, req.TOTPCode, c.RealIP())
	if err != nil {
		return passkeyError(c, err)
	}
	return c.JSON(http.StatusOK, options)
}

func (h *AuthHandler) FinishPasskeyRegistration(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok || user.IsInitialSetup || user.MustChangePassword {
		return passkeyError(c, service.ErrUnauthorized)
	}
	r := c.Request()
	wa, err := service.PasskeyWebAuthn(r.Header.Get("Origin"), r.Host)
	if err != nil {
		return passkeyError(c, err)
	}
	var req passkeyFinish
	if err := bindPasskeyRequest(c, &req); err != nil {
		return err
	}
	if !req.valid() {
		return passkeyError(c, service.ErrPasskeyVerification)
	}
	if err := h.authService.FinishPasskeyRegistration(r.Context(), wa, user, extractToken(c), req.FlowID, req.Credential); err != nil {
		return passkeyError(c, err)
	}
	_ = h.auditService.LogPasskeyChange(service.ContextWithAudit(r.Context(), c), user.Username, true)
	return c.NoContent(http.StatusCreated)
}

func (h *AuthHandler) DeletePasskey(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return passkeyError(c, service.ErrUnauthorized)
	}
	r := c.Request()
	if _, err := service.PasskeyWebAuthn(r.Header.Get("Origin"), r.Host); err != nil {
		return passkeyError(c, err)
	}
	id, err := base64.RawURLEncoding.DecodeString(c.Param("id"))
	if err != nil || len(id) == 0 || len(id) > 1023 {
		return passkeyError(c, sql.ErrNoRows)
	}
	var req passkeyProof
	if err := bindPasskeyRequest(c, &req); err != nil {
		return err
	}
	if err := h.authService.DeletePasskey(r.Context(), user, id, req.Password, req.TOTPCode, c.RealIP()); err != nil {
		return passkeyError(c, err)
	}
	_ = h.auditService.LogPasskeyChange(service.ContextWithAudit(r.Context(), c), user.Username, false)
	return c.NoContent(http.StatusNoContent)
}
