package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	apiBase       = "https://api.steampowered.com"
	communityBase = "https://steamcommunity.com"
	userAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

// Session holds an authenticated steamcommunity.com web session.
type Session struct {
	client      *http.Client
	SteamID     string
	SessionID   string
	AccessToken string
	ExpiresAt   time.Time
}

// apiCall calls a Steam WebAPI service method and decodes the "response" object into out.
// Failures are reported by Steam through the X-eresult header (1 = OK).
func apiCall(ctx context.Context, c *http.Client, method, iface, fn string, params url.Values, out any) error {
	u := fmt.Sprintf("%s/%s/%s/v1/", apiBase, iface, fn)
	var body io.Reader
	if method == http.MethodGet {
		u += "?" + params.Encode()
	} else {
		body = strings.NewReader(params.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Origin", communityBase)
	req.Header.Set("Referer", communityBase+"/")

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return &httpError{Status: resp.StatusCode, Body: truncate(string(data), 200)}
	}
	if er := resp.Header.Get("X-eresult"); er != "" && er != "1" {
		return fmt.Errorf("%s/%s: eresult %s %s", iface, fn, er, resp.Header.Get("X-error_message"))
	}
	if out == nil {
		return nil
	}
	wrapper := struct {
		Response json.RawMessage `json:"response"`
	}{}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return fmt.Errorf("%s/%s: decode: %w", iface, fn, err)
	}
	return json.Unmarshal(wrapper.Response, out)
}

type httpError struct {
	Status int
	Body   string
}

func (e *httpError) Error() string { return fmt.Sprintf("http %d: %s", e.Status, e.Body) }

func isAuthError(err error) bool {
	var he *httpError
	return errors.As(err, &he) && (he.Status == http.StatusUnauthorized || he.Status == http.StatusForbidden)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func steamTimeOffset(ctx context.Context, c *http.Client) time.Duration {
	var r struct {
		ServerTime string `json:"server_time"`
	}
	if err := apiCall(ctx, c, http.MethodPost, "ITwoFactorService", "QueryTime", url.Values{"steamid": {"0"}}, &r); err != nil {
		return 0
	}
	st, err := strconv.ParseInt(r.ServerTime, 10, 64)
	if err != nil {
		return 0
	}
	return time.Unix(st, 0).Sub(time.Now())
}

func Login(ctx context.Context, mf *MaFile, password string) (*Session, error) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	var key struct {
		Mod       string `json:"publickey_mod"`
		Exp       string `json:"publickey_exp"`
		Timestamp string `json:"timestamp"`
	}
	if err := apiCall(ctx, c, http.MethodGet, "IAuthenticationService", "GetPasswordRSAPublicKey",
		url.Values{"account_name": {mf.AccountName}}, &key); err != nil {
		return nil, fmt.Errorf("get rsa key: %w", err)
	}
	encPassword, err := encryptPassword(password, key.Mod, key.Exp)
	if err != nil {
		return nil, err
	}

	var begin struct {
		ClientID  string  `json:"client_id"`
		RequestID string  `json:"request_id"`
		SteamID   string  `json:"steamid"`
		Interval  float64 `json:"interval"`
		Confirms  []struct {
			Type int `json:"confirmation_type"`
		} `json:"allowed_confirmations"`
	}
	if err := apiCall(ctx, c, http.MethodPost, "IAuthenticationService", "BeginAuthSessionViaCredentials", url.Values{
		"account_name":         {mf.AccountName},
		"encrypted_password":   {encPassword},
		"encryption_timestamp": {key.Timestamp},
		"remember_login":       {"true"},
		"persistence":          {"1"},
		"website_id":           {"Community"},
	}, &begin); err != nil {
		return nil, fmt.Errorf("begin auth session (wrong password?): %w", err)
	}

	needsCode := false
	for _, cf := range begin.Confirms {
		if cf.Type == 3 {
			needsCode = true
		}
	}
	if needsCode {
		now := time.Now().Add(steamTimeOffset(ctx, c)).Unix()
		code, err := generateAuthCode(mf.SharedSecret, now)
		if err != nil {
			return nil, err
		}
		if err := apiCall(ctx, c, http.MethodPost, "IAuthenticationService", "UpdateAuthSessionWithSteamGuardCode", url.Values{
			"client_id": {begin.ClientID},
			"steamid":   {begin.SteamID},
			"code":      {code},
			"code_type": {"3"},
		}, nil); err != nil {
			return nil, fmt.Errorf("submit steam guard code: %w", err)
		}
	}

	var poll struct {
		RefreshToken string `json:"refresh_token"`
		AccessToken  string `json:"access_token"`
	}
	for i := 0; i < 10 && poll.RefreshToken == ""; i++ {
		if err := apiCall(ctx, c, http.MethodPost, "IAuthenticationService", "PollAuthSessionStatus", url.Values{
			"client_id":  {begin.ClientID},
			"request_id": {begin.RequestID},
		}, &poll); err != nil {
			return nil, fmt.Errorf("poll auth session: %w", err)
		}
		if poll.RefreshToken == "" {
			time.Sleep(time.Second)
		}
	}
	if poll.RefreshToken == "" {
		return nil, errors.New("login did not complete: no refresh token received")
	}

	s := &Session{client: c, SteamID: begin.SteamID, SessionID: randomHex(12), AccessToken: poll.AccessToken}
	if err := s.finalizeLogin(ctx, poll.RefreshToken); err != nil {
		return nil, err
	}
	if tok := s.cookieAccessToken(); tok != "" {
		s.AccessToken = tok
	}
	s.ExpiresAt = jwtExpiry(s.AccessToken)
	return s, nil
}

func encryptPassword(password, modHex, expHex string) (string, error) {
	n, ok := new(big.Int).SetString(modHex, 16)
	if !ok {
		return "", errors.New("bad rsa modulus")
	}
	e, err := strconv.ParseInt(expHex, 16, 64)
	if err != nil {
		return "", fmt.Errorf("bad rsa exponent: %w", err)
	}
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, &rsa.PublicKey{N: n, E: int(e)}, []byte(password))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

func (s *Session) finalizeLogin(ctx context.Context, refreshToken string) error {
	community, _ := url.Parse(communityBase)
	s.client.Jar.SetCookies(community, []*http.Cookie{{Name: "sessionid", Value: s.SessionID, Path: "/"}})

	var fin struct {
		SteamID      string `json:"steamID"`
		Error        int    `json:"error"`
		TransferInfo []struct {
			URL    string            `json:"url"`
			Params map[string]string `json:"params"`
		} `json:"transfer_info"`
	}
	if err := s.postMultipart(ctx, "https://login.steampowered.com/jwt/finalizelogin", map[string]string{
		"nonce":     refreshToken,
		"sessionid": s.SessionID,
		"redir":     communityBase + "/login/home/?goto=",
	}, &fin); err != nil {
		return fmt.Errorf("finalize login: %w", err)
	}
	if len(fin.TransferInfo) == 0 {
		return fmt.Errorf("finalize login: no transfer info (error %d)", fin.Error)
	}

	for _, ti := range fin.TransferInfo {
		fields := map[string]string{"steamID": fin.SteamID}
		for k, v := range ti.Params {
			fields[k] = v
		}
		err := s.postMultipart(ctx, ti.URL, fields, nil)
		if err != nil && strings.Contains(ti.URL, "steamcommunity.com") {
			return fmt.Errorf("set community cookies: %w", err)
		}
	}
	if s.cookieAccessToken() == "" {
		return errors.New("login finished but steamLoginSecure cookie was not set")
	}
	return nil
}

func (s *Session) postMultipart(ctx context.Context, u string, fields map[string]string, out any) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	w.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Origin", communityBase)
	req.Header.Set("Referer", communityBase+"/")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return &httpError{Status: resp.StatusCode, Body: truncate(string(data), 200)}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (s *Session) cookieAccessToken() string {
	community, _ := url.Parse(communityBase)
	for _, ck := range s.client.Jar.Cookies(community) {
		if ck.Name != "steamLoginSecure" {
			continue
		}
		v, err := url.QueryUnescape(ck.Value)
		if err != nil {
			v = ck.Value
		}
		if _, tok, ok := strings.Cut(v, "||"); ok {
			return tok
		}
	}
	return ""
}

func jwtExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
