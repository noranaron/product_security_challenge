package app

import (
	"errors"
	"net/http"
)

var ErrCookieEmpty = errors.New("cookie value empty")

func GetCookie(r *http.Request, name string) (*http.Cookie, error) {
	cookie, err := r.Cookie(getCookieName(name))
	if err != nil {
		return nil, err
	}
	if cookie.Value == "" {
		return nil, ErrCookieEmpty
	}
	return cookie, nil
}

func SetCookie(w http.ResponseWriter, name string, value string, maxAge int) *http.Cookie {
	cookie := &http.Cookie{
		Name:   getCookieName(name),
		Value:  value,
		Path:   "/",
		Secure: Options.USE_SECURE_COOKIE,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		MaxAge: maxAge,
	}
	http.SetCookie(w, cookie)
	return cookie
}

func GetOrSetCookie(r *http.Request, w http.ResponseWriter, name string, valueFunc func() (value string, maxAge int, err error)) (*http.Cookie, error) {
	cookie, err := GetCookie(r, name)
	if err == http.ErrNoCookie || err == ErrCookieEmpty {
		value, maxAge, err := valueFunc()
		if err != nil {
			return nil, err
		}
		cookie = SetCookie(w, name, value, maxAge)
	} else if err != nil {
		return nil, err
	}
	return cookie, nil
}

func GetOrSetSessionCookie(r *http.Request, w http.ResponseWriter) (*http.Cookie, error) {
	ipaddr := GetIPAddressFromRequest(r)
	userAgent := GetUserAgentFromRequest(r)
	sessionCookie, err := GetOrSetCookie(r, w, Options.COOKIE_KEY_SESSION, func() (value string, maxAge int, err error) {
		session, err := NewSession(SessionData{ UserID: -1 }, userAgent, ipaddr)
		if err != nil {
			return "", 0, err
		}
		return session.SessionKey, 0, nil
	})
	if err != nil {
		return nil, err
	}
	_, err = GetSession(sessionCookie.Value)
	if err == ErrSessionKeyNotFound {
		logEvent := EventSessionKeyNotFound
		logEvent.Values["attempted_session"] = sessionCookie.Value
		logEvent.Values["ipaddress"] = ipaddr
		LogWarn(logEvent)
	}
	if err != nil {
		session, err := NewSession(SessionData{ UserID: -1 }, userAgent, ipaddr)
		if err != nil {
			return nil, err
		}
		sessionCookie = SetCookie(w, Options.COOKIE_KEY_SESSION, session.SessionKey, 0)
	}
	return sessionCookie, nil
}

func GetOrSetCsrfCookie(r *http.Request, w http.ResponseWriter) (*http.Cookie, error) {
	return GetOrSetCookie(r, w, Options.COOKIE_KEY_CSRF_TOKEN, func() (value string, maxAge int, err error) {
		csrfToken, err := NewCsrfToken(Options.CSRF_TOKEN_LENGTH)
		if err != nil {
			return "", 0, err
		}
		return csrfToken, 0, nil
	})
}

func getCookieName(name string) string {
	cookieName := name
	if !Options.USE_SECURE_COOKIE {
		cookieName += "_unsecure"
	}
	return cookieName
}
