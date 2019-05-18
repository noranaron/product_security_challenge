package app

import (
	"context"
	"fmt"
	"net/http"
)

type Middleware func(http.HandlerFunc) http.HandlerFunc

func chainMiddlewares(handler http.HandlerFunc, middlewares []Middleware) http.HandlerFunc {
	wrappedHandler := handler
	for i := len(middlewares) - 1; i >= 0; i-- {
		wrappedHandler = middlewares[i](wrappedHandler)
	}
	return wrappedHandler
}

func sessionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csrfCookie, err := GetOrSetCsrfCookie(r, w)
		if err != nil {
			LogError(EventErrorHttpMiddleware, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		csrfToken := csrfCookie.Value

		sessionCookie, err := GetOrSetSessionCookie(r, w)
		if err != nil {
			LogError(EventErrorHttpMiddleware, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sessionKey := sessionCookie.Value

		session, err := GetSession(sessionKey)
		if err != nil {
			LogError(EventErrorHttpMiddleware, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if session.SessionData.UserID == -1 {
			rememberCookie, err := GetCookie(r, Options.COOKIE_KEY_REMEMBER)
			if err != nil && err != ErrCookieEmpty {
				SetCookie(w, Options.COOKIE_KEY_REMEMBER, "", 0)
			} else if rememberCookie != nil && rememberCookie.Value != "" {
				authToken, user, err := ValidateAuthToken(rememberCookie.Value)
				if err != nil {
					SetCookie(w, Options.COOKIE_KEY_REMEMBER, "", 0)
				} else {
					session, err = UpdateSession(session.SessionKey, SessionData{ UserID: user.ID }, true)
					if err != nil {
						LogSessionError(EventErrorHttpMiddleware, err, session)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					err = UpdateAuthToken(authToken.Selector, GetUserAgentFromRequest(r), GetIPAddressFromRequest(r))
					if err != nil {
						LogSessionError(EventErrorHttpMiddleware, err, session)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
				}
			}
		}

		extendedCtx := context.WithValue(r.Context(), "csrf-token", csrfToken)
		extendedCtx = context.WithValue(extendedCtx, "session", session)
		extendedR := r.WithContext(extendedCtx)
		next.ServeHTTP(w, extendedR)
	}
}

func authenticatedMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := r.Context().Value("session").(*Session)
		if session.SessionData.UserID == -1 {
			LogSessionWarn(EventUnauthorizedAccess, session)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		user, err := GetUser(session.SessionData.UserID)
		if err != nil {
			destroyAuthCookie(r, w, session)
			LogSessionWarn(EventUnauthorizedAccess, session)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		extendedCtx := context.WithValue(r.Context(), "user", user)
		extendedR := r.WithContext(extendedCtx)
		next.ServeHTTP(w, extendedR)
	}
}

func nonAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := r.Context().Value("session").(*Session)
		if session.SessionData.UserID == -1 {
			next.ServeHTTP(w, r)
			return
		}
		_, err := GetUser(session.SessionData.UserID)
		if err != nil {
			destroyAuthCookie(r, w, session)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			err := checkCSRF(r)
			if err != nil {
				session := r.Context().Value("session").(*Session)
				LogSessionWarn(EventCsrfFailed, session)
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintf(w, "csrf failed")
				return
			}
		}
		next.ServeHTTP(w, r)
	}
}

func destroyAuthCookie(r *http.Request, w http.ResponseWriter, session *Session) error {
	err := InvalidateSession(session.SessionKey)
	if err != nil {
		return err
	}
	rememberCookie, err := GetCookie(r, Options.COOKIE_KEY_REMEMBER)
	if err == nil && rememberCookie.Value != "" {
		selector, _ := DecodeAuthTokenSelectorAndValidator(rememberCookie.Value)
		err = InvalidateAuthToken(selector)
		if err != nil {
			return err
		}
	}
	SetCookie(w, Options.COOKIE_KEY_SESSION, "", 0)
	SetCookie(w, Options.COOKIE_KEY_REMEMBER, "", 0)
	return nil
}
