package app

import (
	"errors"
	"net/http"
	"net/url"
)

var ErrCSRFFailed = errors.New("csrf check failed")

func checkCSRF(r *http.Request) error {
	csrfCookie, err := GetCookie(r, Options.COOKIE_KEY_CSRF_TOKEN)
	if err != nil {
		return ErrCSRFFailed
	}
	err = r.ParseForm()
	if err != nil {
		return err
	}
	csrfTokenInCookie := csrfCookie.Value
	csrfTokenInForm := r.FormValue("csrf-token")
	if csrfTokenInCookie != csrfTokenInForm {
		return ErrCSRFFailed
	}

	host := r.URL.Host
	if host == "" {
		host = r.Host
	}

	if r.Header.Get("Origin") != "" {
		originParsed, err := url.Parse(r.Header.Get("Origin"))
		if err != nil {
			return ErrCSRFFailed
		}
		if host != originParsed.Host {
			return ErrCSRFFailed
		}
	} else {
		refererParsed, err := url.Parse(r.Referer())
		if err != nil {
			return ErrCSRFFailed
		}
		if host != refererParsed.Host {
			return ErrCSRFFailed
		}
	}

	return nil
}

func NewCsrfToken(length int) (string, error){
	return GenerateRandomString(length)
}