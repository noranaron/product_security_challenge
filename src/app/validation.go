package app

import (
	"html"
	"net"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

const emailPattern = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"

func ValidateUsername(username string) bool {
	if username != html.EscapeString(username) {
		return false
	}
	for _, c := range username {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			return false
		}
	}
	if len(username) > 32 {
		return false
	}
	return true
}

func ValidateEmailAddress(email string) bool {
	if email != html.EscapeString(email) {
		return false
	}
	re, err := regexp.Compile(emailPattern)
	if err != nil {
		return false
	}
	if !re.MatchString(email) {
		return false
	}
	if len(email) > 32 {
		return false
	}
	return true
}

func GetIPAddressFromRequest(r *http.Request) string {
	ipAddr := ""
	xForwaredForValue := r.Header.Get("X-Forwarded-For")
	if xForwaredForValue != "" {
		clientIP := strings.SplitN(xForwaredForValue, ", ", 1)[0]
		parsedIP := net.ParseIP(clientIP)
		if parsedIP != nil {
			ipAddr = parsedIP.String()
		}
	}
	if ipAddr == "" {
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return ""
		}
		parsedIP := net.ParseIP(clientIP)
		if parsedIP != nil {
			ipAddr = parsedIP.String()
		}
	}
	return html.EscapeString(ipAddr)
}

func GetUserAgentFromRequest(r *http.Request) string {
	return html.EscapeString(r.UserAgent())
}

func GetHostFromRequest(r *http.Request) string {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	return html.EscapeString(host)
}
