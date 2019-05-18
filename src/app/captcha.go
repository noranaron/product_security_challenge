package app

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const recaptchaServerName = "https://www.google.com/recaptcha/api/siteverify"

type RecaptchaResponse struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

func ValidateRecaptcha(remoteip, recaptchaResponse string) bool {
	resp, err := http.PostForm(recaptchaServerName, url.Values{
		"secret": { Options.RECAPTCHA_SECRET_KEY },
		"remoteip": { remoteip },
		"response": { recaptchaResponse },
	})
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	r := RecaptchaResponse{}
	err = json.Unmarshal(body, &r)
	if err != nil {
		return false
	}
	return r.Success
}
