package app

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"unicode"
)

type PasswordPolicyOptions struct {
	MinLength        int
	MaxLength        int
	ContainLowercase bool
	ContainUppercase bool
	ContainDigit     bool
	ContainSymbol    bool
	NotLeaked        bool
}

var ErrPasswordPolicy = errors.New("password policy not fulfilled")

func CheckPassword(password string, option PasswordPolicyOptions) (bool, error, string) {
	if option.MinLength > 0 {
		if len(password) < option.MinLength {
			return false, ErrPasswordPolicy, fmt.Sprintf("Minimum length should be %d", option.MinLength)
		}
	}
	if option.MaxLength > 0 {
		if len(password) > option.MaxLength {
			return false, ErrPasswordPolicy, fmt.Sprintf("Maximum length should be %d", option.MaxLength)
		}
	}
	if option.ContainLowercase {
		ok := false
		for _, c := range password {
			if unicode.IsLower(c) {
				ok = true
				break
			}
		}
		if !ok {
			return false, ErrPasswordPolicy, fmt.Sprintf("password should contains lowercase letter")
		}
	}
	if option.ContainUppercase {
		ok := false
		for _, c := range password {
			if unicode.IsUpper(c) {
				ok = true
				break
			}
		}
		if !ok {
			return false, ErrPasswordPolicy, fmt.Sprintf("password should contains uppercase letter")
		}
	}
	if option.ContainDigit {
		ok := false
		for _, c := range password {
			if unicode.IsDigit(c) {
				ok = true
				break
			}
		}
		if !ok {
			return false, ErrPasswordPolicy, fmt.Sprintf("password should contains digit")
		}
	}
	if option.ContainSymbol {
		ok := false
		for _, c := range password {
			if unicode.IsSymbol(c) || unicode.IsPunct(c) {
				ok = true
				break
			}
		}
		if !ok {
			return false, ErrPasswordPolicy, fmt.Sprintf("password should contains symbol")
		}
	}

	if option.NotLeaked {
		encBytes := sha1.Sum([]byte(password))
		hashedPassword := strings.ToUpper(hex.EncodeToString(encBytes[:]))
		prefix := hashedPassword[:5]
		suffix := hashedPassword[5:]
		resp, err := http.DefaultClient.Get(fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix))
		if err != nil {
			return false, err, ""
		}
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("pwnedpasswords.com return non-200"), ""
		}
		defer resp.Body.Close()
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, err, ""
		}
		bodyString := string(bodyBytes)
		if strings.Contains(bodyString, suffix) {
			return false, ErrPasswordPolicy, "password leaked in internet"
		}
	}

	return true, nil, ""
}
