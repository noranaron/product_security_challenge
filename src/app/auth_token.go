package app

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"strings"
	"time"
)

var (
	ErrAuthTokenInvalid = errors.New("auth token invalid")
	ErrAuthTokenExpired = errors.New("auth token expired")
)

type AuthToken struct {
	Selector        string
	Validator       string
	HashedValidator string
	UserID          int
	Expires         time.Time
	Valid           bool
	UserAgent		string
	IPAddress		string
}

func NewAuthToken(userID int, durationLength int, userAgent string, ipAddr string) (*AuthToken, error) {
	var selector string
	var err error
	isSelecterNotDuplicate := false
	for !isSelecterNotDuplicate {
		selector, err = GenerateRandomString(12)
		if err != nil {
			return nil, err
		}
		row := db.QueryRow("SELECT selector FROM auth_tokens WHERE selector = $1", selector)
		err = row.Scan()
		if err == sql.ErrNoRows {
			isSelecterNotDuplicate = true
		} else if err != nil {
			return nil, err
		}
	}
	validator, err := GenerateRandomString(12)
	if err != nil {
		return nil, err
	}
	hashedValidator := HashSHA256(validator)
	expireTime := time.Now().Add(time.Duration(durationLength) * time.Minute)
	_, err = db.Exec("INSERT INTO auth_tokens (selector, hashedvalidator, userid, expires, valid, useragent, ipaddress) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		selector, hashedValidator, userID, expireTime.Format(time.RFC3339), 1, userAgent, ipAddr)
	if err != nil {
		return nil, err
	}
	return &AuthToken{
		Selector:        selector,
		Validator:       validator,
		HashedValidator: validator,
		UserID:          userID,
		Expires:         expireTime,
		Valid:           true,
		UserAgent:		 userAgent,
		IPAddress:		 ipAddr,
	}, nil
}

func GetAuthToken(selector string, validator string) (*AuthToken, error) {
	authToken := AuthToken{}
	row := db.QueryRow("SELECT selector, hashedvalidator, userid, expires, valid, useragent, ipaddress FROM auth_tokens WHERE selector = $1", selector)
	err := row.Scan(&authToken.Selector, &authToken.HashedValidator, &authToken.UserID, &authToken.Expires, &authToken.Valid, &authToken.UserAgent, &authToken.IPAddress)
	if err != nil {
		return nil, err
	}
	hashedValidator := HashSHA256(validator)
	if subtle.ConstantTimeCompare([]byte(hashedValidator), []byte(authToken.HashedValidator)) == 0 || !authToken.Valid {
		return nil, ErrAuthTokenInvalid
	}
	if authToken.Expires.Before(time.Now()) {
		return nil, ErrAuthTokenExpired
	}
	return &authToken, nil
}

func UpdateAuthToken(selector string, userAgent string, ipAddr string) error {
	_, err := db.Exec("UPDATE auth_tokens SET userAgent = $1, ipaddress = $2 WHERE selector = $3", userAgent, ipAddr, selector)
	if err != nil {
		return err
	}
	return nil
}

func ValidateAuthToken(selectorAndValidator string) (*AuthToken, *User, error) {
	selector, validator := DecodeAuthTokenSelectorAndValidator(selectorAndValidator)
	authToken, err := GetAuthToken(selector, validator)
	if err != nil {
		return nil, nil, err
	}
	user, err := GetUser(authToken.UserID)
	if err != nil {
		return nil, nil, err
	}
	return authToken, user, nil
}

func InvalidateAuthToken(selector string) error {
	_, err := db.Exec("UPDATE auth_tokens SET valid = 0 WHERE selector = $1", selector)
	if err != nil {
		return err
	}
	return nil
}

func InvalidateAuthTokenForUser(userID int) error {
	_, err := db.Exec("UPDATE auth_tokens SET valid = 0 WHERE userid = $1", userID)
	if err != nil {
		return err
	}
	return nil
}

func GetAuthTokensForUser(userID int) ([]*AuthToken, error) {
	rows, err := db.Query("SELECT selector, hashedvalidator, userid, expires, valid, useragent, ipaddress FROM auth_tokens WHERE userid = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []*AuthToken
	for rows.Next() {
		authToken := AuthToken{}
		err := rows.Scan(&authToken.Selector, &authToken.HashedValidator, &authToken.UserID, &authToken.Expires, &authToken.Valid, &authToken.UserAgent, &authToken.IPAddress)
		if err != nil {
			return nil, err
		}
		if !authToken.Valid || authToken.Expires.Before(time.Now()) {
			continue
		}
		tokens = append(tokens, &authToken)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func DecodeAuthTokenSelectorAndValidator(s string) (selector string, validator string) {
	segments := strings.Split(s, ":")
	selector = segments[0]
	if len(segments) > 1 {
		validator = segments[1]
	}
	return selector, validator
}

func EncodeAuthTokenSelectorAndValidator(selector string, validator string) string {
	return selector + ":" + validator
}
