package app

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"time"
)

var (
	ErrSessionInvalid = errors.New("session invalid")
	ErrSessionExpired = errors.New("session expired")
	ErrSessionKeyNotFound = errors.New("session key not found")
)

type Session struct {
	SessionKey  string
	SessionData SessionData
	Expires     time.Time
	Valid       bool
	UserID		int
	UserAgent   string
	IPAddress	string
}

type SessionData struct {
	UserID int
	ShowLoginCaptcha bool
}

func NewSession(data SessionData, userAgent string, ipAddr string) (*Session, error) {
	var key string
	var err error
	keyOK := false
	for !keyOK {
		key, err = GenerateRandomString(32)
		row := db.QueryRow("SELECT sessionKey FROM sessions WHERE sessionKey = $1", key)
		err = row.Scan()
		if err == sql.ErrNoRows {
			keyOK = true
		} else if err != nil {
			return nil, err
		}
	}

	encryptedData, err := encryptSessionData(data)
	if err != nil {
		return nil, err
	}

	expireTime := time.Now().Add(time.Duration(Options.SESSION_EXPIRY_LENGTH) * time.Minute)
	_, err = db.Exec("INSERT INTO sessions (sessionKey, sessionData, expires, valid, userid, useragent, ipaddress) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		key, encryptedData, expireTime.Format(time.RFC3339), true, -1, userAgent, ipAddr)
	if err != nil {
		return nil, err
	}

	return GetSession(key)
}

func GetSession(key string) (*Session, error) {
	session := Session{}
	var encryptedData string
	row := db.QueryRow("SELECT sessionKey, sessionData, expires, valid, userid, useragent, ipaddress FROM sessions WHERE sessionKey = $1", key)
	err := row.Scan(&session.SessionKey, &encryptedData, &session.Expires, &session.Valid, &session.UserID, &session.UserAgent, &session.IPAddress)
	if err == sql.ErrNoRows {
		return nil, ErrSessionKeyNotFound
	} else if err != nil {
		return nil, err
	}
	if !session.Valid {
		return nil, ErrSessionInvalid
	}
	if session.Expires.Before(time.Now()) {
		return nil, ErrSessionExpired
	}
	sessionData, err := decryptSessionData(encryptedData)
	if err != nil {
		return nil, err
	}
	session.SessionData = *sessionData
	return &session, nil
}

func UpdateSession(key string, data SessionData, renewExpireTime bool) (*Session, error) {
	encryptedData, err := encryptSessionData(data)
	if err != nil {
		return nil, err
	}
	if renewExpireTime {
		expireTime := time.Now().Add(time.Duration(Options.SESSION_EXPIRY_LENGTH) * time.Minute)
		_, err = db.Exec("UPDATE sessions SET sessionData = $1, expires = $2, userid = $3 WHERE sessionKey = $4",
			encryptedData, expireTime.Format(time.RFC3339), data.UserID, key)
	} else {
		_, err = db.Exec("UPDATE sessions SET sessionData = $1, userid = $2 WHERE sessionKey = $3", encryptedData, data.UserID, key)
	}
	if err != nil {
		return nil, err
	}
	return GetSession(key)
}

func InvalidateSession(key string) error {
	_, err := db.Exec("UPDATE sessions SET valid = $1 WHERE sessionKey = $2", 0, key)
	if err != nil {
		return err
	}
	return nil
}

func decryptSessionData(s string) (*SessionData, error) {
	b64bytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	decryptedBytes, err := Decrypt(b64bytes, []byte(Options.SESSION_SECRET_KEY))
	reader := bytes.NewReader(decryptedBytes)
	decoder := gob.NewDecoder(reader)
	var data SessionData
	err = decoder.Decode(&data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func encryptSessionData(data SessionData) (string, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(data)
	if err != nil {
		return "", err
	}
	cipherBytes, err := Encrypt(buffer.Bytes(), []byte(Options.SESSION_SECRET_KEY))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

func GetSessionsForUser(userID int) ([]*Session, error) {
	rows, err := db.Query("SELECT sessionKey, sessionData, expires, valid, userid, useragent, ipaddress FROM sessions WHERE userid = $1 AND valid = 1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []*Session
	for rows.Next() {
		session := Session{}
		var encryptedData string
		err := rows.Scan(&session.SessionKey, &encryptedData, &session.Expires, &session.Valid, &session.UserID, &session.UserAgent, &session.IPAddress)
		if err == sql.ErrNoRows {
			continue
		} else if err != nil {
			return nil, err
		}
		if !session.Valid {
			continue
		}
		if session.Expires.Before(time.Now()) {
			continue
		}
		sessionData, err := decryptSessionData(encryptedData)
		if err != nil {
			return nil, err
		}
		session.SessionData = *sessionData
		sessions = append(sessions, &session)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

func InvalidateSessionsForUser(userID int) error {
	_, err := db.Exec("UPDATE sessions SET valid = $1 WHERE userid = $2", 0, userID)
	if err != nil {
		return err
	}
	return nil
}
