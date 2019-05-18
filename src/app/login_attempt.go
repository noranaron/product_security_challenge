package app

import (
	"database/sql"
	"time"
)

type LoginAttempt struct {
	Username string
	Time time.Time
	UserAgent string
	IPAddress string
	Success bool
}

var nilTime = time.Time{}

func NewLoginAttempt(username string, t time.Time, userAgent string, ipAddr string, success bool) (*LoginAttempt, error) {
	if t == nilTime {
		t = time.Now()
	}
	_, err := db.Exec("INSERT INTO login_attempts (username, time, useragent, ipaddr, success) VALUES ($1, $2, $3, $4, $5)",
		username, t.Format(time.RFC3339), userAgent, ipAddr, success)
	if err != nil {
		return nil, err
	}
	return &LoginAttempt{
		Username: username,
		Time: t,
		UserAgent: userAgent,
		IPAddress: ipAddr,
		Success: success,
	}, nil
}

func CountFailedLoginAttemptsFromIP(ipAddr string, duration int) (int, error) {
	timeLowerbound := time.Now().Add(-1 * time.Duration(duration) * time.Minute)
	rowLastSuccess := db.QueryRow("SELECT time FROM login_attempts WHERE ipaddr = $1 AND success = 1 ORDER BY time DESC", ipAddr)
	var timeLastSuccess time.Time
	err := rowLastSuccess.Scan(&timeLastSuccess)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	} else if timeLowerbound.Before(timeLastSuccess){
		timeLowerbound = timeLastSuccess
	}

	row := db.QueryRow("SELECT COUNT(id) FROM login_attempts WHERE ipaddr = $1 AND success = 0 AND time > $2", ipAddr, timeLowerbound.Format(time.RFC3339))
	var nFailed int
	err = row.Scan(&nFailed)
	if err != nil {
		return 0, err
	}

	return nFailed, nil
}

func CountFailedLoginAttemptsFromIPAndUsername(ipAddr string, username string, duration int) (int, error) {
	timeLowerbound := time.Now().Add(-1 * time.Duration(duration) * time.Minute)
	rowLastSuccess := db.QueryRow("SELECT time FROM login_attempts WHERE ipaddr = $1 AND username = $2 AND success = 1 ORDER BY time DESC", ipAddr, username)
	var timeLastSuccess time.Time
	err := rowLastSuccess.Scan(&timeLastSuccess)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	} else if timeLowerbound.Before(timeLastSuccess){
		timeLowerbound = timeLastSuccess
	}

	row := db.QueryRow("SELECT COUNT(id) FROM login_attempts WHERE ipaddr = $1 AND username = $2 AND success = 0 AND time > $3",
		ipAddr, username, timeLowerbound.Format(time.RFC3339))
	var nFailed int
	err = row.Scan(&nFailed)
	if err != nil {
		return 0, err
	}

	return nFailed, nil
}

func IsLoginAttemptAllowed(ipAddr string, duration int, maxAttempt int) (bool, error) {
	nFailed, err := CountFailedLoginAttemptsFromIP(ipAddr, duration)
	if err != nil {
		return false, err
	}
	return nFailed <= maxAttempt, nil
}
