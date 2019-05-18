package app

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"
)

var ErrResetTokenNotExist = errors.New("reset token not exist")

type ResetToken struct {
	UserID      int
	Token		string // only available when first generated
	HashedToken string
	Expire      time.Time
	Valid       bool
}

func NewResetToken(userID int, duration int) (*ResetToken, error) {
	_, err := GetUser(userID)
	if err != nil {
		return nil, err
	}
	err = InvalidateAllResetTokenForUser(userID)
	if err != nil {
		return nil, err
	}
	token, err := GenerateRandomString(32)
	if err != nil {
		return nil, err
	}
	hashedToken := HashSHA256(token)
	expire := time.Now().Add(time.Duration(duration) * time.Minute)
	_, err = db.Exec("INSERT INTO reset_tokens (userid, token, expire, valid) VALUES ($1, $2, $3, $4)",
		userID, hashedToken, expire.Format(time.RFC3339), true)
	if err != nil {
		return nil, err
	}
	return &ResetToken{
		UserID: userID,
		Token: token,
		HashedToken: hashedToken,
		Expire: expire,
		Valid: true,
	}, nil
}

func GetResetToken(userID int) (*ResetToken, error) {
	var resetToken ResetToken
	row := db.QueryRow("SELECT userid, token, expire, valid FROM reset_tokens WHERE userid = $1 and valid = 1 and expire > $2", userID, time.Now().Format(time.RFC3339))
	err := row.Scan(&resetToken.UserID, &resetToken.HashedToken, &resetToken.Expire, &resetToken.Valid)
	if err == sql.ErrNoRows {
		return nil, ErrResetTokenNotExist
	}
	if err != nil {
		return nil, err
	}
	return &resetToken, nil

}

func InvalidateAllResetTokenForUser(userID int) error {
	_, err := db.Exec("UPDATE reset_tokens SET valid = 0 WHERE userid = $1", userID)
	if err != nil {
		return err
	}
	return nil
}

func ValidateResetToken(userID int, token string) (bool, error) {
	resetToken, err := GetResetToken(userID)
	if err != nil {
		return false, err
	}
	hashedToken := HashSHA256(token)
	return subtle.ConstantTimeCompare([]byte(hashedToken), []byte(resetToken.HashedToken)) == 1, nil
}

func IsResetAllowed(username string, duration int, expireDuration int, maxCount int) bool {
	timeUpperBound := time.Now().Add(time.Duration(expireDuration - duration) * time.Minute)
	user, err := GetUserWithUsername(username)
	if err != nil {
		return false
	}
	row := db.QueryRow("SELECT count(id) FROM reset_tokens WHERE userid = $1 and expire > $2", user.ID, timeUpperBound)
			var count int
	err = row.Scan(&count)
	if err != nil {
		return false
	}
	return count <= maxCount
}