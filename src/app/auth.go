package app

import (
	"database/sql"
	"errors"
	"time"
)

var (
	ErrPasswordMismatched = errors.New("password mismatched")
	ErrResetTokenInvalid = errors.New("reset token invalid")
	ErrUserLocked = errors.New("user locked")
)

func login(username string, password string) (*User, error) {
	user, err := GetUserWithUsername(username)
	if err != nil {
		return nil, err
	}
	if user.LockExpire.After(time.Now()) {
		return nil, ErrUserLocked
	}
	err = user.ValidatePassword(password)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func changePassword(username string, oldPassword string, newPassword string) error {
	user, err := GetUserWithUsername(username)
	if err == sql.ErrNoRows {
		return ErrUsernameNotExist
	} else if err != nil {
		return err
	}
	err = user.ValidatePassword(oldPassword)
	if err != nil {
		return err
	}
	err = user.SetPassword(newPassword)
	if err != nil {
		return err
	}
	return nil
}

func resetPassword(username string, token string, password string) (*User, error) {
	user, err := GetUserWithUsername(username)
	if err != nil {
		return nil, err
	}
	tokenValid, _ := ValidateResetToken(user.ID, token)
	if !tokenValid {
		return nil, ErrResetTokenInvalid
	}
	err = InvalidateAllResetTokenForUser(user.ID)
	if err != nil {
		return nil, err
	}
	err = user.SetPassword(password)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func generateResetPasswordToken(username string, duration int) (*ResetToken, error) {
	user, err := GetUserWithUsername(username)
	if err != nil {
		return nil, err
	}
	resetToken, err := NewResetToken(user.ID, duration)
	if err != nil {
		return nil, err
	}
	return resetToken, nil
}

func setOTPSecret(userID int, secret string) error {
	_, err := db.Exec("UPDATE users SET otpsecret = $1 WHERE id = $2", secret, userID)
	if err != nil {
		return err
	}
	return nil
}