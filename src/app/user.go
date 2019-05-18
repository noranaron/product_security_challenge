package app

import (
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

type User struct {
	ID       int
	Username string
	Email	 string
	Password string
	PasswordSalt string
	OTPSecret string
	LockExpire time.Time
}

var (
	ErrUserNotExist = errors.New("user not exist")
	ErrUsernameExists = errors.New("username already existed")
	ErrUserEmailExists = errors.New("user email already existed")
	ErrUsernameNotExist = errors.New("username does not exist")
)

func NewUser(username string, password string, email string) error {
	_, err := GetUserWithUsername(username)
	if err != nil && err != ErrUserNotExist {
		return err
	}
	if err == nil {
		return ErrUsernameExists
	}

	_, err = GetUserWithEmail(email)
	if err != nil && err != ErrUserNotExist {
		return err
	}
	if err == nil {
		return ErrUserEmailExists
	}

	salt, err := GenerateRandomBytes(16)
	if err != nil {
		return err
	}
	hashedPassword, err := HashArgon2(salt, password)
	if err != nil {
		return err
	}
	saltString := hex.EncodeToString(salt)
	_, err = db.Exec("INSERT INTO users (username, email, password, passwordsalt, otpsecret, lockexpire) VALUES ($1, $2, $3, $4, $5, $6)",
		username, email, hashedPassword, saltString, "", time.Time{}.Format(time.RFC3339))
	if err != nil {
		return err
	}
	return nil
}

func scanUserFromRow(row *sql.Row) (*User, error) {
	user := User{}
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.PasswordSalt, &user.OTPSecret, &user.LockExpire)
	if err == sql.ErrNoRows {
		return nil, ErrUserNotExist
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUser(id int) (*User, error) {
	row := db.QueryRow("SELECT id, username, email, password, passwordsalt, otpsecret, lockexpire FROM users WHERE id = $1", id)
	return scanUserFromRow(row)
}

func GetUserWithUsername(username string) (*User, error) {
	row := db.QueryRow("SELECT id, username, email, password, passwordsalt, otpsecret, lockexpire FROM users WHERE username = $1", username)
	return scanUserFromRow(row)
}

func GetUserWithEmail(email string) (*User, error) {
	row := db.QueryRow("SELECT id, username, email, password, passwordsalt, otpsecret, lockexpire FROM users WHERE email = $1", email)
	return scanUserFromRow(row)
}

func LockUser(username string, nMinutes int) error {
	_, err := GetUserWithUsername(username)
	if err != nil {
		return err
	}
	lockExpire := time.Now().Add(time.Duration(nMinutes) * time.Minute)
	_, err = db.Exec("UPDATE users SET lockexpire = $1 WHERE username = $2", lockExpire, username)
	if err != nil {
		return err
	}
	return nil
}

func (user *User) ValidatePassword(password string) error {
	salt, err := hex.DecodeString(user.PasswordSalt)
	if err != nil {
		return err
	}
	hashedPassword, err := HashArgon2(salt, password)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(user.Password), []byte(hashedPassword)) == 0 {
		return ErrPasswordMismatched
	}
	return nil
}

func (user *User) SetPassword(password string) error {
	salt, err := GenerateRandomBytes(16)
	if err != nil {
		return err
	}
	hashedPassword, err := HashArgon2(salt, password)
	if err != nil {
		return err
	}
	saltString := hex.EncodeToString(salt)
	_, err = db.Exec("UPDATE users SET password = $1, passwordsalt = $2 WHERE id = $3", hashedPassword, saltString, user.ID)
	if err != nil {
		return err
	}
	return nil
}


func (user *User) VerifyAccount() error {
	_, err := db.Exec("UPDATE users SET verified = 1 WHERE id = $1", user.ID)
	if err != nil {
		return err
	}
	return nil
}
