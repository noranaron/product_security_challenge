package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"os"
	"src/app"
)

var DEFAULT_OPTIONS = app.AppOptions{
	ADDRESS:                                ":8080",
	DATABASE_NAME:                          "database.db",
	SESSION_SECRET_KEY:                     "abcdefghjiklmnopqrstuvwxyz123456",
	REMEMBER_ME_EXPIRY_LENGTH:              60 * 24 * 10, // minutes
	RESET_TOKEN_EXPIRY_LENGTH:              60,           // minutes
	SESSION_EXPIRY_LENGTH:                  10,           // minutes
	ACCOUNT_LOCKOUT_DURATION:               30,           // minutes
	ACCOUNT_LOCKOUT_LOGIN_ATTEMPT_DURATION: 30,           // minutes
	ACCOUNT_LOCKOUT_LOGIN_ATTEMPT_COUNT:    5,
	MAX_LOGIN_ATTEMPT_DURATION:             30, // minutes
	MAX_LOGIN_ATTEMPT_COUNT:                10,
	MAX_RESET_ATTEMPT_DURATION:             60, // minutes
	MAX_RESET_ATTEMPT_COUNT:                3,
	ENABLE_RECAPTCHA:                       false,
	RECAPTCHA_SECRET_KEY:                   "",
	RECAPTCHA_SITE_KEY:                     "",
	CSRF_TOKEN_LENGTH:                      32,
	HTTPS_ENABLED:                          true,
	HTTPS_CERT_FILE:                        "server.crt",
	HTTPS_KEY_FILE:                         "server.key",
	USE_SECURE_COOKIE:						true,
	COOKIE_KEY_SESSION:						"__ZDSESSID",
	COOKIE_KEY_REMEMBER: 					"__ZDSESSRM",
	COOKIE_KEY_CSRF_TOKEN: 					"__ZDCSRFTOKEN",
	OTP_PRODUCT_NAME:						"zendesk_product_security_challenge",
	PASSWORD_POLICY_OPTION: app.PasswordPolicyOptions{
		MinLength:        12,
		MaxLength:        4096,
		ContainLowercase: false,
		ContainUppercase: false,
		ContainDigit:     false,
		ContainSymbol:    false,
		NotLeaked:        true,
	},
	SMTP_SERVER: app.SmtpServer {
		Host:     "smtp.gmail.com",
		Port:     "465",
		Username: "your_email@gmail.com",
		Password: "your_password",
		UseTLS:   true,
	},
}

func main()  {
	configPtr := flag.String("config", "config.json", "app configuration file")
	flag.Parse()
	options := loadConfiguration(*configPtr)
	app.Start(options)
}

func loadConfiguration(file string) *app.AppOptions {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		data, err := json.MarshalIndent(DEFAULT_OPTIONS, "", "  ")
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(file, data, 0644)
	}
	optionFile, err := os.Open(file)
	defer optionFile.Close()
	if err != nil {
		panic(err)
	}
	jsonParser := json.NewDecoder(optionFile)
	var options app.AppOptions
	err = jsonParser.Decode(&options)
	if err != nil {
		panic(err)
	}
	return &options
}
