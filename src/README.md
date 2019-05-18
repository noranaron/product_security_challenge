# Product Security Challenge

## Table of contents

- [Product Security Challenge](#product-security-challenge)
  * [Features](#features)
  * [How to run this application](#how-to-run-this-application)
    + [Build from source](#build-from-source)
  * [Running the application](#running-the-application)
    + [Executing the Binary](#executing-the-binary)
  * [Changing configuration options](#changing-configuration-options)
    + [Enabling reCaptcha](#enabling-recaptcha)
    + [Setting up SMTP server](#setting-up-smtp-server)
    + [Changing password policy](#changing-password-policy)


## Features

For further explanation, see [FEATURES.md](FEATURES.md).

Main features:
 - Authentication functionalities, including log in, sign up, change password, and forget password.
 - Account's password hashed using [Argon2](https://www.cryptolux.org/images/0/0d/Argon2.pdf) hash function algorithm.
 - Structured application logging, including logs for malicious actions.
 - CSRF prevention, utilizing double submit cookie pattern and Origin http headers.
 - Input sanitization and validations, including form inputs and HTTP headers.
 - TOTP-based two-factor authentication support.
 - Account lockout after consecutive failed login attempts.
 - IP address-based automated / brute force login attempt preventions.
 - Session data is encrypted and stored at server-side.
 - Support long-term persistent session (remember me).
 - Support serving in HTTPS.
 - Configurable password policies.
 - Support captcha using [Google ReCaptcha](https://www.google.com/recaptcha/).
 - Support manual sessions invalidation by user.
 

## How to run this application

### Build from source

This application is written in Go v1.12.
Change `GOOS` and `GOARCH` according to target system.

```bash
$ git clone https://github.com/noranaron/product_security_challenge.git

$ cd product_security_challenge/src

$ GOOS=darwin GOARCH=amd64 go build -o zendesk_login
```

After running the above commands, an executable binary `zendesk_login` will be compiled.


In order to use HTTPS, you can generate example key and self-signed certificate using the provided `gencert.sh`

```bash
$ ./gencert.sh

$ ls server.*
server.crt server.key
```

### Docker container

A docker container serving this application is provided.

```bash
$ docker run -v $(pwd)/app_home:/app -p 8080:8080 adamyordan/product_security_challenge
```


## Running the application

### Executing the Binary

Execute the executable binary `zendesk_login`.

```bash
$ ./zendesk_login -h
Usage of ./zendesk_login:
  -config string
    	app configuration file (default "config.json")
```

After running the binary the first time, a new file `config.json` will be created.
You may change configuration accordingly and restart the application.
In order to run properly, you may need to change the `SESSION_SECRET_KEY`,
enable reCaptcha and setup SMTP server (will be explained below).

```bash
$ cat config.json

{
  "ADDRESS": ":8080",
  "DATABASE_NAME": "database.db",
  "SESSION_SECRET_KEY": "abcdefghjiklmnopqrstuvwxyz123456",
  "REMEMBER_ME_EXPIRY_LENGTH": 14400,
  "RESET_TOKEN_EXPIRY_LENGTH": 60,
  "SESSION_EXPIRY_LENGTH": 10,
  "ACCOUNT_LOCKOUT_DURATION": 30,
  "ACCOUNT_LOCKOUT_LOGIN_ATTEMPT_DURATION": 30,
  "ACCOUNT_LOCKOUT_LOGIN_ATTEMPT_COUNT": 5,
  "MAX_LOGIN_ATTEMPT_DURATION": 30,
  "MAX_LOGIN_ATTEMPT_COUNT": 10,
  "MAX_RESET_ATTEMPT_DURATION": 60,
  "MAX_RESET_ATTEMPT_COUNT": 3,
  "ENABLE_RECAPTCHA": false,
  "RECAPTCHA_SECRET_KEY": "",
  "RECAPTCHA_SITE_KEY": "",
  "CSRF_TOKEN_LENGTH": 32,
  "HTTPS_ENABLED": true,
  "HTTPS_CERT_FILE": "server.crt",
  "HTTPS_KEY_FILE": "server.key",
  "USE_SECURE_COOKIE": true,
  "COOKIE_KEY_SESSION": "__ZDSESSID",
  "COOKIE_KEY_REMEMBER": "__ZDSESSRM",
  "COOKIE_KEY_CSRF_TOKEN": "__ZDCSRFTOKEN",
  "OTP_PRODUCT_NAME": "zendesk_product_security_challenge",
  "PASSWORD_POLICY_OPTION": {
    "MinLength": 12,
    "MaxLength": 4096,
    "ContainLowercase": false,
    "ContainUppercase": false,
    "ContainDigit": false,
    "ContainSymbol": false,
    "NotLeaked": true
  },
  "SMTP_SERVER": {
    "Host": "smtp.gmail.com",
    "Port": "465",
    "Username": "your_email@gmail.com",
    "Password": "your_password",
    "UseTLS": true
  }
}
```

An SQLite3 database will also be created at `database.db` by default.
You can change the database file path in the configuration file `config.json`.

After executing the binary, a new HTTP(S) server will be served in port `8080` (by default).
You may access the application using browser by opening https://localhost:8080/

```bash
$ ./zendesk_login
time="2019-05-16T13:17:20Z" level=info msg="starting up application" event=APP_STARTUP
time="2019-05-16T13:17:20Z" level=info msg="starting up http server" address="localhost:8080" event=HTTP_SERVER_STARTUP https=true
```

## Changing configuration options

### Enabling reCaptcha

This application provide reCaptcha for captcha service to prevent security attacks e.g. automated
scripted request.

To enable reCaptcha, you need to change some configurations in `config.json`.
Change `ENABLE_RECAPTCHA` to `true`, and set `RECAPTCHA_SECRET_KEY` and
`RECAPTCHA_SITE_KEY` accordingly. You can get the secret key and site key from https://www.google.com/recaptcha/admin.
Please select `reCaptcha v2` when registering for reCaptcha keys.


```json
  "ENABLE_RECAPTCHA": true,
  "RECAPTCHA_SECRET_KEY": "",
  "RECAPTCHA_SITE_KEY": "",
```

### Setting up SMTP server

For _forget password_ feature, this application needs a valid SMTP server to send emails.
You can use google mail SMTP server (smtp.gmail.com) and fill in your Gmail credentials.
You may want to use Google [App Passwords](https://support.google.com/accounts/answer/185833?hl=en) instead of your account password.

```json
  "SMTP_SERVER": {
    "Host": "smtp.gmail.com",
    "Port": "465",
    "Username": "your_email@gmail.com",
    "Password": "your_password",
    "UseTLS": true
  }
```


### Changing password policy

Password policies is configurable from configuration file `config.json`. When signing up or changing password,
the inputted password will be checked with the password policies.
If the password does not fulfill any of the policy, the sign up or change password request will be rejected.

The following policy is supported:

| Policy           | Default Value | Description                                                                     |
|------------------|---------------|---------------------------------------------------------------------------------|
| MinLength        | 12            | Password should have minimum length of N                                        |
| MaxLength        | 4096          | Password should have maximum length of N                                        |
| ContainLowercase | false         | Password should include at least 1 lowercase letter                             |
| ContainUppercase | false         | Password should include at least 1 uppercase letter                             |
| ContainDigit     | false         | Password should include at least 1 digit                                        |
| ContainSymbol    | false         | Password should include at least 1 symbol                                       |
| NotLeaked        | true          | Password should not be leaked on internet (checked with api.pwnedpasswords.com) |
