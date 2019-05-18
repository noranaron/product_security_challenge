# Features Documentation

## Table of Contents

- [Features Documentation](#features-documentation)
  * [Overview](#overview)
  * [Session management](#session-management)
    + [Design consideration](#design-consideration)
    + [Implementation](#implementation)
  * [Authentication](#authentication)
    + [Design consideration](#design-consideration-1)
  * [Input sanitization and validation](#input-sanitization-and-validation)
  * [Password hashed](#password-hashed)
  * [Prevention of Timing Attacks](#prevention-of-timing-attacks)
  * [Logging](#logging)
  * [CSRF prevention](#csrf-prevention)
  * [Multi factor authentication](#multi-factor-authentication)
  * [Password reset / Forget password mechanism](#password-reset--forget-password-mechanism)
  * [Blocking brute force attacks (Account lockout)](#blocking-brute-force-attacks-account-lockout)
  * [Cookie](#cookie)
  * [HTTPS](#https)
  * [Password Policy (Known password check)](#password-policy-known-password-check)
  * [Mitigating user enumeration](#mitigating-user-enumeration)
    + [Mitigating user enumeration in Log in page](#mitigating-user-enumeration-in-log-in-page)
    + [Mitigating user enumeration in Forget Password pages](#mitigating-user-enumeration-in-forget-password-pages)
    + [Mitigating user enumeration in Sign up page](#mitigating-user-enumeration-in-sign-up-page)


## Overview

This application is written in Go programming language (v1.12). Most of the features mentioned in this documentation is
self-implemented. This application can be configured by modifying `config.json`. To store application data and system data,
an SQLite3 database is used.

Third party libraries used are:
 - golang.org/x/crypto v0.0.0-20190513172903-22d7a77e9e5f
 - github.com/mattn/go-sqlite3 v1.10.0
 - github.com/boombuler/barcode v1.0.0
 - github.com/sirupsen/logrus v1.4.1


## Session management

### Design consideration

The session management feature is built from scratch to showcase the author's knowledge and understanding of session
management. In real case occasions, it is recommended to use built-in frameworks instead of building one from scratch.

 - A session will be created after the very first user request to keep track of anonymous users.

 - After the user has authenticated, this app will attach the user's userID to the session.

 - Session key / identifier is assigned at session creation time. This key is shared and exchanged by the user and the
   app for the duration of the session. the session ID for this app is with the following format: `__ZDSESSID=<value>`, where
   value is a string of random characters with length 32. The key can be represented in regex pattern as `/^[a-zA-Z0-9]{32}$/`.
    
    - Session key with length of 32 chars (256 bits) is expected to be long enough to prevent brute force attacks.

    - The random function is using cryptographically secure random number generator implemented in package
      [crypto/rand](https://golang.org/pkg/crypto/rand/), in order to make session keys unpredictable (random enough)
      and prevent guessing attack.

 - Session value (or session data) contains the `UserID` (ID of the authenticated user), and
   other information, including `ShowLoginCaptcha` to flag whether to show captcha at login page.

    - The information stored in session data is made as minimum as possible to prevernt information disclosure attack,
      in the event where an attacker is able to decode the contents of the session data.

    - Session value is encrypted with `AES-GCM` algorithm, with the length of key is 32 bytes (256 bits).
      This is to prevent data leakage when the database is compromised.
 
 - Session value and key is stored in server side database (SQLite3).
 
 - Session management is implemented by using HTTP cookies. This is because cookies allow expiration time, granular
   usage constraints, and security features (including HostOnly, Session, Secure, SameSite and HttpOnly attributes).
 
 - Session have expiration time. When expired (or when user manually log out), sessions should be invalidated in both sides,
   server and client.
    - short-term session will expire when browser client shuts down or after 10 minutes (configurable)
    - long-term persistent authentication (_Remember me_) will expire after 10 days (configurable)

 - Remember Me (long-term persistent authentication) is supported
   (reference: [link](https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence))
    - Store `selector:validator` in cookie. `selector` is a unique ID to facilitate database look-ups.
    - SHA-256 hash of `validator` is stored in database. Plaintext of `selector` is stored in database.
        ```sqlite
        CREATE TABLE `auth_tokens` (
          `selector` VARCHAR(12) PRIMARY KEY,
          `hashedValidator` VARCHAR(64) NOT NULL,
          `userid` INTEGER NOT NULL,
          `expires` DATETIME NOT NULL,
          `valid` INTEGER NOT NULL
        )
        ```
    - If database is leaked, immediate session hijacking is prevented, because attacker do not know `validator` value.
    - Login algorithm with _remember me_ token:
        - Get `selector` and `validator` from _remember me_ cookie.
        - Query the row in table `auth_tokens` with the given selector. If none is found, abort.
        - Hash the `validator`
        - Compare the generated hash with the hash stored in database. If not equal, abort.
        - Associate current session with the appropriate user ID.

 - There is a mechanism for user to manually invalidate all sessions.

### Implementation

 - When a user first visit the application.
    - if session cookie `__ZDSESSID` is not set or its value is empty or it is expired:
        - generate `sessionKey` with anonymous user ID (`-1`).
        - set cookie:
            ```go
            session, _ := NewSessions(SessionData{UserID: -1})

            http.SetCookie(w, &http.Cookie{
                Name: "__ZDSESSID",
                Value: session.SessionKey,
                Path: "/",
                SameSite: http.SameSiteLaxMode,
                Secure: true,
                HttpOnly: true,
            })
            ```
    - if _remember me_ cookie `__ZDSESSRM` is set:
        - validate `__ZDSESSRM`. If invalid, abort.
        - get `userid` associated with cookie `__ZDSESSRM`.
        - attach or set the `userid` to the session
            ```go
            user, _ := ValidateAuthToken(rememberCookie.Value)
            if err != nil {
  	            // abort
            } else {
                session, _ = UpdateSession(sessionKey, SessionData{
      	            UserID: user.ID
                })
            }
            ```

 - After user authenticated:
    - attach or set the user's `userid` to the session.
        ```go
        if loginSuccessful {
            _, err = UpdateSession(sessionKey, SessionData{
              UserID: user.ID
            })
        }
        ```

 - After user logged out:
    - Invalidate session in server side.
    - Invalidate long-term auth (_remember me_) token in server side.
    - Invalidate cookie `__ZDSESSID` and `__ZDSESSRM` in client side, by setting value to `""` and `Max-Age` to `0`
        ```go
        _ := InvalidateSession(session.SessionKey)

        rememberCookie, _ := GetCookie(r, "__ZDSESSRM")
        if err == nil && rememberCookie.Value != "" {
            selector, _ := DecodeAuthTokenSelectorAndValidator(rememberCookie.Value)
            _ = InvalidateAuthToken(selector)
        }
  
        http.SetCookie(w, &http.Cookie{
            Name: "__ZDSESSID",
            Value: "",
            Path: "/",
            Secure: true,
            HttpOnly: true,
            MaxAge: 0,
        })

        http.SetCookie(w, &http.Cookie{
            Name: "__ZDSESSRM",
            Value: "",
            Path: "/",
            Secure: true,
            HttpOnly: true,
            MaxAge: 0,
        })
        ```
 

## Authentication

### Design consideration

 - Password policy
    - refer to section [Password Policy](#password-policy-known-password-check).

 - Sign up
    - User need to supply `username`, `email`, and `password` values.
    - `username` should only contains alphanumeric characters with length between 1 and 32.
    - `email` should follow standard email address format,
    - `password` should follow the defined password policies.

 - Change password
    - User need to supply `old_password` and `new_password` values.
    - `old_password` should match the current password.
    - `new_password` should follow the defined password policies.
    - If successful, invalidate all active sessions for the user.

 - Password Reset / Forget password / Account recovery
    - If successful, invalidate all active sessions for the user.
    - Refer to section [Password Reset](#password-reset--forget-password-mechanism).
  


## Input sanitization and validation
 
 - User input sanitization to prevent SQL injection
    - Use safe query functions provided by Go's `database/sql` package

 - User input sanitization to prevent potential code injection
    - All user input values (e.g. username and email during sign up, user agent header) are escaped 
      using [`html.EscapeString` function](https://golang.org/pkg/html/#EscapeString)
      to prevent code injection and cross-site scripting (XSS) issues.
      
    - When displaying information or data (including possible user input) as HTML to user,
      this app use package `html/template` to generate HTML safe against code injection
       ```go
        <span> {{ .ThisIsAutoEscaped }} </span>
        ```
    
    - Username is only allowed to contain alphanumeric characters
        ```go
        func ValidateUsername(username string) bool {
            if username != html.EscapeString(username) {
                return false
            }
            for _, c := range username {
                if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
                    return false
                }
            }
            return true
        }
        ```
        
    - Email address is validated against standard email regex pattern
        ```go
        func ValidateEmailAddress(email string) bool {
            if email != html.EscapeString(email) {
                return false
            }
            re, err := regexp.Compile(emailPattern)
            if err != nil {
                return false
            }
            if !re.MatchString(email) {
                return false
            }
            if len(email) > 32 {
                return false
            }
            return true
        }
        ```


## Password hashed

Plaintext of password is not stored in database. Instead, the hash of the password and its salt is stored.

The hash function is using [Argon2](https://github.com/P-H-C/phc-winner-argon2),
the password-hashing function that won the [Password Hashing Competition (PHC)](https://password-hashing.net/)

 - Upon sign up and changing password, a salt is generated using a cryptographically secure RNG,
   then the password and the salt is hashed. The salt and the hash value is then stored in database.
    ```go
    func NewUser(username string, password string) error { 	 
 	    ...
        
    	salt, err := GenerateRandomBytes(16)
    	hashedPassword, err := HashArgon2(salt, password)
        
 	    db.Exec("INSERT INTO users (username, password, otpsecret, lockexpire) VALUES ($1, $2, $3, $4)",
            username, hashedPassword, "", time.Time{}.Format(time.RFC3339))

        ...
    }
    ```

 - Upon sign in (or validating old password during changing password), the inputted password from user is hashed and then compared to the hash password in the database.
    ```go
    func (user *User) ValidatePassword(password string) error {
        salt, err := hex.DecodeString(user.PasswordSalt)
        hashedPassword, err := HashArgon2(salt, password)
        if user.Password != hashedPassword {
            return ErrPasswordMismatched
        }
        return nil
    }
    ```

## Prevention of Timing Attacks
 
 - This app uses cryptographically secure pseudorandom number generator provided by package [crypto/rand](https://golang.org/pkg/crypto/rand/).
   Therefore attacks by analyzing and looking at time as random seed are not practical anymore.

 - Captcha is used to block automated requests. Most timing attacks rely on the ability to send a large number
   of automated requests and analyse the response times.

 - Time-consuming operations (e.g. sending password reset token via email) are run asynchronously in the background.
   User should not be able determine any sensitive information by examining the HTTP response time latency.
   
 - String comparisons (e.g. comparing token values) are using time-constant comparison function e.g. `subtle.ConstantTimeCompare()`.

 
## Logging

Logging utilizes structured logger provided by package `github.com/sirupsen/logrus` with the output log format
compatible with `github.com/kr/logfmt`.

The log is available in standard output (`os.StdOut`) and external file `app.log`.


Events logged including:
 - Input validation failures
 - Authentication successes and failures
 - Authorization failures e.g. unauthenticated user trying to access unauthorized pages
 - Session management failures e.g. cookie session identification value modification
 - Application errors and system events
 - Application and related systesms start-ups and shut-downs
 - Data changes
 - Suspicious behaviour e.g. CSRF check failure

Attributes in event logs:
 - Log date and time
 - Severity e.g. `{error, warning, info}`
 - Type of event
 - Description
 - Related information e.g. session key


## CSRF prevention

 - State changing operation requests are all using POST method. This application does not use GET for such operations.
   (Refering to [RFC2616, section 9.1.1](https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9.1.1))

 - Using double submit cookie pattern.
    - When a user first visit, this app will generate a random string value of 32 bytes (generated using secure RNG),
      and set it as value in cookie `__ZD_CSRFTOKEN`.
    - When a user send a POST request, this value should be included (as a hidden form value `csrf-token`).
      If value of `__ZD_CSRFTOKEN` cookie matches with `csrf-token` form value, the server accepts it as legitimate
      request, else the request is rejected.
 
 - Verifying origin with standard headers.
    - Identifying the Source Origin
        - if the `Origin` header present, verify that its value matches the `Host` header.
        - if the `Origin` header is not present, verify the hostname in the `Referer` matches the `Host` header.
 
 - Use SameSite cookie attribute, set to `lax`.
    - The `lax` value is chosen because it provides a reasonable balance between security and usability,
      in the event to maintain a user's logged in session after they arrives from external link.
    - The `lax` value will block CSRF-prone requests from external websites, such as ones using POST.
 
 
## Multi factor authentication

 - The multi factor authentication provided in this application is:
    - TOTP-based authentication. The implementation is available at `src/app/totp.go`.

 - TOTP enrollment mechanism:
    - An authenticated user may go to `https://APP_URL/setup-mfa` to setup Multi factor authentication.
    - A page will be displayed to user, containing the QR Code images.
      User may use [Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en_SG)
      app or other appropriate application to scan the QR code and enroll the TOTP authentication.
    - The user should input the OTP passcode in the form inside the page.
      If the passcode is correct, multi factor authentication is successfully setup for the user.

 - When sign in, the OTP passcode (alongside with username and password) will be requested for users already setting up multi factor authentication.

 - User may later reset or remove the TOTP-based multi factore authentication by visiting `https://APP_URL/setup-mfa`.


## Password reset / Forget password mechanism

User can request an account password reset by visiting `https://APP_URL/reset-password`.
The steps are as follow:
 - User input `username`
 - Server check if username is valid and exist in database:
    - If username valid:
        - Server generate random `reset_token` using cryptographically secure RNG.
            - Server then store the token and associated username in database.
            - If there exists previous `reset_token` for the user, invalidate all the previous tokens,
             so there exists at most 1 valid reset token for a user.
            - The reset token will expire in 60 minutes (configurable)
        - Server then send the `token` to the associated user's email address.
 - Regardless of the validity of inputted username, user will then be redirected to a new page to input their token.
 - In the new page, by providing the correct `username` and correct `token`, user is allowed to set a new password.
 - To avoid this feature exploited to spam emails, the number of reset attempts are limited.
   By default, a user's reset token can only be sent to an email address at maximum 3 times in 60 minutes.


## Blocking brute force attacks (Account lockout)

The following approaches are used to prevent brute force attacks:

 - Account lockout
    - After a defined number (5 by default) of incorrect password attempts in the last 30 minutes (configurable),
      account lockout will be applied to the attempted username for a specific duration (30 minutes by default).
      If the user successfully authenticated, the failed attempts counter will be reset.

    - However, there are some problems with naive account lockout approach: ([source](https://www.owasp.org/index.php/Blocking_Brute_Force_Attacks))
        1. Potential denial of service (DoS) by locking out large numbers of accounts.
        2. Based on the error responses, in the case when the error specified that an account is locked out, 
          this can be used to harvest registered usernames from this application.
        3. Account lockout is ineffective against attacks that try one password against a large list of usernames.

    - With the consideration of problems specified above, the following is implemented  to minimize the problems:
        - Do not give distinct error response when an account is locked.
        - To prevent problem C, identify attacker (based on IP addresses). Then block login attempts from attacker's IP address

 - Block login attempt from attacker's IP addresses.
    - After a defined number (10 by default) of incorrect password attempts in the last 30 minutes (configurable),
      any login attempts from the IP address will be blocked for a specific duration (30 minutes by default).
      If the user successfully authenticated, the failed attempts counter will be reset.

 - Using Captcha
    - Google reCaptcha is used.
    - Can be enabled/disabled in the configuration file (disabled by default, because need service key from google reCaptcha service)
    - Captcha is useful to prevent automated brute force attacks. In this app, captcha is inserted in the forms that
      are prone to brute force attacks, including sign up page and reset password page.
    - In login page, after 3 (configurable) consecutive failed login attempts in the 30 minutes (configurable),
      Google reCaptcha will be inserted in the login form. This is to accommodate good balance between security and usability.


## Cookie

 - Cookie is set with attributes:
    - Path: `/`
    - Secure: `true` if this app is served with HTTPS else `false`
    - SameSite: `lax`
    - HttpOnly: `true` to prevent cookie leakage in case of client-side code injection

    ```go
    func SetCookie(w http.ResponseWriter, name string, value string, maxAge int) *http.Cookie {
        cookie := &http.Cookie{
            Name:   name,
            Value:  value,
            Path:   "/",
            Secure: Options.HTTPS_ENABLED,
            SameSite: http.SameSiteLaxMode,
            HttpOnly: true,
            MaxAge: maxAge,
        }
        http.SetCookie(w, cookie)
        return cookie
    }
    ```

For More information please refer to section [Session management](#session-management).


## HTTPS

In order to server HTTPS, we need private key (`server.key`) and signed public key (PEM-encodings `.pem|.crt`)
based on the private (`.key`). For example, a script to generate a private key and self-signed public key is provided
at `gencert.sh`.

```bash
$ ./gencert.sh
$ ls server.*
server.crt server.key
```

To enable or disable HTTPS, change `HTTPS_ENABLED` in configuration file `config.json`.


## Password Policy (Known password check)

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


Default value is chosen with the following configuration
(reference: [link](https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence))

 - Passwords must be at between 12 and 4096 characters in length

 - Passwords can contain any characters (including Unicode).
   App did not need to enforce users to have mixed of letter, number, and symbols for their password.


## Mitigating user enumeration

There are 3 potential attack surface in this application that may allow user enumerations:
 - Log in page
 - Sign up page
 - Forget password pages
    
This section will display the technique used to mitigate or minimize exploitability for user enumeration

###  Mitigating user enumeration in Log in page

 - In log in page, user is expected to input `username` and `password`. If either of those two values is wrong,
   display the same error response e.g. _"username or password invalid"_.
 - This way, attacker cannot enumerate valid usernames from this page, because they need the correct password
   for each username to do that.
 - Moreover, the usage of Captcha can prevent automated brute forces

### Mitigating user enumeration in Forget Password pages
 - In the first forget password page, user is expected to input `username`.
    - Whether the input inputted `username` is valid or not, just continue and redirect them to the next page
      for forget password.
    - In this application, if the username is valid, then this application will contact SMTP server and send
      an email to the associated email address. Contacting SMTP server is time consuming, and attacker can
      utilize this behaviour to check whether a username is valid (username is valid if the response time is slow).
      To mitigate this, the operation to contact SMTP server is run asynchronously in the background, hence the
      page response time will be similar whether the username is valid or not.
 - In the second forget password page, user is expected to input `username`, `reset_token`, `new_password`
    - Regardless of the value of `new_password`, there are 2 possible errors:
      (1) `username` does not exist, and (2) `username` exists but `reset_token` incorrect.
      In either of these two errors, show the same error response e.g. _"reset password failure"_
 - Moreover, the usage of Captcha can prevent automated brute forces

### Mitigating user enumeration in Sign up page
 - In sign up page, user is expected to input `username`, `email`, and `password`.
 
 - Regardless of the value of `password`, there are 4 possible scenarios:
    1. `username` have been used. `email` have been used.
        - In this scenario, show response: _"username or email already been used"_.
          This way, attacker can not know which of the `username` or `email` has already been used.
        - Attacker cannot say that the `username` exists.
        - Attacker cannot say that the `email` exists.
    2. `username` have been used. `email` have *not* been used.
        - In this scenario, show response: _"username or email already been used"_.
          This way, attacker can not know which of the `username` or `email` has already been used.
        - Attacker cannot say that the `username` exists.
        - Attacker cannot say that the `email` exists.
    3. `username` have *not* been used. `email` have been used.
        - In this scenario, show response: _"username or email already been used"_.
          This way, attacker can not know which of the `username` or `email` has already been used.
        - Attacker cannot say that the `username` exists.
        - Attacker cannot say that the `email` exists.
    4. `username` have *not* been used. `email` have *not* been used.
        - Just continue the sign up process. User know that these `username` and `email` have not been used,
          but the damage is trivial.
 
 - Let's say that the attacker know that a user with username `admin` exists, and use `admin` as value of 
  `username` in Sign up page to enumerate email addresses. There are 2 possible scenarios:
    1. `username=admin` have been used. `email` have been used:
        - In this scenario, show response: _"username or email already been used"_.
          This way, attacker can not know which of the `username` or `email` has already been used.
        - Attacker cannot say that the `email` exists. Because the error is shown because of `username=admin`.
    2. `username=admin` have been used. `email` have *not* been used:
        - In this scenario, show response: _"username or email already been used"_.
          This way, attacker can not know which of the `username` or `email` has already been used.
        - Attacker cannot say that the `email` exists. Because the error is shown because of `username=admin`.
 
 - Moreover, the usage of Captcha can prevent automated brute forces

 - There is indeed one way to enumerate usernames: use gibberish email address that is very likely to not exist in this application (e.g. mdak8daiwkadnlrpz@aldjkljda.com).
   If we got _"username or email already been used"_, that means a user with `username` value exists in this application.
   However this methods will be very _noisy_ because the attacker will create many users, and therefore is easily detected.
