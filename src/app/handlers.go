package app

import (
	"encoding/base64"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"time"
)

type PageData struct {
	User       User
	Error      string
	Info 	   string
	CSRFToken  string
	RecaptchaKey string
	ShowRecaptcha bool
}

type LoginMfaPageData struct {
	User       User
	Error      string
	Info 	   string
	CSRFToken  string
	RecaptchaKey string
	ShowRecaptcha bool
	Username   string
	Password   string
	Remember   bool
}

type SetupMfaPageData struct {
	User       User
	Error      string
	Info 	   string
	CSRFToken  string
	RecaptchaKey string
	ShowRecaptcha bool
	Secret     string
	ImageB64   string
	IsMFASetup bool
}

type SessionsPageData struct {
	User       User
	Error      string
	Info 	   string
	CSRFToken  string
	RecaptchaKey string
	ShowRecaptcha bool
	AuthTokens []*AuthToken
	Sessions   []*Session
}

var (
	loginTmpl *template.Template
	loginMfaTmpl *template.Template
	signupTmpl *template.Template
	changePasswordTmpl *template.Template
	indexTmpl *template.Template
	resetPasswordTmpl *template.Template
	resetPassword2Tmpl *template.Template
	sessionsTmpl *template.Template
	setupMfaTmpl *template.Template
)

func InitTemplates() {
	loginTmpl = template.Must(template.ParseFiles("templates/login.html"))
	loginMfaTmpl = template.Must(template.ParseFiles("templates/login-mfa.html"))
	signupTmpl = template.Must(template.ParseFiles("templates/signup.html"))
	changePasswordTmpl = template.Must(template.ParseFiles("templates/change-password.html"))
	indexTmpl = template.Must(template.ParseFiles("templates/index.html"))
	resetPasswordTmpl = template.Must(template.ParseFiles("templates/reset-password.html"))
	resetPassword2Tmpl = template.Must(template.ParseFiles("templates/reset-password2.html"))
	sessionsTmpl = template.Must(template.ParseFiles("templates/sessions.html"))
	setupMfaTmpl = template.Must(template.ParseFiles("templates/setup-mfa.html"))
}

func loginHandlerDisplayPage(w http.ResponseWriter, r *http.Request, pageData *PageData) {
	nAttemptFailed, err := CountFailedLoginAttemptsFromIP(GetIPAddressFromRequest(r), Options.MAX_LOGIN_ATTEMPT_DURATION)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	session := r.Context().Value("session").(*Session)
	if Options.ENABLE_RECAPTCHA && nAttemptFailed > 2 {
		pageData.ShowRecaptcha = true
		pageData.RecaptchaKey = Options.RECAPTCHA_SITE_KEY
		_, _ = UpdateSession(session.SessionKey, SessionData{ UserID: session.SessionData.UserID, ShowLoginCaptcha: true }, true)
	} else {
		_, _ = UpdateSession(session.SessionKey, SessionData{ UserID: session.SessionData.UserID, ShowLoginCaptcha: false}, true)
	}
	_ = loginTmpl.Execute(w, pageData)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*Session)
	pageData := PageData{
		CSRFToken: r.Context().Value("csrf-token").(string),
	}

	switch r.Method {
	case "GET":
		loginHandlerDisplayPage(w, r, &pageData)

	case "POST":
		err := r.ParseForm()
		if err != nil {
			LogSessionError(EventErrorParseForm, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		session := r.Context().Value("session").(*Session)
		if session.SessionData.ShowLoginCaptcha {
			recaptchaResponse := r.FormValue("g-recaptcha-response")
			if !ValidateRecaptcha(GetHostFromRequest(r), recaptchaResponse) {
				LogSessionWarn(EventInvalidCaptcha, session)
				pageData.Error = "Captcha verification failed"
				loginHandlerDisplayPage(w, r, &pageData)
				return
			}
		}

		username := html.EscapeString(r.FormValue("username"))
		password := r.FormValue("password")
		remember := r.FormValue("remember") == "on"

		logEvent := EventLoginAttempt
		logEvent.Values["username"] = username
		LogSessionInfo(logEvent, session)

		userAgent := GetUserAgentFromRequest(r)
		ipAddr := GetIPAddressFromRequest(r)

		loginAllowed, err := IsLoginAttemptAllowed(ipAddr, Options.MAX_LOGIN_ATTEMPT_DURATION, Options.MAX_LOGIN_ATTEMPT_COUNT)
		if err != nil {
			LogSessionError(EventErrorCheckingLoginAllowance, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if !loginAllowed {
			LogSessionInfo(EventLoginDisallowed, session)
			pageData.Error = "Too many attempts. Login temporarily disallowed."
			loginHandlerDisplayPage(w, r, &pageData)
			return
		}

		user, err := login(username, password)
		if err == ErrPasswordMismatched || err == ErrUserNotExist || err == ErrUserLocked {
			_, err := NewLoginAttempt(username, time.Now(), userAgent, ipAddr, false)
			if err != nil {
				logEvent := EventErrorCheckLogin
				logEvent.Values["username"] = username
				LogSessionError(logEvent, err, session)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			nFailed, err := CountFailedLoginAttemptsFromIPAndUsername(ipAddr, username, Options.ACCOUNT_LOCKOUT_LOGIN_ATTEMPT_DURATION)
			if err != nil {
				logEvent := EventErrorCheckLogin
				logEvent.Values["username"] = username
				LogSessionError(logEvent, err, session)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if nFailed >= Options.ACCOUNT_LOCKOUT_LOGIN_ATTEMPT_COUNT {
				err := LockUser(username, Options.ACCOUNT_LOCKOUT_DURATION)
				if err != nil && err != ErrUserNotExist {
					logEvent := EventErrorLockingUser
					logEvent.Values["username"] = username
					LogSessionError(logEvent, err, session)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}

			logEvent := EventLoginFailure
			logEvent.Values["username"] = username
			LogSessionInfo(logEvent, session)

			pageData.Error = "Invalid credential or account locked out."
			loginHandlerDisplayPage(w, r, &pageData)
			return

		} else if err != nil {
			logEvent := EventErrorCheckLogin
			logEvent.Values["username"] = username
			LogSessionError(logEvent, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		_, err = NewLoginAttempt(username, time.Now(), userAgent, ipAddr, true)
		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// because input credential is valid, stop showing login captcha
		_, err = UpdateSession(session.SessionKey, SessionData{ UserID: session.SessionData.UserID, ShowLoginCaptcha: false }, true)
		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if user.OTPSecret != "" {
			otpPasscode := html.EscapeString(r.FormValue("otp"))
			if otpPasscode == "" {
				_ = loginMfaTmpl.Execute(w, LoginMfaPageData{
					CSRFToken: r.Context().Value("csrf-token").(string),
					Username:  username,
					Password:  password,
					Remember:  remember,
				})
				return
			}
			if !ValidateTotp(otpPasscode, user.OTPSecret) {
				logEvent := EventOtpFailure
				logEvent.Values["username"] = username
				LogSessionInfo(logEvent, session)

				_ = loginMfaTmpl.Execute(w, LoginMfaPageData{
					CSRFToken: r.Context().Value("csrf-token").(string),
					Username:  username,
					Password:  password,
					Error:     "Wrong OTP Passcode",
				})
				return
			}
		}

		// login successful
		logEvent = EventLoginSuccessful
		logEvent.Values["username"] = username
		LogSessionInfo(logEvent, session)

		_, err = UpdateSession(session.SessionKey, SessionData{ UserID: user.ID, ShowLoginCaptcha: false }, true)
		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if remember {
			authToken, err := NewAuthToken(user.ID, Options.REMEMBER_ME_EXPIRY_LENGTH, userAgent, ipAddr)
			if err != nil {
				LogSessionError(EventErrorHttpHandler, err, session)
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else {
				logEvent := EventAuthTokenCreated
				logEvent.Values["username"] = username
				LogSessionInfo(logEvent, session)
				rememberValue := EncodeAuthTokenSelectorAndValidator(authToken.Selector, authToken.Validator)
				SetCookie(w, Options.COOKIE_KEY_REMEMBER, rememberValue, Options.REMEMBER_ME_EXPIRY_LENGTH)
			}
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		LogSessionWarn(EventMethodNotAllowed, session)
		_, _ = fmt.Fprint(w, "Method not allowed.")
	}
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*Session)
	pageData := PageData{
		CSRFToken: r.Context().Value("csrf-token").(string),
		ShowRecaptcha: Options.ENABLE_RECAPTCHA,
		RecaptchaKey: Options.RECAPTCHA_SITE_KEY,
	}

	switch r.Method {
	case "GET":
		_ = signupTmpl.Execute(w, pageData)
	case "POST":
		err := r.ParseForm()
		if err != nil {
			LogSessionError(EventErrorParseForm, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		email := r.FormValue("email")
		recaptchaResponse := r.FormValue("g-recaptcha-response")


		logEvent := EventSignupAttempt
		logEvent.Values["username"] = username
		logEvent.Values["email"] = email
		LogSessionInfo(logEvent, session)

		if Options.ENABLE_RECAPTCHA && !ValidateRecaptcha(GetHostFromRequest(r), recaptchaResponse) {
			LogSessionWarn(EventInvalidCaptcha, session)
			pageData.Error = "Captcha verification failed"
			_ = signupTmpl.Execute(w, pageData)
			return
		}


		if !ValidateUsername(username) {
			logEvent := EventUsernameCheckFailed
			logEvent.Values["username"] = username
			logEvent.Values["email"] = email
			LogSessionWarn(logEvent, session)

			pageData.Error = "Bad username. Please use only alphanumeric characters for username."
			_ = signupTmpl.Execute(w, pageData)
			return
		}

		if !ValidateEmailAddress(email) {
			logEvent := EventEmailCheckFailed
			logEvent.Values["username"] = username
			logEvent.Values["email"] = email
			LogSessionWarn(logEvent, session)

			pageData.Error = "Bad email address"
			_ = signupTmpl.Execute(w, pageData)
			return
		}

		passwordOK, err, rejectedReason := CheckPassword(password, Options.PASSWORD_POLICY_OPTION)
		if err != nil && err != ErrPasswordPolicy {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if !passwordOK {
			LogSessionInfo(EventPasswordCheckFailed, session)
			pageData.Error = fmt.Sprintf("Password rejected: %s", rejectedReason)
			_ = signupTmpl.Execute(w, pageData)
			return
		}

		username = html.EscapeString(username)
		email = html.EscapeString(email)

		err = NewUser(username, password, email)
		if err == ErrUsernameExists || err == ErrUserEmailExists {
			logEvent := EventUserCheckDuplicateFailed
			logEvent.Values["username"] = username
			logEvent.Values["email"] = email
			LogSessionWarn(logEvent, session)

			pageData.Error = "username or email already used"
			_ = signupTmpl.Execute(w, pageData)
			return
		} else if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// signup successful
		logEvent = EventSignupSuccessful
		logEvent.Values["username"] = username
		logEvent.Values["email"] = email
		LogSessionInfo(logEvent, session)

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		LogSessionWarn(EventMethodNotAllowed, session)
		_, _ = fmt.Fprint(w, "Method not allowed.")
	}
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*Session)
	pageData := PageData{
		CSRFToken: r.Context().Value("csrf-token").(string),
		ShowRecaptcha: Options.ENABLE_RECAPTCHA,
		RecaptchaKey: Options.RECAPTCHA_SITE_KEY,
	}

	switch r.Method {
	case "GET":
		_ = resetPasswordTmpl.Execute(w, pageData)
	case "POST":
		err := r.ParseForm()
		if err != nil {
			LogSessionError(EventErrorParseForm, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		recaptchaResponse := r.FormValue("g-recaptcha-response")
		if Options.ENABLE_RECAPTCHA && !ValidateRecaptcha(GetHostFromRequest(r), recaptchaResponse) {
			LogSessionWarn(EventInvalidCaptcha, session)
			pageData.Error = "Captcha verification failed"
			_ = resetPasswordTmpl.Execute(w, pageData)
			return
		}

		username := html.EscapeString(r.FormValue("username"))

		logEvent := EventPasswordResetAttempt
		logEvent.Values["username"] = username
		LogSessionInfo(logEvent, session)

		resetToken, err := generateResetPasswordToken(username, Options.RESET_TOKEN_EXPIRY_LENGTH)
		if err != nil && err != ErrUserNotExist {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if err == ErrUserNotExist {
			logEvent := EventPasswordResetUsernameNotExist
			logEvent.Values["username"] = username
			LogSessionWarn(logEvent, session)
		}

		if resetToken != nil && IsResetAllowed(username, Options.MAX_RESET_ATTEMPT_DURATION, Options.RESET_TOKEN_EXPIRY_LENGTH, Options.MAX_RESET_ATTEMPT_COUNT) {
			user, err := GetUserWithUsername(username)
			if err != nil && err != ErrUserNotExist {
				LogSessionError(EventErrorHttpHandler, err, session)
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else if user != nil {
				logEvent := EventPasswordResetTokenSent
				logEvent.Values["username"] = username
				LogSessionInfo(logEvent, session)

				go SendEmail(&Mail{
					SenderId: "product_security_challenge@mail.com",
					ToIds: []string{user.Email},
					Subject: "Reset Token",
					Body: fmt.Sprintf("this is your reset token: %s", resetToken.Token),
				})
			} else {
				logEvent := EventPasswordResetUsernameNotExist
				logEvent.Values["username"] = username
				LogSessionWarn(logEvent, session)
			}
		}
		http.Redirect(w, r, "/reset-password2", http.StatusSeeOther)
	}
}

func resetPassword2Handler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*Session)
	pageData := PageData{
		CSRFToken: r.Context().Value("csrf-token").(string),
		ShowRecaptcha: Options.ENABLE_RECAPTCHA,
		RecaptchaKey: Options.RECAPTCHA_SITE_KEY,
	}

	switch r.Method {
	case "GET":
		_ = resetPassword2Tmpl.Execute(w, pageData)
	case "POST":
		err := r.ParseForm()
		if err != nil {
			LogSessionError(EventErrorParseForm, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		recaptchaResponse := r.FormValue("g-recaptcha-response")
		if Options.ENABLE_RECAPTCHA && !ValidateRecaptcha(GetHostFromRequest(r), recaptchaResponse) {
			LogSessionWarn(EventInvalidCaptcha, session)
			pageData.Error = "Captcha verification failed"
			_ = resetPassword2Tmpl.Execute(w, pageData)
			return
		}

		username := html.EscapeString(r.FormValue("username"))
		token := html.EscapeString(r.FormValue("token"))
		password := r.FormValue("password")

		logEvent := EventPasswordResetTokenAttempt
		logEvent.Values["username"] = username
		LogSessionInfo(logEvent, session)

		passwordOK, err, rejectedReason := CheckPassword(password, Options.PASSWORD_POLICY_OPTION)
		if err != nil && err != ErrPasswordPolicy {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if !passwordOK {
			LogSessionInfo(EventPasswordCheckFailed, session)
			pageData.Error = fmt.Sprintf("Password rejected: %s", rejectedReason)
			_ = resetPassword2Tmpl.Execute(w, pageData)
			return
		}

		user, err := resetPassword(username, token, password)
		if err == ErrUserNotExist || err == ErrResetTokenInvalid {
			logEvent := EventPasswordResetFailure
			logEvent.Values["username"] = username
			LogSessionWarn(logEvent, session)
			pageData.Error = fmt.Sprintf("Token invalid")
			_ = resetPassword2Tmpl.Execute(w, pageData)
			return
		} else if err != nil {
			logEvent := EventPasswordResetFailure
			logEvent.Values["username"] = username
			LogSessionWarn(logEvent, session)
			pageData.Error = fmt.Sprintf("Reset password failure")
			_ = resetPassword2Tmpl.Execute(w, pageData)
			return
		}

		// reset password successful
		logEvent = EventPasswordResetSuccessful
		logEvent.Values["username"] = username
		LogSessionInfo(logEvent, session)

		err = invalidateAllSessionsUser(w, r, user.ID)
		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*User)
	_ = indexTmpl.Execute(w, PageData{
		User: *user,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*Session)
	err := destroyAuthCookie(r, w, session)
	if err != nil {
		LogSessionError(EventErrorHttpHandler, err, session)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	LogSessionInfo(EventLogoutSuccessful, session)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*Session)
	pageData := PageData{
		CSRFToken: r.Context().Value("csrf-token").(string),
	}

	switch r.Method {
	case "GET":
		_ = changePasswordTmpl.Execute(w, pageData)
	case "POST":
		err := r.ParseForm()
		if err != nil {
			LogSessionError(EventErrorParseForm, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		oldPassword := r.FormValue("old-password")
		newPassword := r.FormValue("new-password")

		user := r.Context().Value("user").(*User)

		logEvent := EventChangePasswordAttempt
		logEvent.Values["userid"] = session.SessionData.UserID
		LogSessionInfo(logEvent, session)

		err = changePassword(user.Username, oldPassword, newPassword)
		if err == ErrPasswordMismatched {
			logEvent = EventChangePasswordFailed
			logEvent.Values["userid"] = session.SessionData.UserID
			LogSessionWarn(logEvent, session)

			pageData.Error = "Previous password is wrong"
			_ = changePasswordTmpl.Execute(w, pageData)
			return
		} else if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// change password successful
		logEvent = EventChangePasswordSuccessful
		logEvent.Values["userid"] = session.SessionData.UserID
		LogSessionInfo(logEvent, session)

		err = invalidateAllSessions(w, r)
		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		LogSessionWarn(EventMethodNotAllowed, session)
		_, _ = fmt.Fprint(w, "Method not allowed.")
	}
}

func multiFactorAuthHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*Session)
	pageData := SetupMfaPageData{
		CSRFToken: r.Context().Value("csrf-token").(string),
	}

	switch r.Method {
	case "GET":
		user := r.Context().Value("user").(*User)

		key, err := NewTotpKey(&TotpOptions{
			Issuer: Options.OTP_PRODUCT_NAME,
			AccountName: user.Username,
		})

		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		imgBytes, err := key.Image()
		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		imgB64 := base64.StdEncoding.EncodeToString(imgBytes)

		pageData.Secret = key.Secret()
		pageData.ImageB64 = imgB64
		pageData.IsMFASetup = user.OTPSecret != ""
		_ = setupMfaTmpl.Execute(w, pageData)

	case "POST":
		user := r.Context().Value("user").(*User)

		key, err := NewTotpKey(&TotpOptions{
			Issuer: Options.OTP_PRODUCT_NAME,
			AccountName: user.Username,
		})

		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		imgBytes, err := key.Image()
		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		imgB64 := base64.StdEncoding.EncodeToString(imgBytes)
		pageData.Secret = key.Secret()
		pageData.ImageB64 = imgB64
		pageData.IsMFASetup = user.OTPSecret != ""

		err = r.ParseForm()
		if err != nil {
			LogSessionError(EventErrorParseForm, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		otpPasscode := html.EscapeString(r.FormValue("otp"))
		otpSecret := html.EscapeString(r.FormValue("otp-secret"))
		removeMfa := r.FormValue("remove-mfa") == "true"
		if removeMfa {
			logEvent := EventRemoveMfaAttempt
			logEvent.Values["userid"] = session.SessionData.UserID
			LogSessionInfo(logEvent, session)

			err := setOTPSecret(user.ID, otpSecret)
			if err != nil {
				LogSessionError(EventErrorHttpHandler, err, session)
				w.WriteHeader(http.StatusInternalServerError)
				return
			} else {
				logEvent := EventRemoveMfaSuccessful
				logEvent.Values["userid"] = session.SessionData.UserID
				LogSessionInfo(logEvent, session)

				pageData.Info = "Multi factor authentication is removed"
				pageData.IsMFASetup = false
				_ = setupMfaTmpl.Execute(w, pageData)
				return
			}

		} else {
			logEvent := EventSetupMfaAttempt
			logEvent.Values["userid"] = session.SessionData.UserID
			LogSessionInfo(logEvent, session)

			if ValidateTotp(otpPasscode, otpSecret) {
				err := setOTPSecret(user.ID, otpSecret)
				if err != nil {
					LogSessionError(EventErrorHttpHandler, err, session)
					w.WriteHeader(http.StatusInternalServerError)
					return
				} else {
					logEvent := EventSetupMfaSuccessful
					logEvent.Values["userid"] = session.SessionData.UserID
					LogSessionInfo(logEvent, session)

					pageData.Info = "Multi factor authentication is setup successfully"
					pageData.IsMFASetup = true
					_ = setupMfaTmpl.Execute(w, pageData)
					return
				}
			} else {
				logEvent := EventSetupMfaFailed
				logEvent.Values["userid"] = session.SessionData.UserID
				LogSessionWarn(logEvent, session)

				pageData.Error = "Wrong passcode"
				_ = setupMfaTmpl.Execute(w, pageData)
				return
			}
		}

	default:
		LogSessionWarn(EventMethodNotAllowed, session)
		_, _ = fmt.Fprint(w, "Method not allowed.")
	}
}

func sessionsHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*Session)
	pageData := SessionsPageData{
		CSRFToken: r.Context().Value("csrf-token").(string),
	}
	switch r.Method {
	case "GET":
		user := r.Context().Value("user").(*User)
		authTokens, err := GetAuthTokensForUser(user.ID)
		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sessions, err := GetSessionsForUser(user.ID)
		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		pageData.AuthTokens = authTokens
		pageData.Sessions = sessions
		_ = sessionsTmpl.Execute(w, pageData)
	case "POST":
		err := invalidateAllSessions(w, r)
		if err != nil {
			LogSessionError(EventErrorHttpHandler, err, session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		LogSessionWarn(EventMethodNotAllowed, session)
		_, _ = fmt.Fprint(w, "Method not allowed.")
	}
}

func invalidateAllSessions(w http.ResponseWriter, r *http.Request) error {
	session := r.Context().Value("session").(*Session)
	return invalidateAllSessionsUser(w, r, session.SessionData.UserID)
}

func invalidateAllSessionsUser(w http.ResponseWriter, r *http.Request, userID int) error {
	session := r.Context().Value("session").(*Session)
	err := InvalidateAuthTokenForUser(userID)
	if err != nil {
		return err
	}
	err = InvalidateSessionsForUser(userID)
	if err != nil {
		return err
	}
	err = destroyAuthCookie(r, w, session)
	if err != nil {
		return err
	}

	logEvent := EventSessionsInvalidationSuccessful
	logEvent.Values["userid"] = userID
	LogSessionInfo(logEvent, session)

	return nil
}