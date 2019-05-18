package app

import (
	"github.com/sirupsen/logrus"
	"io"
	"os"
)

var Logger *logrus.Logger

func InitLogger() {
	Logger = logrus.New()
	Logger.SetOutput(os.Stdout)

	file, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		Logger.Errorf("Failed to log to file, using default stdout")
	} else {
		Logger.SetOutput(io.MultiWriter(os.Stdout, file))
	}
}

func GetLogEntry(event LogEvent) *logrus.Entry {
	logEntry := Logger.WithFields(logrus.Fields{
		"event": event.Name,
	})
	for k := range event.Values {
		logEntry = logEntry.WithField(k, event.Values[k])
	}
	return logEntry
}

func LogInfo(event LogEvent) {
	GetLogEntry(event).Info(event.Description)
}

func LogWarn(event LogEvent) {
	GetLogEntry(event).Warn(event.Description)
}

func LogError(event LogEvent, err error) {
	event.Values["err"] = err
	GetLogEntry(event).Errorf(event.Description)
}

func LogSessionInfo(event LogEvent, session *Session) {
	event.Values["session"] = session.SessionKey
	LogInfo(event)
}

func LogSessionWarn(event LogEvent, session *Session) {
	event.Values["session"] = session.SessionKey
	LogWarn(event)
}

func LogSessionError(event LogEvent, err error, session *Session) {
	event.Values["session"] = session.SessionKey
	LogError(event, err)
}

type LogEvent struct {
	Name        string
	Description string
	Values      map[string] interface{}
}

func NewLogEvent(logEvent LogEvent) LogEvent {
	if logEvent.Values == nil {
		logEvent.Values = make(map[string] interface{})
	}
	return logEvent
}

var (
	EventAppStartup = NewLogEvent(LogEvent{
		Name:        "APP_STARTUP",
		Description: "starting up application",
	})
	EventHttpServerStartup = NewLogEvent(LogEvent{
		Name:        "HTTP_SERVER_STARTUP",
		Description: "starting up http server",
	})
	EventLoginAttempt = NewLogEvent(LogEvent{
		Name:        "LOGIN_ATTEMPT",
		Description: "login attempted",
	})
	EventSignupAttempt = NewLogEvent(LogEvent{
		Name:        "SIGNUP_ATTEMPT",
		Description: "signup attempted",
	})
	EventPasswordResetAttempt = NewLogEvent(LogEvent{
		Name:        "PASSWORD_RESET_ATTEMPT",
		Description: "password reset attempted",
	})
	EventPasswordResetTokenAttempt = NewLogEvent(LogEvent{
		Name:        "PASSWORD_RESET_TOKEN_ATTEMPT",
		Description: "password reset with token attempted",
	})
	EventChangePasswordAttempt = NewLogEvent(LogEvent{
		Name:        "CHANGE_PASSWORD_ATTEMPT",
		Description: "change password attempted",
	})
	EventPasswordResetUsernameNotExist = NewLogEvent(LogEvent{
		Name:        "PASSWORD_RESET_USERNAME_NOT_EXIST",
		Description: "password reset with username not exist",
	})
	EventPasswordResetTokenSent = NewLogEvent(LogEvent{
		Name:        "PASSWORD_RESET_TOKEN_SENT",
		Description: "password reset token is sent via email",
	})
	EventLoginFailure = NewLogEvent(LogEvent {
		Name:        "LOGIN_FAILURE",
		Description: "login failed",
	})
	EventLoginSuccessful = NewLogEvent(LogEvent {
		Name:        "LOGIN_SUCCESSFUL",
		Description: "login successful",
	})
	EventSignupSuccessful = NewLogEvent(LogEvent {
		Name:        "SIGNUP_SUCCESSFUL",
		Description: "signup successful",
	})
	EventPasswordResetFailure = NewLogEvent(LogEvent{
		Name:        "PASSWORD_RESET_FAILURE",
		Description: "password reset failure",
	})
	EventPasswordResetSuccessful = NewLogEvent(LogEvent{
		Name:        "PASSWORD_RESET_SUCCESSFUL",
		Description: "password reset successful",
	})
	EventLogoutSuccessful = NewLogEvent(LogEvent {
		Name:        "LOGOUT_SUCCESSFUL",
		Description: "logout successful",
	})
	EventChangePasswordSuccessful = NewLogEvent(LogEvent{
		Name:        "CHANGE_PASSWORD_SUCCESSFUL",
		Description: "change password successful",
	})
	EventChangePasswordFailed = NewLogEvent(LogEvent{
		Name:        "CHANGE_PASSWORD_FAILED",
		Description: "change password failed",
	})
	EventSetupMfaAttempt = NewLogEvent(LogEvent{
		Name:        "SETUP_MFA_ATTEMPT",
		Description: "multi factor authentication setup attempted",
	})
	EventSetupMfaSuccessful = NewLogEvent(LogEvent{
		Name:        "SETUP_MFA_SUCCESSFUL",
		Description: "multi factor authentication setup successful",
	})
	EventSetupMfaFailed = NewLogEvent(LogEvent{
		Name:        "SETUP_MFA_FAILED",
		Description: "multi factor authentication setup failed",
	})
	EventRemoveMfaAttempt = NewLogEvent(LogEvent{
		Name:        "REMOVE_MFA_ATTEMPT",
		Description: "multi factor authentication remove attempted",
	})
	EventRemoveMfaSuccessful = NewLogEvent(LogEvent{
		Name:        "REMOVE_MFA_SUCCESSFUL",
		Description: "multi factor authentication remove successful",
	})
	EventSessionsInvalidationSuccessful = NewLogEvent(LogEvent{
		Name:        "SESSIONS_INVALIDATION_SUCCESSFUL",
		Description: "all sessions invalidation successful",
	})
	EventUsernameCheckFailed = NewLogEvent(LogEvent {
		Name:        "USERNAME_CHECK_FAILED",
		Description: "username check failed",
	})
	EventEmailCheckFailed = NewLogEvent(LogEvent {
		Name:        "EMAIL_CHECK_FAILED",
		Description: "email address check failed",
	})
	EventPasswordCheckFailed = NewLogEvent(LogEvent {
		Name:        "PASSWORD_CHECK_FAILED",
		Description: "password check failed",
	})

	EventUserCheckDuplicateFailed = NewLogEvent(LogEvent {
		Name:        "USERNAME_CHECK_DUPLICATE_FAILED",
		Description: "attempted to sign up with already used username or email",
	})
	EventErrorParseForm = NewLogEvent(LogEvent{
		Name:        "ERROR_PARSE_FORM",
		Description: "error parsing form",
	})
	EventInvalidCaptcha = NewLogEvent(LogEvent{
		Name:        "ERROR_CAPTCHA",
		Description: "error captcha validation",
	})
	EventErrorCheckingLoginAllowance = NewLogEvent(LogEvent{
		Name:        "ERROR_LOGIN_ALLOWANCE",
		Description: "error checking login allowance",
	})
	EventLoginDisallowed = NewLogEvent(LogEvent {
		Name:        "LOGIN_DISALLOWED",
		Description: "login disallowed",
	})
	EventErrorCheckLogin = NewLogEvent(LogEvent {
		Name:        "ERROR_CHECK_LOGIN",
		Description: "error checking login",
	})
	EventErrorLockingUser = NewLogEvent(LogEvent {
		Name:        "ERROR_LOCKING_USER",
		Description: "error locking login",
	})
	EventErrorHttpHandler = NewLogEvent(LogEvent {
		Name:        "ERROR_HTTP_HANDLER",
		Description: "error in http handler",
	})
	EventErrorHttpMiddleware = NewLogEvent(LogEvent {
		Name:        "ERROR_HTTP_MIDDLEWARE",
		Description: "error in http middleware",
	})
	EventOtpFailure = NewLogEvent(LogEvent{
		Name:        "OTP_FAILURE",
		Description: "otp failure",
	})
	EventAuthTokenCreated = NewLogEvent(LogEvent{
		Name:        "AUTH_TOKEN_CREATED",
		Description: "long term auth token created",
	})
	EventMethodNotAllowed = NewLogEvent(LogEvent{
		Name:        "METHOD_NOT_ALLOWED",
		Description: "http method not allowed",
	})
	EventUnauthorizedAccess = NewLogEvent(LogEvent{
		Name:        "UNAUTHORIZED_ACCESS",
		Description: "attempted to access unauthorized page",
	})
	EventCsrfFailed = NewLogEvent(LogEvent{
		Name:        "CSRF_CHECK_FAILED",
		Description: "csrf check failed",
	})
	EventSessionKeyNotFound = NewLogEvent(LogEvent{
		Name:        "SESSION_KEY_NOT_FOUND",
		Description: "session key not found / potential cookie modification",
	})
)
