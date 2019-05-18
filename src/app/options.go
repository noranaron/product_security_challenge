package app

type AppOptions struct {
	ADDRESS                                string
	DATABASE_NAME                          string
	SESSION_SECRET_KEY                     string
	REMEMBER_ME_EXPIRY_LENGTH              int
	RESET_TOKEN_EXPIRY_LENGTH              int
	SESSION_EXPIRY_LENGTH                  int
	ACCOUNT_LOCKOUT_DURATION               int
	ACCOUNT_LOCKOUT_LOGIN_ATTEMPT_DURATION int
	ACCOUNT_LOCKOUT_LOGIN_ATTEMPT_COUNT    int
	MAX_LOGIN_ATTEMPT_DURATION             int
	MAX_LOGIN_ATTEMPT_COUNT                int
	MAX_RESET_ATTEMPT_DURATION             int
	MAX_RESET_ATTEMPT_COUNT                int
	ENABLE_RECAPTCHA                       bool
	RECAPTCHA_SECRET_KEY                   string
	RECAPTCHA_SITE_KEY                     string
	CSRF_TOKEN_LENGTH                      int
	HTTPS_ENABLED                          bool
	HTTPS_CERT_FILE                        string
	HTTPS_KEY_FILE                         string
	USE_SECURE_COOKIE                      bool
	COOKIE_KEY_SESSION					   string
	COOKIE_KEY_REMEMBER					   string
	COOKIE_KEY_CSRF_TOKEN				   string
	OTP_PRODUCT_NAME					   string
	PASSWORD_POLICY_OPTION                 PasswordPolicyOptions
	SMTP_SERVER							   SmtpServer
}
