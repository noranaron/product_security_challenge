package app

import (
	_ "github.com/mattn/go-sqlite3"
	"net/http"
)

var Options *AppOptions

func Start(options *AppOptions) {
	InitLogger()
	LogInfo(EventAppStartup)
	Options = options
	err := ServeHttp(Options.ADDRESS, Options.HTTPS_ENABLED)
	if err != nil {
		panic(err)
	}
}

func ServeHttp(addr string, useHttps bool) error {
	InitDB(Options.DATABASE_NAME)
	InitTemplates()

	fs := http.FileServer(http.Dir("static"))

	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { })

	http.HandleFunc("/signup", chainMiddlewares(signupHandler, []Middleware{
		sessionMiddleware,
		nonAuthMiddleware,
		csrfMiddleware}))

	http.HandleFunc("/login", chainMiddlewares(loginHandler, []Middleware{
		sessionMiddleware,
		nonAuthMiddleware,
		csrfMiddleware}))

	http.HandleFunc("/logout", chainMiddlewares(logoutHandler, []Middleware{
		sessionMiddleware,
		authenticatedMiddleware,
		csrfMiddleware}))


	http.HandleFunc("/reset-password", chainMiddlewares(resetPasswordHandler, []Middleware{
		sessionMiddleware,
		nonAuthMiddleware,
		csrfMiddleware}))

	http.HandleFunc("/reset-password2", chainMiddlewares(resetPassword2Handler, []Middleware{
		sessionMiddleware,
		nonAuthMiddleware,
		csrfMiddleware}))

	http.HandleFunc("/change-password", chainMiddlewares(changePasswordHandler, []Middleware{
		sessionMiddleware,
		authenticatedMiddleware,
		csrfMiddleware}))

	http.HandleFunc("/setup-mfa", chainMiddlewares(multiFactorAuthHandler, []Middleware{
		sessionMiddleware,
		authenticatedMiddleware,
		csrfMiddleware}))

	http.HandleFunc("/sessions", chainMiddlewares(sessionsHandler, []Middleware{
		sessionMiddleware,
		authenticatedMiddleware,
		csrfMiddleware}))

	http.HandleFunc("/", chainMiddlewares(rootHandler, []Middleware{
		sessionMiddleware,
		authenticatedMiddleware,
		csrfMiddleware}))


	logEvent := EventHttpServerStartup
	logEvent.Values["https"] = useHttps
	logEvent.Values["address"] = addr
	LogInfo(logEvent)

	if useHttps {
		return http.ListenAndServeTLS(addr, Options.HTTPS_CERT_FILE, Options.HTTPS_KEY_FILE, nil)
	} else {
		return http.ListenAndServe(addr, nil)
	}
}
