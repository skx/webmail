//
// This is a simple WebMail project.
//

package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

//
// The secure-cookie object we use.
//
var cookieHandler *securecookie.SecureCookie

// LoadCookie loads the persistent cookies from disc, if they exist.
func LoadCookie() {

	//
	// Read the hash
	//
	hash, err := ioutil.ReadFile(".cookie.hsh")
	if err == nil {

		//
		// If there was no error read the block
		//
		block, err := ioutil.ReadFile(".cookie.blk")
		if err == nil {

			//
			// And create the cookie-helper.
			//
			cookieHandler = securecookie.New(hash, block)
			return
		}
	}

	//
	// So we either failed to find, or failed to read, the existing
	// values.  (Perhaps this is the first run.)
	//
	// Generate random values.
	//
	h := securecookie.GenerateRandomKey(64)
	b := securecookie.GenerateRandomKey(32)

	//
	// Now write them out.
	//
	// If writing fails then we'll use the values, and this means
	// when the server restarts authentication will need to to be
	// repeated by the users.
	//
	// (i.e. They'll be logged out.)
	//
	err = ioutil.WriteFile(".cookie.hsh", h, 0644)
	if err != nil {
		fmt.Printf("WARNING: failed to write .cookie.hsh for persistent secure cookie")
		cookieHandler = securecookie.New(h, b)
		return
	}
	err = ioutil.WriteFile(".cookie.blk", b, 0644)
	if err != nil {
		fmt.Printf("WARNING: failed to write .cookie.blk for persistent secure cookie")
		cookieHandler = securecookie.New(h, b)
		return
	}

	//
	// Create the cookie, if we got here we've saved the data
	// for the next restart.
	//
	cookieHandler = securecookie.New(h, b)
}

// AddContext updates our HTTP-handlers to be username-aware.
func AddContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//
		// If we have a session-cookie
		//
		if cookie, err := r.Cookie("cookie"); err == nil {

			// Make a map
			cookieValue := make(map[string]string)

			// Decode it.
			if err = cookieHandler.Decode("cookie", cookie.Value, &cookieValue); err == nil {
				//
				// Add the context to the handler, with the
				// username.
				//
				user := cookieValue["user"]
				pass := cookieValue["pass"]
				host := cookieValue["host"]
				ctx := context.WithValue(r.Context(), "user", user)
				ctx = context.WithValue(ctx, "pass", pass)
				ctx = context.WithValue(ctx, "host", host)
				//
				// And fire it up.
				//
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			} else {
				//
				// We failed to decode the cookie.
				//
				// Probably it was created with the random-key
				// of a previous run of the server.  So we
				// just fall-back to assuming we're not logged
				// in, and have no context.
				//
				next.ServeHTTP(w, r)
				return
			}
		} else {
			next.ServeHTTP(w, r)
			return
		}
	})
}

//
// Serve a static-resource
//
func serveResource(response http.ResponseWriter, request *http.Request, resource string, mime string) {
	tmpl, err := getResource(resource)
	if err != nil {
		fmt.Fprintf(response, err.Error())
		return
	}
	response.Header().Set("Content-Type", mime)
	fmt.Fprintf(response, string(tmpl))
}

//
// loginForm shows the login-form to the user,
//
func loginForm(response http.ResponseWriter, request *http.Request) {
	serveResource(response, request, "data/login.html", "text/html; charset=utf-8")
}

//
// validate tests a login is correct.
//
func validate(host string, username string, password string) bool {

	x := NewIMAP(host, username, password)
	res, err := x.Connect()
	if !res {
		return false
	}
	if err != nil {
		return false
	}
	x.Close()
	return true
}

//
// Process a login-event.
//
func loginHandler(response http.ResponseWriter, request *http.Request) {
	//
	// Get the hostname/username/password from the incoming submission
	//
	host := request.FormValue("host")
	user := request.FormValue("name")
	pass := request.FormValue("pass")

	//
	// If this succeeded then let the login succeed.
	//
	if validate(host, user, pass) {

		//
		// Store everything in the cookie
		//
		value := map[string]string{
			"host": host,
			"user": user,
			"pass": pass,
		}
		if encoded, err := cookieHandler.Encode("cookie", value); err == nil {
			cookie := &http.Cookie{
				Name:  "cookie",
				Value: encoded,
				Path:  "/",
			}
			http.SetCookie(response, cookie)
		}

		http.Redirect(response, request, "/folders/", 302)
		return
	}

	//
	// Failure to login, redirect to try again.
	//
	http.Redirect(response, request, "/login#failed", 302)
}

// indexPageHandler responds to the server-root requests.  If the user
// is logged in it will redirect them to the folder-overview, otherwise
// the login-form.
func indexPageHandler(response http.ResponseWriter, request *http.Request) {
	user := request.Context().Value("user")
	if user == nil {
		http.Redirect(response, request, "/login", 302)
	}
	http.Redirect(response, request, "/folders", 302)

}

//
// Show the folder-list
//
func folderListHandler(response http.ResponseWriter, request *http.Request) {
	user := request.Context().Value("user")
	pass := request.Context().Value("pass")
	host := request.Context().Value("host")

	if user == nil || host == nil || pass == nil {
		http.Redirect(response, request, "/login", 302)
	}

	//
	// This is the page-data we'll return
	//
	type PageData struct {
		Error   string
		Folders []string
	}

	//
	// Create an instance of the object so we can populate
	// our template.
	//
	var x PageData

	//
	// Create an IMAP object.
	//
	imap := NewIMAP(host.(string), user.(string), pass.(string))

	//
	// If we logged in then we can get the folders/messages
	//
	res, err := imap.Connect()
	if (res == true) && (err == nil) {
		x.Folders, err = imap.Folders()
		if err != nil {
			x.Error = err.Error()
		}
		imap.Close()
	} else {
		//
		// Otherwise we will show an error
		//
		x.Error = err.Error()
	}

	//
	// Load our template source.
	//
	tmpl, err := getResource("data/folders.html")
	if err != nil {
		fmt.Fprintf(response, err.Error())
		return
	}

	//
	//  Load our template, from the resource.
	//
	src := string(tmpl)
	t := template.Must(template.New("tmpl").Parse(src))

	//
	// Execute the template into our buffer.
	//
	buf := &bytes.Buffer{}
	err = t.Execute(buf, x)

	//
	// If there were errors, then show them.
	//
	if err != nil {
		fmt.Fprintf(response, err.Error())
		return
	}

	//
	// Otherwise write the result.
	//
	buf.WriteTo(response)
}

//
// Show the messages in the given folder.
//
func messageListHandler(response http.ResponseWriter, request *http.Request) {
	user := request.Context().Value("user")
	pass := request.Context().Value("pass")
	host := request.Context().Value("host")

	if user == nil || host == nil || pass == nil {
		http.Redirect(response, request, "/login", 302)
	}

	//
	// Get the name of the folder we're going to display
	//
	vars := mux.Vars(request)
	folder := vars["name"]

	//
	// This is the page-data we'll return
	//
	type PageData struct {
		Error    string
		Messages []Message
		Folder   string
		Folders  []string
	}

	//
	// Create an instance of the object so we can populate
	// our template.
	//
	var x PageData
	var err error

	//
	// Fill it up
	//
	x.Folder = folder

	//
	// Create an IMAP object.
	//
	imap := NewIMAP(host.(string), user.(string), pass.(string))

	//
	// If we logged in then we can get the folders/messages
	//
	res, err := imap.Connect()
	if (res == true) && (err == nil) {
		x.Folders, err = imap.Folders()
		if err != nil {
			x.Error = err.Error()
		}
		x.Messages, err = imap.Messages(folder)
		if err != nil {
			x.Error = err.Error()
		}
		imap.Close()
	} else {
		//
		// Otherwise we will show an error
		//
		x.Error = err.Error()
	}

	//
	// Load our template source.
	//
	tmpl, err := getResource("data/messages.html")
	if err != nil {
		fmt.Fprintf(response, err.Error())
		return
	}

	//
	//  Load our template, from the resource.
	//
	src := string(tmpl)
	t := template.Must(template.New("tmpl").Parse(src))

	//
	// Execute the template into our buffer.
	//
	buf := &bytes.Buffer{}
	err = t.Execute(buf, x)

	//
	// If there were errors, then show them.
	if err != nil {
		fmt.Fprintf(response, err.Error())
		return
	}

	//
	// Otherwise write the result.
	//
	buf.WriteTo(response)
}

// Show a single message.
func messageHandler(response http.ResponseWriter, request *http.Request) {
	user := request.Context().Value("user")
	pass := request.Context().Value("pass")
	host := request.Context().Value("host")

	if user == nil || host == nil || pass == nil {
		http.Redirect(response, request, "/login", 302)
	}

	//
	// Get the name of the folder, and the number of the message
	// we're supposed to display
	//
	vars := mux.Vars(request)
	uid := vars["number"]
	folder := vars["folder"]

	//
	// This is the page-data we'll return
	//
	type PageData struct {
		Error   string
		Body    string
		Folder  string
		Folders []string
	}

	//
	// Create an instance of the object so we can populate
	// our template.
	//
	var x PageData
	var err error

	//
	// Create an IMAP object.
	//
	imap := NewIMAP(host.(string), user.(string), pass.(string))

	//
	// If we logged in then we can get the folders/messages
	//
	res, err := imap.Connect()
	if (res == true) && (err == nil) {
		x.Folders, err = imap.Folders()
		if err != nil {
			x.Error = err.Error()
		}
		x.Body, err = imap.GetMessage(uid, folder)
		if err != nil {
			x.Error = err.Error()
		}
		imap.Close()
	} else {
		//
		// Otherwise we will show an error
		//
		x.Error = err.Error()
	}

	x.Folder = folder

	//
	// Load our template source.
	//
	tmpl, err := getResource("data/message.html")
	if err != nil {
		fmt.Fprintf(response, err.Error())
		return
	}

	//
	//  Load our template, from the resource.
	//
	src := string(tmpl)
	t := template.Must(template.New("tmpl").Parse(src))

	//
	// Execute the template into our buffer.
	//
	buf := &bytes.Buffer{}
	err = t.Execute(buf, x)

	//
	// If there were errors, then show them.
	if err != nil {
		fmt.Fprintf(response, err.Error())
		return
	}

	//
	// Otherwise write the result.
	//
	buf.WriteTo(response)
}

//
// logout handler
//
func logoutHandler(response http.ResponseWriter, request *http.Request) {
	cookie := &http.Cookie{
		Name:   "cookie",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
	http.Redirect(response, request, "/", 302)
}

func main() {

	//
	// Configure our secure cookies
	//
	LoadCookie()

	//
	// Configure our routes.
	//
	var router = mux.NewRouter()
	router.HandleFunc("/", indexPageHandler)

	router.HandleFunc("/login", loginForm).Methods("GET")
	router.HandleFunc("/login/", loginForm).Methods("GET")
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/login/", loginHandler).Methods("POST")

	router.HandleFunc("/logout", logoutHandler).Methods("GET")
	router.HandleFunc("/logout/", logoutHandler).Methods("GET")
	router.HandleFunc("/logout", logoutHandler).Methods("POST")
	router.HandleFunc("/logout/", logoutHandler).Methods("POST")

	//
	// Folder List
	//
	router.HandleFunc("/folders", folderListHandler).Methods("GET")
	router.HandleFunc("/folders/", folderListHandler).Methods("GET")

	//
	// List of messages in the given folder.
	//
	router.HandleFunc("/folder/{name}", messageListHandler).Methods("GET")
	router.HandleFunc("/folder/{name}/", messageListHandler).Methods("GET")

	//
	// Single message
	//
	router.HandleFunc("/message/{number}/{folder}", messageHandler).Methods("GET")
	router.HandleFunc("/message/{number}/{folder}/", messageHandler).Methods("GET")

	http.Handle("/", router)

	//
	// Show what we're going to bind upon.
	//
	bindHost := "127.0.0.1"
	bindPort := 8080

	bind := fmt.Sprintf("%s:%d", bindHost, bindPort)
	fmt.Printf("Listening on http://%s/\n", bind)

	//
	// Wire up logging.
	//
	loggedRouter := handlers.LoggingHandler(os.Stdout, router)

	//
	// Wire up context (i.e. cookie-based session stuff.)
	//
	contextRouter := AddContext(loggedRouter)

	//
	// We want to make sure we handle timeouts effectively
	//
	srv := &http.Server{
		Addr:         bind,
		Handler:      contextRouter,
		ReadTimeout:  25 * time.Second,
		IdleTimeout:  25 * time.Second,
		WriteTimeout: 25 * time.Second,
	}

	//
	// Launch the server.
	//
	err := srv.ListenAndServe()
	if err != nil {
		fmt.Printf("\nError starting HTTP server: %s\n", err.Error())
	}
}
