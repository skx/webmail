//
// This is a simple WebMail project.
//

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	imap "github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
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

// RemoteIP handles retrieving the remote IP which made a particular
// HTTP-request, handling reverse-proxies as well as direct connections.
func RemoteIP(request *http.Request) string {

	//
	// Get the X-Forwarded-For header, if present.
	//
	xForwardedFor := request.Header.Get("X-Forwarded-For")

	//
	// No forwarded IP?  Then use the remote address directly.
	//
	if xForwardedFor == "" {
		ip, _, _ := net.SplitHostPort(request.RemoteAddr)
		return ip
	}

	entries := strings.Split(xForwardedFor, ",")
	address := strings.TrimSpace(entries[0])
	return (address)
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

func loginForm(response http.ResponseWriter, request *http.Request) {
	serveResource(response, request, "data/login.html", "text/html; charset=utf-8")
}

// validate tests a login
func validate(host string, username string, password string) bool {
	var err error

	//
	// Default to connecting to an IPv4-address
	//
	address := fmt.Sprintf("%s:%d", host, 993)

	//
	// Setup a dialer so we can have a suitable timeout
	//
	var dial = &net.Dialer{
		Timeout: 5 * time.Second,
	}

	//
	// Setup the default TLS config.
	tlsSetup := &tls.Config{
		InsecureSkipVerify: true,
	}

	//
	// Connect.
	//
	con, err := client.DialWithDialerTLS(dial, address, tlsSetup)
	if err != nil {
		return false

	}
	defer con.Close()

	err = con.Login(username, password)
	if err != nil {
		fmt.Printf("ERROR: (%s,%s), %s\n", username, password, err.Error())
		con.Logout()
		return false
	}

	// Logout so that we don't keep the handle open.
	err = con.Logout()
	return true
}

// Folders returns all the folders a remote host contains
func Folders(host string, username string, password string) ([]string, error) {
	var err error
	var res []string

	//
	// Default to connecting to an IPv4-address
	//
	address := fmt.Sprintf("%s:%d", host, 993)

	//
	// Setup a dialer so we can have a suitable timeout
	//
	var dial = &net.Dialer{
		Timeout: 5 * time.Second,
	}

	//
	// Setup the default TLS config.
	tlsSetup := &tls.Config{
		InsecureSkipVerify: true,
	}

	//
	// Connect.
	//
	con, err := client.DialWithDialerTLS(dial, address, tlsSetup)
	if err != nil {
		return res, err

	}
	defer con.Close()

	err = con.Login(username, password)
	if err != nil {
		return res, err
	}

	// List mailboxes
	mailboxes := make(chan *imap.MailboxInfo, 15)
	done := make(chan error, 1)
	go func() {
		done <- con.List("", "*", mailboxes)
	}()

	// For each result save the name
	for m := range mailboxes {
		res = append(res, m.Name)
	}

	// Wait for completion
	if err := <-done; err != nil {
		log.Fatal(err)
	}

	con.Logout()
	sort.Strings(res)
	return res, nil
}

//
// This is a very minimal structure for a message in a folder
//
type Message struct {
	New     bool
	ID      string
	To      string
	From    string
	Date    string
	Subject string
}

// Messages returns the most recent messages in the given folder.
func Messages(folder string, host string, username string, password string) ([]Message, error) {
	var err error
	var res []Message
	//
	// Default to connecting to an IPv4-address
	//
	address := fmt.Sprintf("%s:%d", host, 993)

	//
	// Setup a dialer so we can have a suitable timeout
	//
	var dial = &net.Dialer{
		Timeout: 5 * time.Second,
	}

	//
	// Setup the default TLS config.
	tlsSetup := &tls.Config{
		InsecureSkipVerify: true,
	}

	//
	// Connect.
	//
	con, err := client.DialWithDialerTLS(dial, address, tlsSetup)
	if err != nil {
		return res, err

	}
	defer con.Close()

	err = con.Login(username, password)
	if err != nil {
		return res, err
	}

	// Select INBOX
	mbox, err := con.Select(folder, false)
	if err != nil {
		return res, err
	}

	// Get the last 50 messages
	from := uint32(1)
	to := mbox.Messages
	if mbox.Messages > 50 {
		// We're using unsigned integers here, only substract if the result is > 0
		from = mbox.Messages - 50
	}
	seqset := new(imap.SeqSet)
	seqset.AddRange(from, to)

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)
	go func() {
		done <- con.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope, imap.FetchFlags}, messages)
	}()

	for msg := range messages {

		fr := msg.Envelope.From[0].MailboxName + "@" + msg.Envelope.From[0].HostName
		to := msg.Envelope.To[0].MailboxName + "@" + msg.Envelope.To[0].HostName

		var new bool
		new = true
		for _, x := range msg.Flags {
			if x == "\\Seen" {
				new = false
			}
		}
		x := Message{Subject: msg.Envelope.Subject,
			Date: msg.Envelope.Date.String(),
			From: fr,
			ID:   fmt.Sprintf("%d", msg.SeqNum),
			To:   to,
			New:  new,
		}
		res = append(res, x)
	}

	if err := <-done; err != nil {
		log.Fatal(err)
	}

	con.Logout()
	return res, nil
}

// GetMessage returns the contents of a single message.
func GetMessage(uid string, folder string, host string, username string, password string) (string, error) {
	var err error

	//
	// Default to connecting to an IPv4-address
	//
	address := fmt.Sprintf("%s:%d", host, 993)

	//
	// Setup a dialer so we can have a suitable timeout
	//
	var dial = &net.Dialer{
		Timeout: 5 * time.Second,
	}

	//
	// Setup the default TLS config.
	tlsSetup := &tls.Config{
		InsecureSkipVerify: true,
	}

	//
	// Connect.
	//
	con, err := client.DialWithDialerTLS(dial, address, tlsSetup)
	if err != nil {
		return "", err

	}
	defer con.Close()

	err = con.Login(username, password)
	if err != nil {
		return "", err
	}

	// Select the folder
	_, err = con.Select(folder, false)
	if err != nil {
		return "", err
	}

	//
	// Get the stuff
	//
	seqSet := new(imap.SeqSet)
	x, _ := strconv.Atoi(uid)
	seqSet.AddNum(uint32(x))

	// Get the whole message body
	section := &imap.BodySectionName{}
	items := []imap.FetchItem{section.FetchItem()}

	messages := make(chan *imap.Message, 1)
	go func() {
		if err := con.Fetch(seqSet, items, messages); err != nil {
			log.Fatal(err)
		}
	}()

	msg := <-messages
	if msg == nil {
		log.Fatal("Server didn't returned message")
		return "", errors.New("Server didn't returned message")
	}

	// Logout
	con.Logout()

	//
	// Hack - we just return the complete message
	//
	txt := fmt.Sprintf("%s\n", msg.GetBody(section))
	return txt, nil
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

	type PageData struct {
		Folders []string
	}

	var x PageData
	x.Folders, _ = Folders(host.(string), user.(string), pass.(string))

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

	vars := mux.Vars(request)
	folder := vars["name"]

	type PageData struct {
		Messages []Message
		Folder   string
		Folders  []string
	}

	var x PageData
	var err error
	x.Folders, _ = Folders(host.(string), user.(string), pass.(string))
	x.Folder = folder
	x.Messages, err = Messages(folder, host.(string), user.(string), pass.(string))
	if err != nil {
		log.Printf("ERROR: %s\n", err.Error())
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

	vars := mux.Vars(request)
	number := vars["number"]
	folder := vars["folder"]

	//
	// How we'll populate the template
	//
	type PageData struct {
		Body    string
		Folder  string
		Folders []string
	}

	var x PageData
	var err error
	x.Folders, _ = Folders(host.(string), user.(string), pass.(string))
	x.Folder = folder
	x.Body, err = GetMessage(number, folder, host.(string), user.(string), pass.(string))
	if err != nil {
		log.Printf("ERROR: %s\n", err.Error())
	}

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
