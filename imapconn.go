// imapconn.go holds helper-functions for talking to the remote IMAP(S)
// server.
//
// In short the server.go function handle HTTP, and this file handles:
//
// * Getting lists of folders.
// * Getting lists of messages.
// * Getting a single message
//

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	imap "github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/jhillyerd/go.enmime"
	"github.com/microcosm-cc/bluemonday"
)

// IAMPConnection handles the the connection to a back-end IMAP(S) server.
type IMAPConnection struct {
	uri  string
	user string
	pass string
	conn *client.Client
}

// Message is a very minimal structure for a message in a folder.
// It is used in `GetMessages` and nowhere else.
type Message struct {
	New         bool
	ID          string
	To          string
	From        string
	Date        string
	Subject     string
	Attachments bool
}

// SingleMessage is used to display a single message-view.
type SingleMessage struct {
	Folder         string
	UID            string
	Headers        map[string]string
	HTML           string
	Text           string
	RAW            string
	HasHTML        bool
	Attachments    []enmime.MIMEPart
	HasAttachments bool
}

func prepend(arr []Message, item Message) []Message {
	return append([]Message{item}, arr...)
}

// New returns a new IMAPConnection object.
func NewIMAP(uri string, user string, pass string) *IMAPConnection {
	obj := &IMAPConnection{uri: uri, user: user, pass: pass}
	return (obj)
}

// Connect returns an IMAP connection, or an error
func (s *IMAPConnection) Connect() (bool, error) {
	//
	// Holder for any error.
	//
	var err error

	//
	// Default port
	//
	port := 993

	//
	// Parse the given URI.
	//
	u, err := url.Parse(s.uri)
	if err != nil {
		return false, err
	}

	//
	// Work out port-number
	//
	if u.Scheme == "imap" {
		port = 143
	}
	if u.Scheme == "imaps" {
		port = 993
	}
	if u.Port() != "" {
		port, _ = strconv.Atoi(u.Port())
	}

	//
	// The target we'll connect to.
	//
	address := fmt.Sprintf("%s:%d", u.Host, port)

	//
	// Setup a dialer so we can have a suitable timeout
	//
	var dial = &net.Dialer{
		Timeout: 5 * time.Second,
	}

	//
	// Setup the default TLS config.
	//
	tlsSetup := &tls.Config{
		InsecureSkipVerify: true,
	}

	//
	// Connect - using TLS or not
	//
	var con *client.Client
	if port == 993 {
		con, err = client.DialWithDialerTLS(dial, address, tlsSetup)
	} else {
		con, err = client.DialWithDialer(dial, address)
	}

	//
	// Did that connection work?
	//
	if err != nil {
		return false, err

	}

	//
	// Attempt to login
	//
	err = con.Login(s.user, s.pass)
	if err != nil {

		//
		// If we failed to login we should close the
		// connection immediately.
		//
		con.Close()
		return false, err
	}

	//
	// OK we've connected and logged in
	//
	// Record the connection, so that we can later close it, and
	// return the success.
	//
	s.conn = con
	return true, nil

}

// Close closes our connection to the remote IMAP(S) server
func (s *IMAPConnection) Close() {
	if s.conn != nil {
		s.conn.Logout()
	}
	s.conn = nil
}

// Folders returns the list of folders our remote IMAP(S) server contains
func (s *IMAPConnection) Folders() ([]string, error) {

	var res []string

	mailboxes := make(chan *imap.MailboxInfo, 15)
	done := make(chan error, 1)
	go func() {
		done <- s.conn.List("", "*", mailboxes)
	}()

	// For each result save the name
	for m := range mailboxes {
		res = append(res, m.Name)
	}

	// Wait for completion
	if err := <-done; err != nil {
		return res, err
	}

	//
	// Sort the list of mailboxes.
	//

	sort.Slice(res, func(i, j int) bool {
		return strings.ToLower(res[i]) < strings.ToLower(res[j])
	})

	return res, nil
}

// Messages returns the most recent messages in the given folder.
func (s *IMAPConnection) Messages(folder string) ([]Message, error) {

	var err error
	var res []Message

	// Select the given folder
	mbox, err := s.conn.Select(folder, false)
	if err != nil {
		return res, err
	}

	// Get the last 50 messages
	from := uint32(1)
	to := mbox.Messages
	if mbox.Messages > 50 {
		from = mbox.Messages - 50
	}
	seqset := new(imap.SeqSet)
	seqset.AddRange(from, to)

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)
	go func() {
		done <- s.conn.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope, imap.FetchFlags, imap.FetchBodyStructure}, messages)
	}()

	//
	// Here we create instances of the `Message` object and append to
	// our list
	//
	for msg := range messages {
		fr := msg.Envelope.From[0].MailboxName + "@" + msg.Envelope.From[0].HostName
		to := msg.Envelope.To[0].MailboxName + "@" + msg.Envelope.To[0].HostName

		// Is this message new?
		new := true

		// Are there attachments with this message?
		attach := false

		for _, x := range msg.Flags {
			if x == "\\Seen" {
				new = false
			}
		}

		// Attempt to guess if an attachment is present.
		if len(msg.BodyStructure.Parts) > 0 {
			for _, e := range msg.BodyStructure.Parts {
				if e.Disposition == "attachment" {
					attach = true
				}
			}
		}

		x := Message{Subject: msg.Envelope.Subject,
			Date:        msg.Envelope.Date.String(),
			From:        fr,
			Attachments: attach,
			ID:          fmt.Sprintf("%d", msg.SeqNum),
			To:          to,
			New:         new,
		}
		res = prepend(res, x)
	}

	if err := <-done; err != nil {
		return nil, err
	}

	return res, nil
}

// GetMessage returns the text of a single message.
func (s *IMAPConnection) GetMessage(uid string, folder string) (SingleMessage, error) {
	var err error
	tmp := SingleMessage{}

	// Select the folder
	_, err = s.conn.Select(folder, false)
	if err != nil {
		return tmp, err
	}

	//
	// Prepare to retrieve the message.
	//
	seqSet := new(imap.SeqSet)
	x, _ := strconv.Atoi(uid)
	seqSet.AddNum(uint32(x))

	//
	// Get the whole message body
	//
	section := &imap.BodySectionName{}
	items := []imap.FetchItem{section.FetchItem()}

	messages := make(chan *imap.Message, 1)
	go func() {
		if err := s.conn.Fetch(seqSet, items, messages); err != nil {
			// ?
		}
	}()

	msg := <-messages
	if msg == nil {
		return tmp, errors.New("Server didn't return the message.")
	}

	//
	// Get the body of the message as a string, and pass it to the
	// golang net/mail object.
	//
	raw := fmt.Sprintf("%s", msg.GetBody(section))
	r := strings.NewReader(raw)
	m, err := mail.ReadMessage(r)
	if err != nil {
		return tmp, err
	}

	//
	// Now pass the net/mail object to the enmime-library.
	//
	var mime *enmime.MIMEBody
	mime, err = enmime.ParseMIMEBody(m)
	if err != nil {
		return tmp, fmt.Errorf("During enmime.ParseMIMEBody: %v", err)
	}

	//
	// Ensure that our return-value has a populated map.
	//
	tmp.Headers = make(map[string]string)

	//
	// Copy "some" headers into that map.
	//
	for k := range m.Header {
		switch strings.ToLower(k) {
		case "date", "subject":
			tmp.Headers[k] = mime.GetHeader(k)
		}
	}

	//
	// Now handle the address-lists in the to/cc/from
	// headers.
	//
	for _, hkey := range enmime.AddressHeaders {
		addrlist, err := mime.AddressList(hkey)
		if err != nil {
			if err == mail.ErrHeaderNotPresent {
				continue
			}
			panic(err)
		}

		for _, addr := range addrlist {
			cur := tmp.Headers[hkey]
			if cur != "" {
				cur += ", "
			}
			cur += "\"" + addr.Name + "\" &lt;" + addr.Address + "&gt;"

			tmp.Headers[hkey] = cur
		}
	}

	//
	// Save three copies of the body (!) in the object.
	//
	tmp.Text = mime.Text
	tmp.RAW = raw
	tmp.HTML = string(bluemonday.UGCPolicy().SanitizeBytes([]byte(mime.HTML)))
	//
	// If we had a non-empty HTML-section then mark that as being
	// the case.
	//
	// (Because the message-display template won't show the HTML-tab
	// if such a part isn't available.)
	//
	if tmp.HTML != "" {
		tmp.HasHTML = true
	}

	//
	// Finally copy the attachments.
	//
	tmp.Attachments = mime.Attachments
	tmp.HasAttachments = len(mime.Attachments) > 0

	//
	// Parent-details
	//
	tmp.Folder = folder
	tmp.UID = uid

	return tmp, nil
}
