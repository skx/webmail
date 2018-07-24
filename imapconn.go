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
	"bufio"
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

// IMAPFolder contains details about a single folder
type IMAPFolder struct {
	// The name of the folder.
	Name string

	// Does this folder contain unread messages?
	Unread bool
}

// IMAPConnection handles the the connection to a back-end IMAP(S) server.
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
	Replied     bool
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

// prepend adds a single message to the start of the array.
// It is used when retrieving the list of messages.
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

// Close closes our connection to the remote IMAP(S) server.
// Calling this more than once is pointless, but permitted.
func (s *IMAPConnection) Close() {
	if s.conn != nil {
		s.conn.Logout()
	}
	s.conn = nil
}

// Folders returns the list of folders our remote IMAP(S) server contains.
// Note that due to speed concerns the list only contains the names of the
// folders - and not whether there are any unread messages in the folder.
//
// This can be resolved via "selecting" each folder, but it is slow
// when you have a lot of folders:
//  https://play.golang.org/p/jdCRMheabcA
//
func (s *IMAPConnection) Folders(unread bool) ([]IMAPFolder, error) {

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
		return nil, err
	}

	//
	// Sort the list of mailboxes in a case-insensitive fashion.
	//
	sort.Slice(res, func(i, j int) bool {
		return strings.ToLower(res[i]) < strings.ToLower(res[j])
	})

	//
	// Now build up the return value.
	//
	var tmp []IMAPFolder

	//
	// If we're not showing unread indicators for folders we're simple.
	//
	for _, name := range res {

		new := false

		//
		// But if we do we have to select the folder
		// and see if there are unread messages.
		//
		if unread {

			//
			// Select.
			//
			folder, err := s.conn.Select(name, false)
			if err == nil {
				// Look to see if there are unread messages.
				new = folder.UnseenSeqNum > 0
			}
		}
		x := IMAPFolder{Name: name, Unread: new}
		tmp = append(tmp, x)
	}

	return tmp, nil
}

// Messages returns the most recent messages in the given folder.
//
func (s *IMAPConnection) Messages(folder string, offset int) ([]Message, int, int, error) {

	var err error
	var res []Message

	// Select the given folder
	mbox, err := s.conn.Select(folder, false)
	if err != nil {
		return res, 0, 0, err
	}

	//
	// If the offset is missing then we start at "max" and
	// work backwards.
	//
	if offset < 0 {
		offset = int(mbox.Messages)
	}

	//
	// Perform a search to get the numbers which are available.
	//
	// Here we're doing the smallest search we can "messages which
	// arrived before 'now'".
	//
	criteria := imap.NewSearchCriteria()
	criteria.Before = time.Now()
	var uids []uint32
	uids, err = s.conn.Search(criteria)
	if err != nil {
		return res, 0, 0, err
	}

	//
	// So now we'll have "uids" complete with ALL the IDs which
	// are available.
	//
	seqsets := new(imap.SeqSet)
	seqsets.AddNum(uids...)

	//
	// Reverse the list
	//
	for i, j := 0, len(uids)-1; i < j; i, j = i+1, j-1 {
		uids[i], uids[j] = uids[j], uids[i]
	}

	//
	// Add the first 50 numbers which are less than the
	// given offset to the result-list
	//
	retrieve := new(imap.SeqSet)
	count := 0
	for _, num := range uids {
		if num <= uint32(offset) {
			if count < 50 {
				retrieve.AddNum(num)
				count++
			}
		}
	}

	//
	// Now we can retrieve those messages.
	//
	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)
	go func() {
		done <- s.conn.Fetch(retrieve, []imap.FetchItem{imap.FetchEnvelope, imap.FetchFlags, imap.FetchBodyStructure}, messages)
	}()

	//
	// Here we create instances of the `Message` object and append to
	// our list
	//
	for msg := range messages {
		fr := msg.Envelope.From[0].MailboxName + "@" + msg.Envelope.From[0].HostName
		to := ""
		if len(msg.Envelope.To) > 0 {
			to = msg.Envelope.To[0].MailboxName + "@" + msg.Envelope.To[0].HostName
		}

		// Is this message new?
		new := true

		// Are there attachments with this message?
		attach := false

		// Is this message been replied to?
		replied := false

		for _, x := range msg.Flags {
			if x == "\\Seen" {
				new = false
			}
			if x == "\\Answered" {
				replied = true
			}
		}

		// Attempt to guess if an attachment is present.
		if len(msg.BodyStructure.Parts) > 0 {
			for _, e := range msg.BodyStructure.Parts {
				if e.Disposition == "attachment" {
					attach = true
				}
				if e.Disposition == "inline" && e.Params["name"] != "" {
					attach = true
				}
			}
		}

		x := Message{Subject: msg.Envelope.Subject,
			Date:        msg.Envelope.Date.String(),
			From:        fr,
			Attachments: attach,
			Replied:     replied,
			ID:          fmt.Sprintf("%d", msg.SeqNum),
			To:          to,
			New:         new,
		}
		res = prepend(res, x)
	}

	if err := <-done; err != nil {
		return nil, 0, 0, err
	}

	return res, 0, int(mbox.Messages), nil
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
	// If the text-part is empty then that is because it is not
	// a MIME message at all.  Instead we'll have to use a horrid
	// hack.
	//
	// Such is life when it comes to email.
	//
	if tmp.Text == "" {

		//
		// We have the raw-message in `raw`.
		//
		// The body will be the thing from the first blank-line
		// until the EOF
		//
		inHeader := true

		scanner := bufio.NewScanner(strings.NewReader(raw))
		for scanner.Scan() {

			if inHeader {
				if scanner.Text() == "" {
					inHeader = false
				}
			} else {
				tmp.Text += scanner.Text() + "\n"
			}
		}
	}

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
	// Copy the attachments.
	//
	tmp.Attachments = mime.Attachments

	//
	// And copy any inline attachments too.
	//
	for _, i := range mime.Inlines {
		if i.FileName() != "" {
			tmp.Attachments = append(tmp.Attachments, i)
		}
	}

	//
	// Did we find any inline/attached media?
	//
	tmp.HasAttachments = len(tmp.Attachments) > 0

	//
	// Parent-details
	//
	tmp.Folder = folder
	tmp.UID = uid

	return tmp, nil
}
