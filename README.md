# Webmail

This repository contains a simple webmail implementation for golang:

* You can connect to a remote IMAP server and perform basic operations
  * Retrieve the list of remote folders.
  * Open a folder and see the most recent 50 messages in it.
     * Unread messages will be displayed in bold.
  * For any message in the folder list you can retrieve it
     * Which will also mark the message as being read.

This application has been tested against three remote IMAP hosts:

* GMail
* GMX
* My mailserver, running dovecot.

All perform well, though in all honesty my own server performs the worst
because I have ~1000 mailboxes.  So just getting the folder list takes
some time I'd rather avoid.



## Installation

To install this run:

     ~ $ go get -u github.com/skx/webmail
     ~ $ go install github.com/skx/webmail

## Usage

Build the application and start it:

     ~$ webmail

Now point your favourite browser at http://localhost:8080/ and fill in the appropriate details.  For example if you wished to test against Google-mail you'd enter the following values:


| Value    | Setting                 |
| -------- | ----------------------- |
| Host     | imaps://imap.gmail.com/ |
| Username | example@gmail.com       |
| Password | s3cr1t                  |


**NOTE**: If you want to us IMAP (143) use `imap://` as a prefix, if you want IMAPS (993) use `imaps://`.  To avoid issues I'm __NOT__ validating the SSL certificate.  This is intentional.  Sorry.



## Limitations

This is a naive webmail client, which means that every time you carry
out an option the flow goes:

* Your browser sends a request to this server.
* The server opens a __new__ connection to the remote IMAP server:
  * The appropriate command(s) are executed.
  * The IMAP server connection is closed.
* The server sends the response to your client.

This means that things are slower than they would be if there were a dedicated
proxy maintaining a persistent connection to the IMAP server.


## Missing Features

You cannot:

* Delete a message.
* Reply to a message.
* Forward a message.
* Page backwards/forwards in message-lists.
* Compose a fresh message.

Some of those would be trivial to add.


## Hacking

The generated HTML views are stored inside the compiled binary to ease
deployment.  If you wish to tweak the look & feel by editing them then
you're more then welcome.

The raw HTML-templates are located beneath `data/`, and you can edit them
then rebuild the compiled versions via the `implant` tool.

If you don't already have `implant` installed fetch it like so:

     go get -u  github.com/skx/implant/
     go install github.com/skx/implant/

Now regenerate the compiled version(s) of the templates and rebuild the
binary to make your changes:

    implant -input data/ -output static.go
    go build .


Steve
--
