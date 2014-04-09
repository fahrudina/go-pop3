package pop3

import (
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
)

type Client struct {
	Text *Connection
	conn net.Conn
}

// MessageInfo represents the message attributes returned by a LIST command.
type MessageInfo struct {
	Seq  uint32 // Message sequence number
	Size uint32 // Message size in bytes
}

var lineSeparator = "\n"

func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewClient(conn)
}

func DialTLS(addr string) (*Client, error) {
	conn, err := tls.Dial("tcp", addr, nil)
	if err != nil {
		return nil, err
	}
	return NewClient(conn)
}

func NewClient(conn net.Conn) (*Client, error) {
	text := NewConnection(conn)
	client := &Client{Text: text, conn: conn}
	// read greeting
	_, err := client.Text.ReadResponse()
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (client *Client) User(user string) (err error) {
	_, err = client.Text.Cmd("USER %s", user)
	return
}

// Pass sends the given password to the server. The password is sent
// unencrypted unless the connection is already secured by TLS (via DialTLS or
// some other mechanism).
func (client *Client) Pass(password string) (err error) {
	_, err = client.Text.Cmd("PASS %s", password)
	return
}

// Auth sends the given username and password to the server.
func (client *Client) Auth(username, password string) (err error) {
	err = client.User(username)
	if err != nil {
		return
	}
	err = client.Pass(password)
	return
}

// Stat retrieves a drop listing for the current maildrop, consisting of the
// number of messages and the total size (in octets) of the maildrop.
// Information provided besides the number of messages and the size of the
// maildrop is ignored. In the event of an error, all returned numeric values
// will be 0.
func (client *Client) Stat() (count, size uint32, err error) {
	l, err := client.Text.Cmd("STAT")
	if err != nil {
		return 0, 0, err
	}
	parts := strings.Fields(l)
	count, err = stringToUint32(parts[0])
	if err != nil {
		return 0, 0, errors.New("Invalid server response")
	}
	size, err = stringToUint32(parts[1])
	if err != nil {
		return 0, 0, errors.New("Invalid server response")
	}
	return
}

// List returns the size of the message referenced by the sequence number,
// if it exists. If the message does not exist, or another error is encountered,
// the returned size will be 0.
func (client *Client) List(msgSeqNum uint32) (size uint32, err error) {
	l, err := client.Text.Cmd("LIST %d", msgSeqNum)
	if err != nil {
		return 0, err
	}
	size, err = stringToUint32(strings.Fields(l)[1])
	if err != nil {
		return 0, errors.New("Invalid server response")
	}
	return size, nil
}

// ListAll returns a list of MessageInfo for all messages, containing their
// sequence number and size.
func (client *Client) ListAll() (msgInfos []*MessageInfo, err error) {
	_, err = client.Text.Cmd("LIST")
	if err != nil {
		return
	}
	lines, err := client.Text.ReadMultiLines()
	if err != nil {
		return
	}
	msgInfos = make([]*MessageInfo, len(lines))
	for i, line := range lines {
		var seq, size uint32
		fields := strings.Fields(line)
		seq, err = stringToUint32(fields[0])
		if err != nil {
			return
		}
		size, err = stringToUint32(fields[1])
		if err != nil {
			return
		}
		msgInfos[i] = &MessageInfo{
			Seq:  seq,
			Size: size,
		}
	}
	return
}

// Retr downloads and returns the given message. The lines are separated by LF,
// whatever the server sent.
func (client *Client) Retr(msg uint32) (text string, err error) {
	_, err = client.Text.Cmd("RETR %d", msg)
	if err != nil {
		return "", err
	}
	lines, err := client.Text.ReadMultiLines()
	text = strings.Join(lines, lineSeparator)
	return
}

// Dele marks the given message as deleted.
func (client *Client) Dele(msg uint32) (err error) {
	_, err = client.Text.Cmd("DELE %d", msg)
	return
}

// Noop does nothing, but will prolong the end of the connection if the server
// has a timeout set.
func (client *Client) Noop() (err error) {
	_, err = client.Text.Cmd("NOOP")
	return
}

// Rset unmarks any messages marked for deletion previously in this session.
func (client *Client) Rset() (err error) {
	_, err = client.Text.Cmd("RSET")
	return
}

// Quit sends the QUIT message to the POP3 server and closes the connection.
func (client *Client) Quit() (err error) {
	_, err = client.Text.Cmd("QUIT")
	if err != nil {
		return err
	}
	client.Text.Close()
	return
}

// Uidl retrieves the unique ID of the message referenced by the sequence number.
func (client *Client) Uidl(msgSeqNum uint32) (uid uint32, err error) {
	line, err := client.Text.Cmd("LIST %d", msgSeqNum)
	if err != nil {
		return 0, err
	}
	uid, err = stringToUint32(strings.Fields(line)[1])
	if err != nil {
		return 0, errors.New("Invalid server response")
	}
	return
}

func stringToUint32(intString string) (uint32, error) {
	val, err := strconv.Atoi(intString)
	if err != nil {
		return 0, err
	}
	return uint32(val), nil
}
