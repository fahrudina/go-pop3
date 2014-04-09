package pop3

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

type Connection struct {
	Reader *bufio.Reader
	Writer *bufio.Writer
	conn   io.ReadWriteCloser
}

var crlf = []byte{'\r', '\n'}
var okResponse = "+OK"
var endResponse = "."

func NewConnection(conn io.ReadWriteCloser) *Connection {
	return &Connection{
		Reader: bufio.NewReader(conn),
		Writer: bufio.NewWriter(conn),
		conn:   conn,
	}
}

func (c *Connection) Close() error {
	return c.conn.Close()
}

func (c *Connection) Cmd(format string, args ...interface{}) (result string, err error) {
	c.SendCMD(format, args...)
	return c.ReadResponse()
}

func (c *Connection) SendCMD(format string, args ...interface{}) {
	fmt.Fprintf(c.Writer, format, args...)
	c.Writer.Write(crlf)
	c.Writer.Flush()

	return
}

func (c *Connection) ReadResponse() (result string, err error) {
	result = ""

	response, _, err := c.Reader.ReadLine()
	if err != nil {
		return
	}

	line := string(response)
	if line[0:3] != okResponse {

		err = errors.New(line[5:])
	}

	if len(line) >= 4 {
		result = line[4:]
	}

	return
}

func (c *Connection) ReadMultiLines() (lines []string, err error) {
	lines = make([]string, 0)
	var bytes []byte

	for {
		bytes, _, err = c.Reader.ReadLine()
		line := string(bytes)

		if err != nil || line == endResponse {
			return
		}

		if len(line) > 0 && string(line[0]) == "." {
			line = line[1:]
		}

		lines = append(lines, line)
	}

	return
}
