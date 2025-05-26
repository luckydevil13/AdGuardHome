package home

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/AdguardTeam/golibs/ioutil"
	"github.com/AdguardTeam/golibs/log"
	"github.com/josharian/native"
)

// GLMode - enable GL-Inet compatibility mode
var GLMode bool

var glFilePrefix = "/tmp/gl_token_"

const (
	glTokenTimeoutSeconds = 3600
	glCookieName          = "Admin-Token"
)

func glProcessRedirect(w http.ResponseWriter, r *http.Request) bool {
	if !GLMode {
		return false
	}
	// redirect to gl-inet login
	host, _, _ := net.SplitHostPort(r.Host)
	url := "http://" + host
	log.Debug("Auth: redirecting to %s", url)
	http.Redirect(w, r, url, http.StatusFound)
	return true
}

func glProcessCookie() bool {
	return true
}

func glCheckToken(sess string) bool {
	return true
}

// MaxFileSize is a maximum file length in bytes.
const MaxFileSize = 1024 * 1024

func glGetTokenDate(file string) uint32 {
	f, err := os.Open(file)
	if err != nil {
		log.Error("os.Open: %s", err)

		return 0
	}
	defer func() {
		derr := f.Close()
		if derr != nil {
			log.Error("glinet: closing file: %s", err)
		}
	}()

	fileReader := ioutil.LimitReader(f, MaxFileSize)

	var dateToken uint32

	// This use of ReadAll is now safe, because we limited reader.
	bs, err := io.ReadAll(fileReader)
	if err != nil {
		log.Error("reading token: %s", err)

		return 0
	}

	buf := bytes.NewBuffer(bs)

	// TODO(a.garipov): Get rid of github.com/josharian/native dependency.
	err = binary.Read(buf, native.Endian, &dateToken)
	if err != nil {
		log.Error("decoding token: %s", err)

		return 0
	}

	return dateToken
}
