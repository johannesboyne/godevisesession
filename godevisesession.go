package godevisesession

import (
	"encoding/json"
	"errors"
	"net/http"

	"unicode"
	"unicode/utf8"

	"github.com/adeven/gorails/session"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

type RailsCookie struct {
	Session_Id      string        `json:"session_id"`
	Warden_User_key []interface{} `json:"warden.user.user.key"`
}

func (rC *RailsCookie) UserKey() (int, error) {
	if rC.Warden_User_key == nil {
		return -1, errors.New("no user key")
	}
	return int(rC.Warden_User_key[0].([]interface{})[0].(float64)), nil
}

func (rC *RailsCookie) AuthenticatableSalt() (string, error) {
	if rC.Warden_User_key == nil {
		return "", errors.New("no user key")
	}
	return string(rC.Warden_User_key[1].(string)), nil
}

func isMnCc(r rune) bool {
	rT := []*unicode.RangeTable{unicode.Mn, unicode.Cc}
	return unicode.IsOneOf(rT, r)
}

func ParseData(jS []byte) (RailsCookie, error) {
	t := transform.Chain(norm.NFD, transform.RemoveFunc(isMnCc), norm.NFC)
	result, _, _ := transform.String(t, string(jS))

	var m RailsCookie

	err := json.Unmarshal([]byte(result), &m)
	if err != nil {
		return m, err
	}
	return m, nil
}

// sessionCookie - raw _<your app name>_session cookie, i.e. _my_rails_app_session
func getRailsSessionData(sessionCookie string, secretKeyBase string, salt string) (decryptedCookieData []byte, err error) {
	return session.DecryptSignedCookie(sessionCookie, secretKeyBase, salt)
}

func ParseCookie(request *http.Request, cookieName string, secret string, salt string) (RailsCookie, error) {
	cookie, _ := request.Cookie(cookieName)
	sessionData, _ := getRailsSessionData(string(cookie.String()[utf8.RuneCountInString(cookieName)+1:]), secret, salt)
	return ParseData(sessionData)
}
