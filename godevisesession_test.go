package godevisesession

import (
	"net/http"
	"testing"
)

const jsonString = "{\"session_id\":\"9a93ef8b17cc6ba80246d3ca8d3f7970\",\"warden.user.user.key\":[[1],\"$2a$10$KItas1NKsvunK0O5w9ioWu\"],\"_csrf_token\":\"8KkCrd9Az1eEMiWoMtpWstg9YjgJXKSB74JLgmUbXPL=\"}\a\a\a\a"

func TestParseData(t *testing.T) {
	rC, _ := ParseData([]byte(jsonString))
	if rC.Session_Id != "9a93ef8b17cc6ba80246d3ca8d3f7970" {
		t.Errorf("Session_Id wrongly parsed: %v", rC)
	}
	uK, _ := rC.UserKey()
	aS, _ := rC.AuthenticatableSalt()
	if uK != 1 {
		t.Errorf("Warden User Key wrongly parsed: %v %v", rC.Warden_User_key[0].([]interface{})[0], rC)
	}
	if aS != "$2a$10$KItas1NKsvunK0O5w9ioWu" {
		t.Errorf("Warden User 30 chars Hashed-Pass wrongly parsed: %v %v", rC.Warden_User_key[0].([]interface{})[1], rC)
	}
}

func TestParseCookie(t *testing.T) {
	request, _ := http.NewRequest("Get", "http://localserver/", nil)
	request.Header.Add("Cookie", "_test_rails_session=QjJ0UjFOZS85SjJGV0N3c1ZndHZzalhsSUpvRUl1V29wS3cyWWFqNnEzM25qak1yR2YydlJCUFBUV3F6YXhxVXNLa0hReVBOUEljME1zS3d4NHFDS1BNY2RHU3hQYTNYaXpGclhKZVFDb3hwWStoZWZtYVZlRGk2Q0FReVNaZlJ3VVFhckYrN0ZFVjlvRi9yVnpHWHgwakRxMlJndy9rQ3BwY3ppWSs2RFRBZWpOdlQ5MDZ0VGFnNEtlQ1pOa2czU0F2SkpZcHRnblFyTmJrN25pTEcyV3l3bVdlSzVrejF5YWFhRzd0bU5BRT0tLVREZDBFNTB2T3pTSllHam5xYnd5ZVE9PQ%3D%3D--330daf21b03241864bf7dceb1367e338022fafa1")
	rC, _ := ParseCookie(request, "_test_rails_session", "e4c76e3bf3164f7a7e4e01a7f6d922217af8de71a4cdc77b15a600fcad8eff614766c98e94aaebc92420d3fb92f0730e42d3ab25f2b8605f586eff9993d42ef2", "encrypted cookie")
	_, err := rC.UserKey()
	_, err = rC.AuthenticatableSalt()
	if err != nil {
		t.Errorf("An error occured while parsing: %v", err)
	}
}
