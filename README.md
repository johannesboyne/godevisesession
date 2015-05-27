#GO Devise Session

*godevisesession* is a Rails Cookie Parser for Devise/Warden Session-Cookies to check whether a user is signed in or not for your monolithic rails app you are thankfully breaking apart into more services ;-) 

If you are interested in the devise/warden cookie magic, read the following stack-overflow article: [http://stackoverflow.com/questions/23597718/what-is-the-warden-data-in-a-rails-devise-session-composed-of](http://stackoverflow.com/questions/23597718/what-is-the-warden-data-in-a-rails-devise-session-composed-of)

##Usage

```go
railsCookie, _  := godevisesession.ParseCookie(httpRequest, "_rails_appname_session", "secretBase", "salt")
userKey, _      := railsCookie.UserKey() //Integer, i.e.: 17 (User-ID: 17)
authSal, _      := railsCookie.AuthenticatableSalt() //String, i.e.: "$2a$10$KItas1NKsvunK0O5w9ioWu"
```

##License

MIT
