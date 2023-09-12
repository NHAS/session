package session

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

type sessionKey struct{}

type expiryTimer struct {
	timer       *time.Timer
	maxLifeTime time.Time
}

// SessionStore holds the session data and settings
type SessionStore[T any] struct {
	cookieName   string
	sessions     map[string]T
	onDelete     map[string]func(T)
	lock         sync.RWMutex
	ctxKey       sessionKey
	expiration   time.Duration
	expireTimers map[string]*expiryTimer
	hmacKey      string

	MaxSessionDuration int
	VerboseErrors      bool
}

// Init will initialize the SessionStore object
func NewStore[T any](cookieName string, itemExpiry time.Duration, MaxSessionDuration int, VerboseErrors bool) (st *SessionStore[T], err error) {
	st = &SessionStore[T]{}

	st.hmacKey, err = GenerateRandom(32)
	if err != nil {
		return nil, errors.New("unable to generate hmac session key: " + err.Error())
	}

	st.cookieName = cookieName

	st.sessions = make(map[string]T)
	st.expireTimers = make(map[string]*expiryTimer)
	st.onDelete = map[string]func(T){}

	st.ctxKey = sessionKey{}
	st.expiration = itemExpiry

	st.MaxSessionDuration = MaxSessionDuration
	st.VerboseErrors = VerboseErrors

	return st, nil
}

// PutSession will store the session in the SessionStore.
// The session will automatically expire after defined SessionStore.sessionExpiration.
func (st *SessionStore[T]) StartSession(w http.ResponseWriter, r *http.Request, sess T, onDelete func(T)) string {
	cookieValue, err := GenerateRandom(32)
	if err != nil {
		return ""
	}

	st.lock.Lock()

	var newExpiryTimer expiryTimer

	newExpiryTimer.timer = time.AfterFunc(st.expiration, func() {
		st.deleteEntry(cookieValue)
	})

	newExpiryTimer.maxLifeTime = time.Now().Add(time.Duration(st.MaxSessionDuration) * time.Second)

	st.expireTimers[cookieValue] = &newExpiryTimer
	st.sessions[cookieValue] = sess
	st.onDelete[cookieValue] = onDelete

	st.lock.Unlock()

	SetCookie(st.cookieName, cookieValue, time.Now().Add(time.Duration(st.MaxSessionDuration)*time.Second), w, r, true)

	return cookieValue
}

// UpdateSession will change the stored value
func (st *SessionStore[T]) GetSession(sessionKey string) *T {
	st.lock.RLock()
	defer st.lock.RUnlock()
	sess, ok := st.sessions[sessionKey]
	if !ok {
		return nil
	}

	return &sess
}

// UpdateSession will change the stored value
func (st *SessionStore[T]) UpdateSession(sessionKey string, sess T) {
	st.lock.Lock()
	st.sessions[sessionKey] = sess
	st.lock.Unlock()
}

// DeleteSession will delete the session from the SessionStore.
func (st *SessionStore[T]) DeleteSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(st.cookieName)
	if err != nil {
		return
	}

	st.deleteEntry(cookie.Value)

	ClearCookie(st.cookieName, w, r)
}

func (st *SessionStore[T]) deleteEntry(cookieValue string) {

	st.lock.Lock()
	defer st.lock.Unlock()

	if _, ok := st.onDelete[cookieValue]; ok {
		go st.onDelete[cookieValue](st.sessions[cookieValue])
	}

	if _, ok := st.expireTimers[cookieValue]; ok {
		st.expireTimers[cookieValue].timer.Stop()
	}

	delete(st.onDelete, cookieValue)
	delete(st.sessions, cookieValue)
	delete(st.expireTimers, cookieValue)

}

// GetSessionFromRequest retrieves the session from the http.Request cookies.
// The function will return nil if the session does not exist within the http.Request cookies.
func (st *SessionStore[T]) GetSessionFromRequest(r *http.Request) (string, *T) {

	if st == nil {
		return "", nil
	}

	cookie, err := r.Cookie(st.cookieName)
	if err != nil {
		return "", nil
	}

	st.lock.RLock()
	defer st.lock.RUnlock()

	t, ok := st.expireTimers[cookie.Value]
	if !ok {
		return "", nil
	}

	if time.Now().Before(t.maxLifeTime) {
		t.timer.Reset(st.expiration)
	}

	sess, ok := st.sessions[cookie.Value]
	if !ok {
		return "", nil
	}

	return cookie.Value, &sess
}

func (st *SessionStore[T]) ResetTimer(sessionKey string) error {
	st.lock.RLock()
	defer st.lock.RUnlock()

	t, ok := st.expireTimers[sessionKey]
	if !ok {
		return errors.New("not found")
	}

	if time.Now().After(t.maxLifeTime) {
		return errors.New("could not extend session lifetime")
	}

	t.timer.Reset(st.expiration)

	return nil
}

// AuthorisationChecks will load the session into the http.Request context, and checks CSRF protections
// A http.StatusUnauthorized will be retuned to the client if no session can be found.
func (st *SessionStore[T]) AuthorisationChecks(next http.Handler, onFailureRedirect string, onCheck func(w http.ResponseWriter, r *http.Request, sess T) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sess := st.GetSessionFromRequest(r)
		if sess == nil {
			http.Redirect(w, r, onFailureRedirect, http.StatusTemporaryRedirect)
			return
		}

		if onCheck != nil && !onCheck(w, r, *sess) {
			return
		}

		switch r.Method {

		//Allow these methods to pass without CSRF tokens
		case "GET", "OPTIONS", "HEAD":

			//Anything else will go through here
		default:

			csrfToken := r.FormValue("csrf_token")
			if len(csrfToken) == 0 {
				st.serverError(w, r, errors.New("token wasnt found in form"))
				return
			}
			decodedToken, err := hex.DecodeString(csrfToken)
			if err != nil {
				st.serverError(w, r, errors.New("decoding hex token failed"))
				return
			}

			cookie, err := r.Cookie(st.cookieName)
			if err != nil {
				st.serverError(w, r, err)
				return
			}

			expectValued, err := st.hmac(cookie.Value)
			if err != nil {
				st.serverError(w, r, err)
				return
			}

			if subtle.ConstantTimeCompare(expectValued, decodedToken) != 1 {
				st.serverError(w, r, fmt.Errorf("comparing tokens failed, Form: %x Expected: %x", decodedToken, expectValued))
				return
			}

		}

		ctx := context.WithValue(r.Context(), st.ctxKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (st *SessionStore[T]) GenerateCSRFToken(r *http.Request) ([]byte, error) {
	cookie, err := r.Cookie(st.cookieName)
	if err != nil {
		return nil, err
	}

	return st.hmac(cookie.Value)
}

func (st *SessionStore[T]) hmac(contents string) ([]byte, error) {

	//Blake2 can be used as a mac
	hmac, err := blake2b.New256([]byte(st.hmacKey))
	if err != nil {
		return nil, err
	}

	hmac.Write([]byte(contents))

	return hmac.Sum(nil), nil
}

func (st *SessionStore[T]) serverError(w http.ResponseWriter, request *http.Request, err error) {
	message := err.Error()

	//This has to do a direct call to logf so that the function that called this (the 2nd set up the call chain) will be printed
	log.Println(message)
	if !st.VerboseErrors {
		message = "Sorry, a server error has occurred. please contact the admins if this problem persists"
	}
	http.Error(w, message, http.StatusInternalServerError)
}

// This should probably allow the user to specify
func SetCookie(name, data string, expires time.Time, w http.ResponseWriter, r *http.Request, lax bool) {

	cookie := http.Cookie{
		Name:     name,
		Value:    data,
		HttpOnly: true,
		Secure:   r.URL.Scheme == "https",
		Expires:  expires,
		Path:     "/",
	}

	cookie.SameSite = http.SameSiteStrictMode
	if lax {
		// required to allow oauth
		cookie.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, &cookie)
}

// clearCookie will set a given cookie to blank value, expiring at the unix epoch
func ClearCookie(name string, w http.ResponseWriter, r *http.Request) {
	SetCookie(name, "", time.Unix(0, 0), w, r, false)
}

func GenerateRandom(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
