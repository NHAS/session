# session
A simple HTTP session manager. Got bored and needed to have a session manager that manages idle timeouts as well as longer max timeouts. 



Example:
```go


type SessionEntry struct {
	ArbitraryContent string
}


sessionManager = NewStore[SessionEntry]("session", time.Duration(IdleTimeDuration)*time.Second)

authorisedRoutes := http.NewServeMux()
authorisedRoutes.HandleFunc("/status", status)
authorisedRoutes.HandleFunc("/dashboard/", dashboard)


log.Fatal(http.ListenAndServe(addr, sessionManager.AuthorisationChecks(authorisedRoutes, nil)))


```

```go
_, data := sessionManager.GetSessionFromRequest(r)
if data == nil {
    http.Error(w, "No", http.StatusUnauthorized)
    return
}
```

```go
sessionKey := sessionManager.StartSession(w, r, currentSession, func(session SessionEntry) {
 // Do something on session expiry	
})

// Do stuff


sessionManager.DeleteSession(w,r)
```