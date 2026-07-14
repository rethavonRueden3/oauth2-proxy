package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"golang.org/x/sync/singleflight"
)

type storedSession struct {
	sessionStore sessions.SessionStore
	provider     providers.Provider
	handler      http.Handler
	refreshGroup singleflight.Group
}

// NewStoredSession creates a new storedSession middleware
func NewStoredSession(sessionStore sessions.SessionStore, provider providers.Provider) middleware.Middleware {
	return func(next http.Handler) http.Handler {
		return &storedSession{
			sessionStore: sessionStore,
			provider:     provider,
			handler:      next,
		}
	}
}

func (s *storedSession) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	scope := middleware.GetRequestScope(req)
	if scope == nil {
		logger.Errorf("Request scope not found")
		s.handler.ServeHTTP(rw, req)
		return
	}

	sessionState, err := s.sessionStore.Load(req)
	if err != nil {
		logger.Errorf("Error loading session: %v", err)
		s.handler.ServeHTTP(rw, req)
		return
	}

	if sessionState == nil {
		s.handler.ServeHTTP(rw, req)
		return
	}

	// Check if the session is expired and needs to be refreshed
	var refreshed bool
	if sessionState.IsExpired() {
		key := sessionState.ID
		if key == "" {
			key = sessionState.RefreshToken
			if key == "" {
				key = sessionState.AccessToken
			}
		}

		if key != "" {
			type refreshResult struct {
				refreshed    bool
				sessionState *sessions.SessionState
			}

			val, err, _ := s.refreshGroup.Do(key, func() (interface{}, error) {
				cloned, err := cloneSession(sessionState)
				if err != nil {
					return nil, err
				}
				refreshed, err := s.provider.RefreshSessionIfNeeded(req.Context(), cloned)
				if err != nil {
					return nil, err
				}
				return refreshResult{
					refreshed:    refreshed,
					sessionState: cloned,
				}, nil
			})

			if err != nil {
				logger.Errorf("Error refreshing session: %v", err)
				err = s.sessionStore.Clear(rw, req)
				if err != nil {
					logger.Errorf("Error clearing session: %v", err)
				}
				s.handler.ServeHTTP(rw, req)
				return
			}

			res := val.(refreshResult)
			refreshed = res.refreshed
			if refreshed {
				sessionState = res.sessionState
			}
		} else {
			refreshed, err = s.provider.RefreshSessionIfNeeded(req.Context(), sessionState)
			if err != nil {
				logger.Errorf("Error refreshing session: %v", err)
				err = s.sessionStore.Clear(rw, req)
				if err != nil {
					logger.Errorf("Error clearing session: %v", err)
				}
				s.handler.ServeHTTP(rw, req)
				return
			}
		}
	}

	if refreshed {
		err = s.sessionStore.Save(rw, req, sessionState)
		if err != nil {
			logger.Errorf("Error saving session: %v", err)
		}
	}

	scope.Session = sessionState
	s.handler.ServeHTTP(rw, req)
}

func cloneSession(s *sessions.SessionState) (*sessions.SessionState, error) {
	if s == nil {
		return nil, nil
	}
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var clone sessions.SessionState
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, err
	}
	return &clone, nil
}