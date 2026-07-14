package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

type mockRaceProvider struct {
	providers.Provider
	mu           sync.Mutex
	refreshCount int
	refreshDelay time.Duration
}

func (m *mockRaceProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	m.mu.Lock()
	m.refreshCount++
	m.mu.Unlock()

	time.Sleep(m.refreshDelay)

	future := time.Now().Add(1 * time.Hour)
	s.ExpiresOn = &future
	return true, nil
}

type mockRaceSessionStore struct {
	sessions.SessionStore
	mu      sync.Mutex
	session *sessions.SessionState
}

func (m *mockRaceSessionStore) Load(req *http.Request) (*sessions.SessionState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.session == nil {
		return nil, nil
	}
	data, err := json.Marshal(m.session)
	if err != nil {
		return nil, err
	}
	var clone sessions.SessionState
	if err := json.Unmarshal(data, &clone); err != nil {
		return nil, err
	}
	return &clone, nil
}

func (m *mockRaceSessionStore) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = s
	return nil
}

func (m *mockRaceSessionStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = nil
	return nil
}

func TestStoredSessionConcurrentRefresh(t *testing.T) {
	g := NewWithT(t)

	past := time.Now().Add(-1 * time.Hour)
	session := &sessions.SessionState{
		ID:        "session-id",
		ExpiresOn: &past,
	}

	store := &mockRaceSessionStore{
		session: session,
	}

	provider := &mockRaceProvider{
		refreshDelay: 50 * time.Millisecond,
	}

	middlewareInstance := NewStoredSession(store, provider)

	handler := middlewareInstance(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))

	const numRequests = 10
	var wg sync.WaitGroup
	wg.Add(numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/", nil)
			scope := &middleware.RequestScope{}
			req = middleware.AddRequestScope(req, scope)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(http.StatusOK))
		}()
	}

	wg.Wait()

	g.Expect(provider.refreshCount).To(Equal(1))
}