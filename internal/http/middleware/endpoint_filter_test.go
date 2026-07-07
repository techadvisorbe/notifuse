package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPublicEndpointFilter(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("served"))
	})

	testCases := []struct {
		name       string
		path       string
		extraPaths []string
		expectCode int
	}{
		// end-user endpoints must stay reachable
		{name: "health", path: "/health", expectCode: http.StatusOK},
		{name: "healthz", path: "/healthz", expectCode: http.StatusOK},
		{name: "preferences", path: "/preferences", expectCode: http.StatusOK},
		{name: "subscribe", path: "/subscribe", expectCode: http.StatusOK},
		{name: "unsubscribe", path: "/unsubscribe", expectCode: http.StatusOK},
		{name: "one-click unsubscribe", path: "/unsubscribe-oneclick", expectCode: http.StatusOK},
		{name: "click redirection", path: "/visit", expectCode: http.StatusOK},
		{name: "open tracking", path: "/opens", expectCode: http.StatusOK},
		{name: "encrypted open tracking", path: "/t/abc123", expectCode: http.StatusOK},
		{name: "encrypted click tracking", path: "/r/abc123", expectCode: http.StatusOK},
		{name: "notification center root", path: "/notification-center", expectCode: http.StatusOK},
		{name: "notification center assets", path: "/notification-center/assets/index.js", expectCode: http.StatusOK},
		{name: "config.js used by notification center", path: "/config.js", expectCode: http.StatusOK},
		{name: "email provider webhook", path: "/webhooks/email", expectCode: http.StatusOK},
		{name: "inbound reply webhook", path: "/webhooks/email/inbound", expectCode: http.StatusOK},
		{name: "supabase webhook", path: "/webhooks/supabase/auth-email", expectCode: http.StatusOK},

		// console and management API must be hidden
		{name: "root redirect", path: "/", expectCode: http.StatusNotFound},
		{name: "console", path: "/console", expectCode: http.StatusNotFound},
		{name: "console assets", path: "/console/assets/index.js", expectCode: http.StatusNotFound},
		{name: "api root", path: "/api", expectCode: http.StatusNotFound},
		{name: "signin", path: "/api/user.signin", expectCode: http.StatusNotFound},
		{name: "setup", path: "/api/setup.initialize", expectCode: http.StatusNotFound},
		{name: "settings", path: "/api/settings.update", expectCode: http.StatusNotFound},
		{name: "workspaces", path: "/api/workspaces.list", expectCode: http.StatusNotFound},
		{name: "contacts", path: "/api/contacts.list", expectCode: http.StatusNotFound},
		{name: "transactional send", path: "/api/transactional.send", expectCode: http.StatusNotFound},
		{name: "cron", path: "/api/cron", expectCode: http.StatusNotFound},
		{name: "demo reset", path: "/api/demo.reset", expectCode: http.StatusNotFound},
		{name: "favicon detection", path: "/api/detect-favicon", expectCode: http.StatusNotFound},
		{name: "webhooks exact prefix is not a route", path: "/webhookadmin", expectCode: http.StatusNotFound},

		// extra paths open specific additional endpoints
		{
			name:       "extra exact path",
			path:       "/api/transactional.send",
			extraPaths: []string{"/api/transactional.send"},
			expectCode: http.StatusOK,
		},
		{
			name:       "extra exact path does not open siblings",
			path:       "/api/transactional.delete",
			extraPaths: []string{"/api/transactional.send"},
			expectCode: http.StatusNotFound,
		},
		{
			name:       "extra prefix path",
			path:       "/custom/deep/route",
			extraPaths: []string{"/custom/"},
			expectCode: http.StatusOK,
		},
		{
			name:       "blank extra entries are ignored",
			path:       "/api/contacts.list",
			extraPaths: []string{"", "  "},
			expectCode: http.StatusNotFound,
		},
		{
			name:       "extra path without leading slash is normalized",
			path:       "/api/cron",
			extraPaths: []string{"api/cron"},
			expectCode: http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler := PublicEndpointFilter(tc.extraPaths)(next)

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.expectCode, rec.Code)
			if tc.expectCode == http.StatusOK {
				assert.Equal(t, "served", rec.Body.String())
			}
		})
	}
}
