package middleware

import (
	"net/http"
	"strings"
)

// publicExactPaths are the end-user-facing endpoints served when the server
// runs in public mode (SERVER_MODE=public). Everything else returns 404 so an
// internet-facing instance never exposes the console or the management API.
var publicExactPaths = map[string]struct{}{
	// health checks (load balancers / container orchestration)
	"/health":  {},
	"/healthz": {},
	// subscription management (linked from emails)
	"/preferences":          {},
	"/subscribe":            {},
	"/unsubscribe":          {},
	"/unsubscribe-oneclick": {},
	// legacy email tracking
	"/visit": {},
	"/opens": {},
	// runtime config loaded by the notification center page
	"/config.js": {},
}

// publicPathPrefixes are path prefixes allowed in public mode.
var publicPathPrefixes = []string{
	// encrypted open/click tracking
	"/t/",
	"/r/",
	// notification center widget (preferences UI + static assets)
	"/notification-center",
	// inbound webhooks from email providers (SES, Mailgun, Supabase, ...)
	"/webhooks/",
}

// PublicEndpointFilter returns a middleware that only lets end-user-facing
// endpoints through, answering 404 for everything else. extraPaths adds
// deployment-specific paths (entries ending with "/" are treated as prefixes),
// e.g. "/api/transactional.send" or "/api/cron" when external systems call them.
func PublicEndpointFilter(extraPaths []string) func(http.Handler) http.Handler {
	extraExact := make(map[string]struct{})
	var extraPrefixes []string
	for _, p := range extraPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if strings.HasSuffix(p, "/") {
			extraPrefixes = append(extraPrefixes, p)
		} else {
			extraExact[p] = struct{}{}
		}
	}

	isAllowed := func(path string) bool {
		if _, ok := publicExactPaths[path]; ok {
			return true
		}
		for _, prefix := range publicPathPrefixes {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
		if _, ok := extraExact[path]; ok {
			return true
		}
		for _, prefix := range extraPrefixes {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
		return false
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isAllowed(r.URL.Path) {
				http.NotFound(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
