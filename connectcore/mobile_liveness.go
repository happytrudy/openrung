package connectcore

import (
	"context"
	"net/http"
	"time"
)

// Shipping Android's neutral physical-path endpoints (mobile main 53e03d9).
// Keep these independent of broker fronts, relays, and OpenRung infrastructure.
// InternetProbeURLs instead prove the through-tunnel path and must not be reused.
var mobileLivenessURLs = [...]string{
	"https://www.gstatic.com/generate_204",
	"https://cp.cloudflare.com/generate_204",
}

const mobileLivenessTimeout = 3 * time.Second

func (s *Engine) physicalNetworkAlive(ctx context.Context, endpoints []string) bool {
	transport := protectedTransport(s.currentProtector(), s.currentDNSServers())
	transport.Proxy = nil // Never inherit a process proxy or use the captured TUN.
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		Timeout:       mobileLivenessTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, endpoint := range endpoints {
		if ctx.Err() != nil {
			return false
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("User-Agent", "") // No application identity or broker headers.
		response, err := client.Do(req)
		if err == nil {
			response.Body.Close()
			// Any received status proves physical connectivity, including a
			// captive portal redirect. It is not evidence of tunnel health.
			return ctx.Err() == nil
		}
		if isSocketProtectionFailure(err) {
			// The gate cannot measure a refused socket. Let the ladder surface
			// the terminal local failure instead of waiting for internet forever.
			return ctx.Err() == nil
		}
	}
	return false
}
