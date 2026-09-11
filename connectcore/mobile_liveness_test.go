package connectcore

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openrung/openrung/brokerapi"
)

func TestMobileLivenessAllowsBlockedBrokerWithReachableNeutralEndpoint(t *testing.T) {
	want := []string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"}
	if got := New().mobileLivenessEndpoints(); !reflect.DeepEqual(got, want) {
		t.Fatalf("neutral endpoints drifted: %v", got)
	}
	neutral := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("method = %s", r.Method)
		}
		for key := range r.Header {
			if key != "Cache-Control" && key != "Connection" {
				t.Errorf("unexpected identifying header: %s", key)
			}
		}
		w.WriteHeader(http.StatusServiceUnavailable) // Any response proves connectivity.
	}))
	defer neutral.Close()
	s := New()
	s.physicalLivenessURLs = []string{neutral.URL}
	s.Mobile = &MobileHost{}
	protector := &recordingProtector{}
	s.SetSocketProtector(protector)
	// A blocked broker is deliberately not a prerequisite for re-laddering.
	if !s.networkAlive(context.Background(), []string{"127.0.0.1:1"}) {
		t.Fatal("neutral response did not permit recovery")
	}
	if protector.count() == 0 {
		t.Fatal("physical probe socket was not protected")
	}
}

func TestMobileLivenessDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	s := New()
	s.physicalLivenessURLs = []string{redirect.URL}
	if !s.physicalNetworkAlive(context.Background()) {
		t.Fatal("verified endpoint redirect should permit the ladder")
	}
	if redirected.Load() != 0 {
		t.Fatal("followed a physical probe redirect")
	}
}

func TestMobileLivenessCancellationAndProtectionRefusal(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	s := New()
	s.physicalLivenessURLs = []string{server.URL}
	go func() { result <- s.physicalNetworkAlive(ctx) }()
	<-entered
	cancel()
	select {
	case alive := <-result:
		if alive {
			t.Fatal("cancelled probe proved liveness")
		}
	case <-time.After(time.Second):
		t.Fatal("probe did not join on cancellation")
	}
	s.SetSocketProtector(&recordingProtector{refuse: true})
	if !s.physicalNetworkAlive(context.Background()) {
		t.Fatal("protection refusal must let the ladder report local failure")
	}
	if s.physicalNetworkAlive(ctx) {
		t.Fatal("cancelled probe must not dial")
	}
	// The protected resolver must preserve the same local-failure decision.
	s.SetDNSServers([]string{"127.0.0.1"})
	s.physicalLivenessURLs = []string{"https://neutral-test.invalid/"}
	if !s.physicalNetworkAlive(context.Background()) {
		t.Fatal("DNS protection refusal held recovery")
	}
}

func TestMobileLocationDetailsNeverFallBackToOperatorName(t *testing.T) {
	for _, tc := range []struct{ city, country, want string }{
		{" Tokyo ", " Japan ", "Tokyo, Japan"}, {"Tokyo", "", "Tokyo"}, {"", "Japan", "Japan"}, {"", "", ""},
	} {
		s := New()
		s.Mobile = &MobileHost{}
		s.core.status = StatusConnected
		s.conn = &connection{active: &candidateResult{relay: brokerapi.RelayDescriptor{
			ID: "relay_ab12", Label: "\u202eevil", RelayGeoLocation: brokerapi.RelayGeoLocation{City: tc.city, Country: tc.country},
		}}}
		details := s.detailsLocked()
		if details.LocationLabel != tc.want {
			t.Fatalf("location = %q, want %q", details.LocationLabel, tc.want)
		}
		if details.RelayName != "\u202eevil" {
			t.Fatal("operator name must remain separate for native sanitization")
		}
		s.core.status = StatusConnecting
		details = s.detailsLocked()
		if !reflect.DeepEqual(details, &StateDetails{}) {
			t.Fatalf("recovery retained relay/location details: %+v", details)
		}
	}
}

func TestMobileLivenessAllowsBlockedNeutralEndpointsWithReachableFront(t *testing.T) {
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	s := New()
	s.Mobile = &MobileHost{}
	s.physicalLivenessURLs = []string{"http://127.0.0.1:1", "http://127.0.0.1:1"}
	s.SetSocketProtector(&recordingProtector{})
	if !s.networkAlive(context.Background(), []string{front.Addr().String()}) {
		t.Fatal("reachable front was blocked by neutral failures")
	}
	if s.networkAlive(context.Background(), []string{"127.0.0.1:1"}) {
		t.Fatal("unreachable endpoints proved connectivity")
	}
}

func TestMobileLivenessAllowsSlowResponseAndRejectsUntrustedTLS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3200 * time.Millisecond):
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	s := New()
	s.physicalLivenessURLs = []string{server.URL}
	if !s.physicalNetworkAlive(context.Background()) {
		t.Fatal("usable response beyond three seconds rejected")
	}
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusFound) }))
	defer untrusted.Close()
	s.physicalLivenessURLs = []string{untrusted.URL}
	if s.physicalNetworkAlive(context.Background()) {
		t.Fatal("untrusted TLS response proved neutral liveness")
	}
}

func TestPhysicalTransportsNeverUseProcessProxy(t *testing.T) {
	s := New()
	s.SetSocketProtector(&recordingProtector{})
	for _, transport := range []*http.Transport{
		protectedTransport(s.currentProtector(), nil),
		s.geoHTTPClient().Transport.(*http.Transport),
		s.punchCoordinationClient().Transport.(*http.Transport),
	} {
		if transport.Proxy != nil {
			t.Fatal("physical transport inherited a process proxy")
		}
	}
}

func TestMobileDownStateSkipsAllPhysicalProbesAndHoldExpires(t *testing.T) {
	s := New()
	s.Mobile = &MobileHost{}
	s.networkRecoveryLimit = 25 * time.Millisecond
	s.networkRetryDelay = 2 * time.Millisecond
	s.UpdateNetworkState(NetworkState{Up: false, Fingerprint: "airplane"})
	var probes atomic.Int32
	s.checkNetworkAlive = func(context.Context, []string) bool { probes.Add(1); return false }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn := &connection{netNotify: make(chan struct{}, 1)}
	if !s.waitForNetworkRecovery(ctx, conn) {
		t.Fatal("down state held the post-teardown gate forever")
	}
	if probes.Load() != 0 {
		t.Fatal("known-down network performed physical probes")
	}
	if ctx.Err() != nil {
		t.Fatal("released only at parent deadline")
	}
}

func TestMobileBlockedProbesCannotHoldHealthOrRecoveryForever(t *testing.T) {
	for _, health := range []bool{false, true} {
		s := New()
		s.Mobile = &MobileHost{}
		s.healthTick = time.Millisecond
		s.networkRecoveryLimit = 25 * time.Millisecond
		s.networkRetryDelay = time.Millisecond
		s.checkNetworkAlive = func(context.Context, []string) bool { return false }
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if health {
			failed := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.healthLoopWithProbe(ctx, 0, nil, failed, nil,
					func(context.Context, int) error { return errors.New("remote path lost") }, nil)
			}()
			select {
			case <-failed:
			case <-ctx.Done():
				t.Fatal("health's network-down gate never permitted recovery")
			}
			cancel()
			<-done
		} else {
			if !s.waitForNetworkRecovery(ctx, &connection{netNotify: make(chan struct{}, 1)}) {
				t.Fatal("post-teardown gate never permitted recovery")
			}
			cancel()
		}
	}
}

// Observe entry to the outage wait before delivering an up epoch. Without this
// barrier the test could pass by observing Up on its very first liveness check.
type recoveryWaitingSink struct {
	testSink
	ready chan struct{}
}

func (s *recoveryWaitingSink) Log(entry LogEntry) {
	s.testSink.Log(entry)
	if entry.Line == "the tunnel stopped while the local network is down; waiting for connectivity" {
		s.ready <- struct{}{}
	}
}

func TestMobileRecoveryBackoffAndNetworkSignal(t *testing.T) {
	delay := networkRecoveryPollInterval
	var got []time.Duration
	for i := 0; i < 7; i++ {
		got = append(got, delay)
		delay = nextMobileRecoveryDelay(delay)
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second, 60 * time.Second, 60 * time.Second}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("retry delays = %v", got)
	}
	s := New()
	s.Mobile = &MobileHost{}
	s.networkRetryDelay = time.Hour // Only a network signal may wake this test's timer.
	waiting := &recoveryWaitingSink{ready: make(chan struct{}, 1)}
	s.Sink = waiting
	s.UpdateNetworkState(NetworkState{Up: false, Fingerprint: "airplane"})
	var probes atomic.Int32
	s.checkNetworkAlive = func(context.Context, []string) bool { probes.Add(1); return true }
	conn := &connection{netNotify: make(chan struct{}, 1)}
	s.conn = conn
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan bool, 1)
	go func() { result <- s.waitForNetworkRecovery(ctx, conn) }()
	select {
	case <-waiting.ready:
	case <-ctx.Done():
		t.Fatal("recovery never entered the outage wait")
	}
	s.UpdateNetworkState(NetworkState{Up: true, Fingerprint: "cellular"})
	if !<-result {
		t.Fatal("up signal failed to wake recovery")
	}
	if probes.Load() != 1 {
		t.Fatalf("physical checks = %d", probes.Load())
	}
	cancel()
	if s.networkAliveBefore(ctx, nil, time.Now().Add(-time.Second)) {
		t.Fatal("expired hold defeated cancellation")
	}
}

func TestMobileRecoveryBudgetCancelsAnInFlightProbe(t *testing.T) {
	s := New()
	s.Mobile = &MobileHost{}
	s.checkNetworkAlive = func(ctx context.Context, _ []string) bool {
		<-ctx.Done()
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !s.networkAliveBefore(ctx, nil, time.Now().Add(25*time.Millisecond)) || ctx.Err() != nil {
		t.Fatal("probe outlived the mobile budget or consumed the parent cancellation")
	}
}

func TestMobilePromoteKeepsAllLocationSurfacesGeographic(t *testing.T) {
	for _, mobile := range []bool{false, true} {
		for _, tc := range []struct{ city, label, desktop string }{
			{"", "\u202eevil", "\u202eevil"},
			{"Tokyo", "\u202eevil", "\u202eevil"},
			{"", "", "relay relay_ab12"},
			{"Tokyo", "", "relay relay_ab12"},
		} {
			s := New()
			s.SetMode(ModeTUN) // No process-global proxy settings in this state projection test.
			if mobile {
				s.Mobile = &MobileHost{}
			}
			sink := &testSink{}
			s.Sink = sink
			r := usableRelay("relay_ab12", "JP", tc.city, "")
			r.Label = tc.label
			conn := &connection{}
			s.conn = conn
			if !s.promote(context.Background(), conn, &candidateResult{relay: r}, 0, false) {
				t.Fatal("promotion rejected")
			}
			state := sink.last()
			want := tc.desktop // Desktop deliberately keeps city-only fallback behavior.
			if mobile {
				want = tc.city
			}
			if state.RelayLabel == nil || *state.RelayLabel != want {
				t.Fatalf("mobile=%v label=%v want=%q", mobile, state.RelayLabel, want)
			}
			if len(state.Recents) != 1 || state.Recents[0].Label != want {
				t.Fatalf("recent = %+v", state.Recents)
			}
			if mobile && (state.Details.LocationLabel != want || state.Recents[0].RelayID != r.ID) {
				t.Fatalf("mobile metadata = %+v", state)
			}
		}
	}
}
