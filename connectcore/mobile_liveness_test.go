package connectcore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openrung/openrung/brokerapi"
)

func TestMobileLivenessUsesNeutralEndpointsNotBrokerFronts(t *testing.T) {
	want := [...]string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"}
	if mobileLivenessURLs != want {
		t.Fatalf("neutral endpoints drifted: %v", mobileLivenessURLs)
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
	saved := mobileLivenessURLs
	mobileLivenessURLs = [2]string{neutral.URL, neutral.URL}
	t.Cleanup(func() { mobileLivenessURLs = saved })
	s := New()
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
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer portal.Close()
	if !New().physicalNetworkAlive(context.Background(), []string{portal.URL}) {
		t.Fatal("portal response should permit the ladder")
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
	go func() { result <- New().physicalNetworkAlive(ctx, []string{server.URL}) }()
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
	s := New()
	s.SetSocketProtector(&recordingProtector{refuse: true})
	if !s.physicalNetworkAlive(context.Background(), []string{server.URL}) {
		t.Fatal("protection refusal must let the ladder report local failure")
	}
	if s.physicalNetworkAlive(ctx, []string{server.URL}) {
		t.Fatal("cancelled probe must not dial")
	}
	// The protected resolver must preserve the same local-failure decision.
	s.SetDNSServers([]string{"127.0.0.1"})
	if !s.physicalNetworkAlive(context.Background(), []string{"https://neutral-test.invalid/"}) {
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
