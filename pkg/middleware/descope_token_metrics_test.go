package middleware

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestTokenTrackerRecordsDistinctKeyExpiryPairs(t *testing.T) {
	tracker := newTestTokenTracker()
	exp := time.Now().Add(time.Hour).Truncate(time.Second)

	tracker.record("key-a", &exp)
	tracker.record("key-a", &exp)

	expUnix := exp.Unix()
	if got := len(tracker.seen); got != 1 {
		t.Fatalf("expected one seen pair, got %d", got)
	}
	if got := len(tracker.expiryBuckets[expUnix]); got != 1 {
		t.Fatalf("expected one expiry bucket entry, got %d", got)
	}
}

func TestTokenTrackerSweepRemovesExpiredBuckets(t *testing.T) {
	tracker := newTestTokenTracker()
	expired := time.Now().Add(time.Hour).Truncate(time.Second)
	future := expired.Add(time.Minute)

	tracker.record("expired-key", &expired)
	tracker.record("future-key", &future)
	tracker.sweep(expired.Unix())

	if got := len(tracker.seen); got != 1 {
		t.Fatalf("expected one live pair after sweep, got %d", got)
	}
	if _, exists := tracker.expiryBuckets[expired.Unix()]; exists {
		t.Fatal("expected expired bucket to be removed")
	}
	if got := len(tracker.expiryBuckets[future.Unix()]); got != 1 {
		t.Fatalf("expected future bucket to remain, got %d entries", got)
	}
}

func TestTokenTrackerIgnoresExpiredTokens(t *testing.T) {
	tracker := newTestTokenTracker()
	expired := time.Now().Add(-time.Minute).Truncate(time.Second)

	tracker.record("expired-key", &expired)

	if got := len(tracker.seen); got != 0 {
		t.Fatalf("expected no seen pairs, got %d", got)
	}
	if got := len(tracker.expiryBuckets); got != 0 {
		t.Fatalf("expected no expiry buckets, got %d", got)
	}
}

func newTestTokenTracker() *tokenTracker {
	return &tokenTracker{
		seen:          make(map[string]int64),
		expiryBuckets: make(map[int64][]string),
		g: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "test_descope_jwt_token",
				Help: "Test Descope JWT token gauge.",
			},
			[]string{"key_id", "exp"},
		),
	}
}
