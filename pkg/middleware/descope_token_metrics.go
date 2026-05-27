package middleware

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// descope_jwt_token is set to 1 for each distinct (key_id, exp) JWT observed,
// and removed once the token's exp has passed. This lets the metrics backend
// count distinct issued tokens with:
//
//	count(count by (key_id, exp) (descope_jwt_token))
//
// Grouping by (key_id, exp) collapses the per-pod label set, so the distinct
// count is exact across replicas (no per-pod overcount). key_id is the JWT
// `sub` claim = the Descope access key ID (MIG-11558).
//
// Memory is bounded: only currently-valid tokens are held in-process; a
// background sweep deletes label sets once exp passes. At a ~1h token TTL the
// active set is roughly (new tokens/hour seen by this pod), not the full
// historical set — the backend retains history, the process does not.
var descopeTokenGauge = registerDescopeTokenGauge(prometheus.DefaultRegisterer)

func registerDescopeTokenGauge(registerer prometheus.Registerer) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "descope_jwt_token",
			Help: "Set to 1 for each distinct (key_id, exp) JWT observed while within its validity window. Count distinct issuances with count(count by (key_id,exp)(descope_jwt_token)).",
		},
		[]string{"key_id", "exp"},
	)
	if err := registerer.Register(g); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			return are.ExistingCollector.(*prometheus.GaugeVec)
		}
		panic(err)
	}
	return g
}

// tokenTracker dedups observed tokens and expires them when their exp passes,
// keeping the exposed series (and process memory) bounded.
type tokenTracker struct {
	mu   sync.Mutex
	seen map[string]int64 // "key_id\x00exp" -> exp unix seconds
	g    *prometheus.GaugeVec
}

var descopeTokens = newTokenTracker(descopeTokenGauge)

func newTokenTracker(g *prometheus.GaugeVec) *tokenTracker {
	t := &tokenTracker{seen: make(map[string]int64), g: g}
	go t.sweepLoop()
	return t
}

// record marks a token (key_id, exp) as observed. First observation sets the
// gauge; repeats are no-ops. Expired tokens are ignored.
func (t *tokenTracker) record(keyID string, exp *time.Time) {
	if keyID == "" || exp == nil || exp.IsZero() {
		return
	}
	expUnix := exp.Unix()
	if expUnix <= time.Now().Unix() {
		return
	}
	expStr := strconv.FormatInt(expUnix, 10)
	key := keyID + "\x00" + expStr

	t.mu.Lock()
	_, exists := t.seen[key]
	if !exists {
		t.seen[key] = expUnix
	}
	t.mu.Unlock()

	if !exists {
		t.g.WithLabelValues(keyID, expStr).Set(1)
	}
}

func (t *tokenTracker) sweepLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		t.sweep(time.Now().Unix())
	}
}

func (t *tokenTracker) sweep(now int64) {
	t.mu.Lock()
	expired := make([]string, 0)
	for key, exp := range t.seen {
		if exp <= now {
			expired = append(expired, key)
			delete(t.seen, key)
		}
	}
	t.mu.Unlock()

	for _, key := range expired {
		if i := strings.IndexByte(key, '\x00'); i >= 0 {
			t.g.DeleteLabelValues(key[:i], key[i+1:])
		}
	}
}
