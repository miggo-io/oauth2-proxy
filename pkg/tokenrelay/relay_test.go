package tokenrelay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// fakeUpstream starts a test HTTP server that returns a fixed status, body,
// and optional headers. It records the last request it received so tests can
// inspect what was forwarded.
type fakeUpstream struct {
	server      *httptest.Server
	status      int
	body        string
	headers     map[string]string
	lastRequest *http.Request
	lastBody    []byte
}

func newFakeUpstream(status int, body string) *fakeUpstream {
	f := &fakeUpstream{status: status, body: body, headers: map[string]string{}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastRequest = r
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		f.lastBody = buf.Bytes()

		for k, v := range f.headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(f.status)
		fmt.Fprint(w, f.body)
	}))
	return f
}

func (f *fakeUpstream) URL() string { return f.server.URL }
func (f *fakeUpstream) Close()      { f.server.Close() }

var _ = Describe("Handler", func() {
	var (
		upstream *fakeUpstream
		handler  *Handler
		logBuf   *bytes.Buffer
	)

	BeforeEach(func() {
		logBuf = new(bytes.Buffer)
		logger.SetOutput(logBuf)
		logger.SetErrOutput(logBuf)
	})

	Describe("ServeHTTP", func() {
		Context("when upstream returns 200 with a token", func() {
			BeforeEach(func() {
				upstreamBody := `{"access_token":"tok123","expires_in":3600,"token_type":"Bearer"}`
				upstream = newFakeUpstream(http.StatusOK, upstreamBody)
				handler = NewHandler(upstream.URL())
			})

			AfterEach(func() { upstream.Close() })

			It("returns 200 and the upstream body", func() {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/oauth2/token/relay",
					strings.NewReader("grant_type=client_credentials"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				handler.ServeHTTP(rec, req)

				Expect(rec.Code).To(Equal(http.StatusOK))
				Expect(rec.Body.String()).To(ContainSubstring("tok123"))
			})

			It("forwards the request body to upstream unchanged", func() {
				reqBody := "grant_type=client_credentials&client_id=my-key"
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/oauth2/token/relay",
					strings.NewReader(reqBody))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				handler.ServeHTTP(rec, req)

				Expect(string(upstream.lastBody)).To(Equal(reqBody))
			})

			It("forwards the Content-Type header to upstream", func() {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/oauth2/token/relay",
					strings.NewReader("grant_type=client_credentials"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				handler.ServeHTTP(rec, req)

				Expect(upstream.lastRequest.Header.Get("Content-Type")).To(Equal("application/x-www-form-urlencoded"))
			})

			It("forwards upstream response headers to the caller", func() {
				upstream.headers["X-Custom-Header"] = "some-value"
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/oauth2/token/relay",
					strings.NewReader("grant_type=client_credentials"))

				handler.ServeHTTP(rec, req)

				Expect(rec.Header().Get("X-Custom-Header")).To(Equal("some-value"))
			})

			It("logs client_id, status, expires_in, and duration", func() {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/oauth2/token/relay",
					strings.NewReader("grant_type=client_credentials&client_id=my-key"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				handler.ServeHTTP(rec, req)

				log := logBuf.String()
				Expect(log).To(ContainSubstring("client_id=my-key"))
				Expect(log).To(ContainSubstring("status=200"))
				Expect(log).To(ContainSubstring("expires_in=3600s"))
			})

			It("logs empty client_id when credentials are only in Authorization header", func() {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/oauth2/token/relay",
					strings.NewReader("grant_type=client_credentials"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

				handler.ServeHTTP(rec, req)

				Expect(logBuf.String()).To(ContainSubstring("client_id="))
				Expect(logBuf.String()).To(ContainSubstring("status=200"))
			})
		})

		Context("when upstream returns a non-200 status", func() {
			BeforeEach(func() {
				upstream = newFakeUpstream(http.StatusBadRequest, `{"error":"invalid_client"}`)
				handler = NewHandler(upstream.URL())
			})

			AfterEach(func() { upstream.Close() })

			It("passes the upstream status and body through unchanged", func() {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/oauth2/token/relay",
					strings.NewReader("grant_type=client_credentials"))

				handler.ServeHTTP(rec, req)

				Expect(rec.Code).To(Equal(http.StatusBadRequest))
				Expect(rec.Body.String()).To(ContainSubstring("invalid_client"))
			})

			It("logs status without expires_in", func() {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/oauth2/token/relay",
					strings.NewReader("grant_type=client_credentials"))

				handler.ServeHTTP(rec, req)

				log := logBuf.String()
				Expect(log).To(ContainSubstring("status=400"))
				Expect(log).To(ContainSubstring("expires_in=0s"))
			})
		})

		Context("when upstream is unreachable", func() {
			BeforeEach(func() {
				handler = NewHandler("http://127.0.0.1:1") // nothing listening
			})

			It("returns 502", func() {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/oauth2/token/relay",
					strings.NewReader("grant_type=client_credentials"))

				handler.ServeHTTP(rec, req)

				Expect(rec.Code).To(Equal(http.StatusBadGateway))
			})
		})

		Context("when method is not POST", func() {
			BeforeEach(func() {
				upstream = newFakeUpstream(http.StatusOK, "")
				handler = NewHandler(upstream.URL())
			})

			AfterEach(func() { upstream.Close() })

			DescribeTable("rejects non-POST methods",
				func(method string) {
					rec := httptest.NewRecorder()
					req := httptest.NewRequest(method, "/oauth2/token/relay", nil)

					handler.ServeHTTP(rec, req)

					Expect(rec.Code).To(Equal(http.StatusMethodNotAllowed))
				},
				Entry("GET", http.MethodGet),
				Entry("PUT", http.MethodPut),
				Entry("DELETE", http.MethodDelete),
			)
		})
	})

	Describe("extractClientID", func() {
		Context("form-encoded body", func() {
			It("extracts client_id from a well-formed body", func() {
				body := []byte("grant_type=client_credentials&client_id=my-key&client_secret=secret")
				Expect(extractClientID(body, "application/x-www-form-urlencoded")).To(Equal("my-key"))
			})

			It("returns empty string when client_id is absent", func() {
				body := []byte("grant_type=client_credentials")
				Expect(extractClientID(body, "application/x-www-form-urlencoded")).To(Equal(""))
			})

			It("treats empty Content-Type as form-encoded", func() {
				body := []byte("client_id=fallback-key")
				Expect(extractClientID(body, "")).To(Equal("fallback-key"))
			})
		})

		Context("JSON body", func() {
			It("extracts client_id from a JSON body", func() {
				body, _ := json.Marshal(map[string]string{
					"grant_type": "client_credentials",
					"client_id":  "json-key",
				})
				Expect(extractClientID(body, "application/json")).To(Equal("json-key"))
			})

			It("returns empty string when client_id is absent from JSON", func() {
				body, _ := json.Marshal(map[string]string{"grant_type": "client_credentials"})
				Expect(extractClientID(body, "application/json")).To(Equal(""))
			})

			It("returns empty string for malformed JSON", func() {
				Expect(extractClientID([]byte("{not-valid-json"), "application/json")).To(Equal(""))
			})
		})

		Context("empty body", func() {
			It("returns empty string", func() {
				Expect(extractClientID([]byte{}, "application/x-www-form-urlencoded")).To(Equal(""))
				Expect(extractClientID([]byte{}, "application/json")).To(Equal(""))
			})
		})
	})
})
