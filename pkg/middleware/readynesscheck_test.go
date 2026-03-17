package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ReadynessCheck suite", func() {
	type requestTableInput struct {
		readyPath        string
		healthVerifiable Verifiable
		requestString    string
		expectedStatus   int
		expectedBody     string
	}

	DescribeTable("when serving a request",
		func(in *requestTableInput) {
			req := httptest.NewRequest("", in.requestString, nil)

			rw := httptest.NewRecorder()

			ctx := context.Background()

			handler := NewReadynessCheck(ctx, in.readyPath, in.healthVerifiable)(http.NotFoundHandler())
			handler.ServeHTTP(rw, req)

			Expect(rw.Code).To(Equal(in.expectedStatus))
			Expect(rw.Body.String()).To(Equal(in.expectedBody))
		},
		Entry("when requesting the readyness check path", &requestTableInput{
			readyPath:        "/ready",
			healthVerifiable: &fakeVerifiable{nil},
			requestString:    "http://example.com/ready",
			expectedStatus:   200,
			expectedBody:     "OK",
		}),
		Entry("when requesting a different path", &requestTableInput{
			readyPath:        "/ready",
			healthVerifiable: &fakeVerifiable{nil},
			requestString:    "http://example.com/different",
			expectedStatus:   404,
			expectedBody:     "404 page not found\n",
		}),
		Entry("when a blank string is configured as a readyness check path and the request has no specific path", &requestTableInput{
			readyPath:        "",
			healthVerifiable: &fakeVerifiable{nil},
			requestString:    "http://example.com",
			expectedStatus:   404,
			expectedBody:     "404 page not found\n",
		}),
		Entry("with full health check and without an underlying error", &requestTableInput{
			readyPath:        "/ready",
			healthVerifiable: &fakeVerifiable{nil},
			requestString:    "http://example.com/ready",
			expectedStatus:   200,
			expectedBody:     "OK",
		}),
		Entry("with full health check and with an underlying error", &requestTableInput{
			readyPath:        "/ready",
			healthVerifiable: &fakeVerifiable{func(ctx context.Context) error { return errors.New("failed to check") }},
			requestString:    "http://example.com/ready",
			expectedStatus:   500,
			expectedBody:     "error: failed to check",
		}),
	)

	Context("during graceful shutdown (cancelled context)", func() {
		var cancelledCtx context.Context

		BeforeEach(func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			cancelledCtx = ctx
		})

		It("returns 503 on the readiness path", func() {
			req := httptest.NewRequest("GET", "http://example.com/ready", nil)
			rw := httptest.NewRecorder()

			handler := NewReadynessCheck(cancelledCtx, "/ready", &fakeVerifiable{nil})(http.NotFoundHandler())
			handler.ServeHTTP(rw, req)

			Expect(rw.Code).To(Equal(http.StatusServiceUnavailable))
			Expect(rw.Body.String()).To(Equal("Shutting down"))
		})

		It("still serves non-readiness requests normally", func() {
			nextCalled := false
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				nextCalled = true
				rw.WriteHeader(http.StatusOK)
				rw.Write([]byte("upstream response"))
			})

			req := httptest.NewRequest("POST", "http://example.com/v1/traces", nil)
			rw := httptest.NewRecorder()

			handler := NewReadynessCheck(cancelledCtx, "/ready", &fakeVerifiable{nil})(next)
			handler.ServeHTTP(rw, req)

			Expect(nextCalled).To(BeTrue())
			Expect(rw.Code).To(Equal(http.StatusOK))
			Expect(rw.Body.String()).To(Equal("upstream response"))
		})

		It("does not leak shutdown status to arbitrary paths", func() {
			paths := []string{
				"http://example.com/",
				"http://example.com/v1/traces",
				"http://example.com/api/data",
				"http://example.com/oauth2/callback",
			}

			for _, path := range paths {
				rw := httptest.NewRecorder()
				req := httptest.NewRequest("GET", path, nil)

				handler := NewReadynessCheck(cancelledCtx, "/ready", &fakeVerifiable{nil})(
					http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
						rw.WriteHeader(http.StatusOK)
					}),
				)
				handler.ServeHTTP(rw, req)

				Expect(rw.Code).To(Equal(http.StatusOK), "path %s should not get 503 during shutdown", path)
			}
		})
	})
})

type fakeVerifiable struct {
	mock func(context.Context) error
}

func (v *fakeVerifiable) VerifyConnection(ctx context.Context) error {
	if v.mock != nil {
		return v.mock(ctx)
	}
	return nil
}

var _ Verifiable = (*fakeVerifiable)(nil)
