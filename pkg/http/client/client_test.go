// Copyright 2026 Thomson Reuters
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thomsonreuters/stamp/pkg/logger"
	"golang.org/x/sync/errgroup"
)

// CLIENT TESTS

func TestNew(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	require.NotNil(t, client)
	assert.NotNil(t, client.httpClient)
	assert.NotNil(t, client.insecureClient)
	assert.NotEmpty(t, client.userAgent)
	assert.NotNil(t, client.headers)
}

func TestClient_SetBaseURL(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	url := "https://api.example.com"
	result := client.SetBaseURL(url)

	assert.Equal(t, client, result, "SetBaseURL should return client for chaining")
	assert.Equal(t, url, client.baseURL)
}

func TestClient_SetTimeout(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	timeout := 60 * time.Second
	result := client.SetTimeout(timeout)

	assert.Equal(t, client, result, "SetTimeout should return client for chaining")
	assert.Equal(t, timeout, client.httpClient.Timeout)
	assert.Equal(t, timeout, client.insecureClient.Timeout)
}

func TestClient_SetUserAgent(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	ua := "test-agent/1.0"
	result := client.SetUserAgent(ua)

	assert.Equal(t, client, result, "SetUserAgent should return client for chaining")
	assert.Equal(t, ua, client.userAgent)
}

func TestClient_SetHeader(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	key, value := "X-Custom", "value"
	result := client.SetHeader(key, value)

	assert.Equal(t, client, result, "SetHeader should return client for chaining")
	assert.Equal(t, value, client.headers[key])
}

func TestClient_SetHeaders(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	client.SetHeader("X-Existing", "value1")

	headers := map[string]string{
		"X-Custom1":  "value1",
		"X-Custom2":  "value2",
		"X-Existing": "overridden",
	}

	result := client.SetHeaders(headers)

	assert.Equal(t, client, result, "SetHeaders should return client for chaining")
	for k, v := range headers {
		assert.Equal(t, v, client.headers[k])
	}
}

func TestClient_SetAuthToken(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	token := "test-token-123"
	client.SetAuthToken(token)

	expected := "Bearer " + token
	assert.Equal(t, expected, client.headers["Authorization"])
}

func TestClient_SetDebug(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	result := client.SetDebug(true)

	assert.Equal(t, client, result, "SetDebug should return client for chaining")
	assert.True(t, client.debug)
}

func TestClient_SetTLSClientConfig(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	result := client.SetTLSClientConfig(config)

	assert.Equal(t, client, result, "SetTLSClientConfig should return client for chaining")
	transport, ok := client.httpClient.Transport.(*http.Transport)
	require.True(t, ok, "Transport should be *http.Transport")
	assert.Equal(t, uint16(tls.VersionTLS13), transport.TLSClientConfig.MinVersion)
}

func TestClient_ChainedConfiguration(t *testing.T) {
	client := New(&logger.Noop{}).
		SetBaseURL("https://api.example.com").
		SetTimeout(30*time.Second).
		SetUserAgent("test/1.0").
		SetHeader("Accept", "application/json").
		SetDebug(true)
	defer client.Close()

	assert.Equal(t, "https://api.example.com", client.baseURL)
	assert.Equal(t, "test/1.0", client.userAgent)
	assert.True(t, client.debug)
}

func TestClient_R(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	client.SetHeader("X-Client", "value")
	req := client.R()

	require.NotNil(t, req)
	assert.Equal(t, client, req.client)
	assert.Equal(t, "value", req.headers["X-Client"])
	assert.NotNil(t, req.ctx)
}

func TestClient_SimpleGET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, World!"))
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode())

	body, err := resp.String()
	require.NoError(t, err)
	assert.Equal(t, "Hello, World!", body)
}

func TestClient_WithBaseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/users", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{}).SetBaseURL(server.URL)
	defer client.Close()

	resp, err := client.R().Get("/users")
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode())
}

func TestClient_Close(t *testing.T) {
	client := New(&logger.Noop{})

	assert.NotPanics(t, func() {
		client.Close()
		client.Close()
	})
}

func TestClient_BuildURL_InvalidURL(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	_, err := client.buildURL("http://invalid url with space", map[string]string{"key": "value"})
	assert.Error(t, err)
}

func TestClient_BuildURL_WithQueryParams(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	url, err := client.buildURL("https://api.example.com/users", map[string]string{
		"page":  "1",
		"limit": "10",
	})

	require.NoError(t, err)
	assert.Contains(t, url, "page=1")
	assert.Contains(t, url, "limit=10")
}

func TestClient_BuildURL_WithBaseURL(t *testing.T) {
	client := New(&logger.Noop{}).SetBaseURL("https://api.example.com")
	defer client.Close()

	url, err := client.buildURL("/users", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com/users", url)

	url, err = client.buildURL("https://other.com/data", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://other.com/data", url)
}

func TestClient_BuildURL_EmptyParams(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	expected := "https://api.example.com/users"

	url, err := client.buildURL(expected, nil)
	require.NoError(t, err)
	assert.Equal(t, expected, url)

	url, err = client.buildURL(expected, map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, expected, url)
}

func TestClient_DebugMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test"))
	}))
	defer server.Close()

	client := New(&logger.Noop{}).SetDebug(true)
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode())
}

func TestClient_UserAgent(t *testing.T) {
	customUA := "custom-agent/2.0"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, customUA, r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{}).SetUserAgent(customUA)
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()
}

func TestClient_DefaultUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()
}

func TestClient_HeadersInheritance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "client-value", r.Header.Get("X-Client-Header"))
		assert.Equal(t, "request-value", r.Header.Get("X-Request-Header"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{}).SetHeader("X-Client-Header", "client-value")
	defer client.Close()

	resp, err := client.R().
		SetHeader("X-Request-Header", "request-value").
		Get(server.URL)

	require.NoError(t, err)
	defer func() { _ = resp.Close() }()
}

func TestClient_InsecureClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().
		SetInsecure(true).
		Get(server.URL)

	require.NoError(t, err)
	defer func() { _ = resp.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode())
}

// REQUEST TESTS

func TestRequest_SetContext(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	req := client.R().SetContext(ctx)
	assert.Equal(t, ctx, req.ctx)
}

func TestRequest_SetHeader(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	req := client.R().SetHeader("X-Test", "value")
	assert.Equal(t, "value", req.headers["X-Test"])
}

func TestRequest_SetHeaders(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	req := client.R().SetHeader("X-Existing", "old")

	headers := map[string]string{
		"X-New":      "value",
		"X-Existing": "new",
	}

	req.SetHeaders(headers)

	assert.Equal(t, "value", req.headers["X-New"])
	assert.Equal(t, "new", req.headers["X-Existing"])
}

func TestRequest_SetQueryParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "1", r.URL.Query().Get("page"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().
		SetQueryParam("page", "1").
		Get(server.URL)

	require.NoError(t, err)
	_ = resp.Close()
}

func TestRequest_SetQueryParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "1", r.URL.Query().Get("page"))
		assert.Equal(t, "10", r.URL.Query().Get("limit"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().
		SetQueryParams(map[string]string{
			"page":  "1",
			"limit": "10",
		}).
		Get(server.URL)

	require.NoError(t, err)
	_ = resp.Close()
}

func TestRequest_SetAuthToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().
		SetAuthToken("test-token").
		Get(server.URL)

	require.NoError(t, err)
	_ = resp.Close()
}

func TestRequest_SetAuthToken_Empty(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	req := client.R().SetAuthToken("")

	_, exists := req.headers["Authorization"]
	assert.False(t, exists)
}

func TestRequest_SetBasicAuth(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	req := client.R().SetBasicAuth("user", "pass")
	assert.Equal(t, "Basic user:pass", req.headers["Authorization"])
}

func TestRequest_SetBody(t *testing.T) {
	tests := []struct {
		name string
		body any
	}{
		{"string", "test string"},
		{"bytes", []byte("test bytes")},
		{"reader", strings.NewReader("test reader")},
		{"struct", map[string]string{"key": "value"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := New(&logger.Noop{})
			defer client.Close()

			req := client.R().SetBody(tt.body)
			assert.True(t, req.body != nil || req.jsonBody != nil)
		})
	}
}

func TestRequest_SetJSON(t *testing.T) {
	type User struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))

		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if !assert.NoError(t, err, "Failed to decode JSON") {
			return
		}
		assert.Equal(t, "John", user.Name)

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(user)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	user := User{Name: "John", Email: "john@example.com"}

	resp, err := client.R().
		SetJSON(user).
		Post(server.URL)
	defer func() { _ = resp.Close() }()

	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode())
}

func TestRequest_SetResult(t *testing.T) {
	type User struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		user := User{ID: 1, Name: "John"}
		_ = json.NewEncoder(w).Encode(user)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	var user User

	resp, err := client.R().
		SetResult(&user).
		Get(server.URL)

	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	assert.Equal(t, 1, user.ID)
	assert.Equal(t, "John", user.Name)
}

func TestRequest_SetInsecure(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	req := client.R().SetInsecure(true)
	assert.True(t, req.insecure)
}

func TestRequest_AllHTTPMethods(t *testing.T) {
	methods := []struct {
		name   string
		method string
		fn     func(*Request, string) (*Response, error)
	}{
		{"GET", http.MethodGet, (*Request).Get},
		{"POST", http.MethodPost, (*Request).Post},
		{"PUT", http.MethodPut, (*Request).Put},
		{"DELETE", http.MethodDelete, (*Request).Delete},
		{"PATCH", http.MethodPatch, (*Request).Patch},
		{"HEAD", http.MethodHead, (*Request).Head},
		{"OPTIONS", http.MethodOptions, (*Request).Options},
	}

	for _, tt := range methods {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.method, r.Method)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client := New(&logger.Noop{})
			defer client.Close()

			resp, err := tt.fn(client.R(), server.URL)
			require.NoError(t, err)
			defer func() { _ = resp.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode())
		})
	}
}

func TestRequest_ContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	_, err := client.R().
		SetContext(ctx).
		Get(server.URL)

	assert.Error(t, err)
}

func TestRequest_JSONMarshalError(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	invalidData := make(chan int)
	req := client.R().SetJSON(invalidData)

	err := req.prepareBody()
	assert.Error(t, err)
}

func TestRequest_SetResult_NonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": "not found"}`))
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	type User struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}

	var user User

	resp, err := client.R().
		SetResult(&user).
		Get(server.URL)

	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	assert.Equal(t, 0, user.ID)
	assert.Empty(t, user.Name)
}

func TestRequest_Execute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Execute(http.MethodPost, server.URL)
	defer func() { _ = resp.Close() }()

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode())
}

func TestRequest_HeaderOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "request-value", r.Header.Get("X-Header"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{}).SetHeader("X-Header", "client-value")
	defer client.Close()

	resp, err := client.R().
		SetHeader("X-Header", "request-value").
		Get(server.URL)

	defer func() { _ = resp.Close() }()

	require.NoError(t, err)
}

func TestRequest_PrepareBody_NoBody(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	req := client.R()
	err := req.prepareBody()

	assert.NoError(t, err)
}

// RESPONSE TESTS

func TestResponse_Status(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		isSuccess  bool
		isError    bool
	}{
		{"200 OK", 200, true, false},
		{"201 Created", 201, true, false},
		{"204 No Content", 204, true, false},
		{"400 Bad Request", 400, false, true},
		{"404 Not Found", 404, false, true},
		{"500 Internal Server Error", 500, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			client := New(&logger.Noop{})
			defer client.Close()

			resp, err := client.R().Get(server.URL)
			require.NoError(t, err)
			defer func() { _ = resp.Close() }()

			assert.Equal(t, tt.statusCode, resp.StatusCode())
			assert.Equal(t, tt.isSuccess, resp.IsSuccess())
			assert.Equal(t, tt.isError, resp.IsError())
		})
	}
}

func TestResponse_String(t *testing.T) {
	expected := "test response body"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(expected))
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	body, err := resp.String()
	require.NoError(t, err)
	assert.Equal(t, expected, body)
}

func TestResponse_Bytes(t *testing.T) {
	expected := []byte("test response body")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(expected)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	body, err := resp.Bytes()
	require.NoError(t, err)
	assert.Equal(t, expected, body)
}

//nolint:dupl // similar test structure is intentional for JSON/XML comparison
func TestResponse_JSON(t *testing.T) {
	type User struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		user := User{ID: 1, Name: "John"}
		_ = json.NewEncoder(w).Encode(user)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	var user User
	err = resp.JSON(&user)
	require.NoError(t, err)

	assert.Equal(t, 1, user.ID)
	assert.Equal(t, "John", user.Name)
}

//nolint:dupl // similar test structure is intentional for JSON/XML comparison
func TestResponse_XML(t *testing.T) {
	type User struct {
		ID   int    `xml:"id"`
		Name string `xml:"name"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		user := User{ID: 1, Name: "John"}
		_ = xml.NewEncoder(w).Encode(user)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	var user User
	err = resp.XML(&user)
	require.NoError(t, err)

	assert.Equal(t, 1, user.ID)
	assert.Equal(t, "John", user.Name)
}

func TestResponse_Header(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Custom", "value")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	assert.Equal(t, "value", resp.GetHeader("X-Custom"))
	assert.Equal(t, "application/json", resp.ContentType())
}

func TestResponse_Cookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "abc123",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	cookies := resp.Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "session", cookies[0].Name)
	assert.Equal(t, "abc123", cookies[0].Value)
}

func TestResponse_Duration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	duration := resp.Duration()
	assert.GreaterOrEqual(t, duration, 10*time.Millisecond)
}

func TestResponse_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	respErr := resp.Error()
	require.Error(t, respErr)
	assert.Contains(t, respErr.Error(), "404")
}

func TestResponse_RawResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	rawResp := resp.RawResponse() //nolint:bodyclose // body is managed by Response wrapper
	assert.NotNil(t, rawResp)
	assert.Equal(t, http.StatusOK, rawResp.StatusCode)
}

func TestResponse_BodyReadError(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	resp := &Response{
		body: nil,
	}

	_, err := resp.Bytes()
	require.Error(t, err)

	_, err = resp.String()
	require.Error(t, err)
}

func TestResponse_JSON_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	var result map[string]string
	err = resp.JSON(&result)
	assert.Error(t, err)
}

func TestResponse_XML_InvalidXML(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not valid xml"))
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	type Result struct {
		Name string `xml:"name"`
	}
	var result Result
	err = resp.XML(&result)
	assert.Error(t, err)
}

func TestResponse_ContentLength(t *testing.T) {
	content := "test content"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "12")
		_, _ = w.Write([]byte(content))
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	assert.Equal(t, int64(12), resp.ContentLength())
}

func TestResponse_Status_String(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	status := resp.Status()
	assert.Contains(t, status, "201")
}

func TestResponse_Header_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	header := resp.GetHeader("X-Non-Existent")
	assert.Empty(t, header)
}

func TestResponse_Cookies_NoCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	cookies := resp.Cookies()
	assert.Empty(t, cookies)
}

func TestResponse_Error_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	assert.NoError(t, resp.Error())
}

func TestResponse_Close_MultipleCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test"))
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)

	_, _ = resp.String()

	assert.NotPanics(t, func() {
		_ = resp.Close()
		_ = resp.Close()
		_ = resp.Close()
	})
}

// INTEGRATION TESTS

func TestConcurrentRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	var eg errgroup.Group
	concurrency := 100

	for range concurrency {
		eg.Go(func() error {
			resp, err := client.R().Get(server.URL)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Close() }()

			if resp.StatusCode() != http.StatusOK {
				return fmt.Errorf("expected status %d, got %d", http.StatusOK, resp.StatusCode())
			}
			return nil
		})
	}

	require.NoError(t, eg.Wait())
}

func TestBodyCaching(t *testing.T) {
	expected := "test body"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(expected))
	}))
	defer server.Close()

	client := New(&logger.Noop{})
	defer client.Close()

	resp, err := client.R().Get(server.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Close() }()

	body1, _ := resp.String()
	body2, _ := resp.String()
	bytes1, _ := resp.Bytes()

	assert.Equal(t, expected, body1)
	assert.Equal(t, expected, body2)
	assert.Equal(t, expected, string(bytes1))
}

func TestRequestIndependence(t *testing.T) {
	client := New(&logger.Noop{})
	defer client.Close()

	req1 := client.R().SetHeader("X-Test", "value1")
	req2 := client.R().SetHeader("X-Test", "value2")

	assert.NotEqual(t, req1.headers["X-Test"], req2.headers["X-Test"])
}
