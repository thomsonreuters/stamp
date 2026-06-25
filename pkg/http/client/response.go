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
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"

	pkgerrors "github.com/thomsonreuters/stamp/pkg/errors"
)

// Response represents an HTTP response.
type Response struct {
	request     *Request
	rawResponse *http.Response

	body       io.ReadCloser
	bodyBytes  []byte
	statusCode int
	status     string
	header     http.Header
	duration   time.Duration
}

// Status returns the HTTP status string.
func (r *Response) Status() string {
	return r.status
}

// StatusCode returns the HTTP status code.
func (r *Response) StatusCode() int {
	return r.statusCode
}

// Header returns the response headers.
func (r *Response) Header() http.Header {
	return r.header
}

// Duration returns the request duration.
func (r *Response) Duration() time.Duration {
	return r.duration
}

// IsSuccess returns true if status code is 2xx.
func (r *Response) IsSuccess() bool {
	return r.statusCode >= 200 && r.statusCode < 300
}

// IsError returns true if status code is 4xx or 5xx.
func (r *Response) IsError() bool {
	return r.statusCode >= http.StatusBadRequest
}

// String returns the response body as a string.
func (r *Response) String() (string, error) {
	body, err := r.Bytes()
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// Bytes returns the response body as bytes.
func (r *Response) Bytes() ([]byte, error) {
	if r.bodyBytes != nil {
		return r.bodyBytes, nil
	}

	if r.body == nil {
		return nil, pkgerrors.NewWithContext("http_response", "read_body",
			"response body is nil")
	}

	defer func() { _ = r.body.Close() }()

	body, err := io.ReadAll(r.body)
	if err != nil {
		return nil, pkgerrors.WrapWithContext(err, "http_response", "read_body",
			"failed to read response body")
	}

	r.bodyBytes = body
	return body, nil
}

// JSON unmarshals the response body as JSON.
func (r *Response) JSON(v any) error {
	body, err := r.Bytes()
	if err != nil {
		return err
	}

	if unmarshalErr := json.Unmarshal(body, v); unmarshalErr != nil {
		return pkgerrors.WrapWithContext(unmarshalErr, "http_response", "unmarshal_json",
			"failed to unmarshal JSON response")
	}

	return nil
}

// XML unmarshals the response body as XML.
func (r *Response) XML(v any) error {
	body, err := r.Bytes()
	if err != nil {
		return err
	}

	if unmarshalErr := xml.Unmarshal(body, v); unmarshalErr != nil {
		return pkgerrors.WrapWithContext(unmarshalErr, "http_response", "unmarshal_xml",
			"failed to unmarshal XML response")
	}

	return nil
}

// Close closes the response body.
func (r *Response) Close() error {
	if r.body != nil {
		return r.body.Close()
	}
	return nil
}

// Cookies returns all cookies from the response.
func (r *Response) Cookies() []*http.Cookie {
	if r.rawResponse != nil {
		return r.rawResponse.Cookies()
	}
	return nil
}

// GetHeader returns a header value.
func (r *Response) GetHeader(key string) string {
	return r.header.Get(key)
}

// ContentType returns the Content-Type header.
func (r *Response) ContentType() string {
	return r.GetHeader("Content-Type")
}

// ContentLength returns the Content-Length.
func (r *Response) ContentLength() int64 {
	if r.rawResponse != nil {
		return r.rawResponse.ContentLength
	}
	return 0
}

// Error returns an error if the response indicates failure.
func (r *Response) Error() error {
	if r.IsError() {
		body, _ := r.String()
		return fmt.Errorf("HTTP %d: %s - %s", r.statusCode, r.status, body)
	}
	return nil
}

// RawResponse returns the underlying *http.Response.
func (r *Response) RawResponse() *http.Response {
	return r.rawResponse
}
