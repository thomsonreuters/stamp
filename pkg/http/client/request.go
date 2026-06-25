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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"strings"
)

// Request represents an HTTP request with fluent API.
type Request struct {
	client      *Client
	method      string
	url         string
	body        io.Reader
	headers     map[string]string
	queryParams map[string]string
	ctx         context.Context
	insecure    bool
	jsonBody    any
	result      any
}

// SetContext sets the context for this request.
func (r *Request) SetContext(ctx context.Context) *Request {
	r.ctx = ctx
	return r
}

// SetHeader sets a header for this request.
func (r *Request) SetHeader(key, value string) *Request {
	r.headers[key] = value
	return r
}

// SetHeaders sets multiple headers for this request without overriding existing ones.
func (r *Request) SetHeaders(headers map[string]string) *Request {
	maps.Copy(r.headers, headers)
	return r
}

// SetQueryParam sets a query parameter.
func (r *Request) SetQueryParam(key, value string) *Request {
	r.queryParams[key] = value
	return r
}

// SetQueryParams sets multiple query parameters.
func (r *Request) SetQueryParams(params map[string]string) *Request {
	maps.Copy(r.queryParams, params)
	return r
}

// SetAuthToken sets the Bearer token.
func (r *Request) SetAuthToken(token string) *Request {
	if token != "" {
		r.headers["Authorization"] = "Bearer " + token
	}
	return r
}

// SetBasicAuth sets basic authentication.
func (r *Request) SetBasicAuth(username, password string) *Request {
	r.headers["Authorization"] = "Basic " + username + ":" + password
	return r
}

// SetBody sets the raw request body.
func (r *Request) SetBody(body any) *Request {
	switch v := body.(type) {
	case io.Reader:
		r.body = v
	case []byte:
		r.body = bytes.NewReader(v)
	case string:
		r.body = strings.NewReader(v)
	default:
		r.jsonBody = body
	}
	return r
}

// SetJSON sets JSON body and appropriate headers.
func (r *Request) SetJSON(body any) *Request {
	r.jsonBody = body
	r.headers["Content-Type"] = "application/json"
	r.headers["Accept"] = "application/json"
	return r
}

// SetResult sets where to unmarshal the response (auto-unmarshal).
func (r *Request) SetResult(result any) *Request {
	r.result = result
	return r
}

// SetInsecure allows insecure HTTPS (skip TLS verification).
func (r *Request) SetInsecure(insecure bool) *Request {
	r.insecure = insecure
	return r
}

// HTTP Method Execution

// Get executes a GET request.
func (r *Request) Get(url string) (*Response, error) {
	return r.Execute(http.MethodGet, url)
}

// Post executes a POST request.
func (r *Request) Post(url string) (*Response, error) {
	return r.Execute(http.MethodPost, url)
}

// Put executes a PUT request.
func (r *Request) Put(url string) (*Response, error) {
	return r.Execute(http.MethodPut, url)
}

// Delete executes a DELETE request.
func (r *Request) Delete(url string) (*Response, error) {
	return r.Execute(http.MethodDelete, url)
}

// Patch executes a PATCH request.
func (r *Request) Patch(url string) (*Response, error) {
	return r.Execute(http.MethodPatch, url)
}

// Head executes a HEAD request.
func (r *Request) Head(url string) (*Response, error) {
	return r.Execute(http.MethodHead, url)
}

// Options executes an OPTIONS request.
func (r *Request) Options(url string) (*Response, error) {
	return r.Execute(http.MethodOptions, url)
}

// Execute performs the request with specified method and URL.
func (r *Request) Execute(method, url string) (*Response, error) {
	r.method = method
	r.url = url

	resp, err := r.client.execute(r)
	if err != nil {
		return nil, err
	}

	if r.result != nil && resp.IsSuccess() {
		if jsonErr := resp.JSON(r.result); jsonErr != nil {
			return resp, jsonErr
		}
	}

	return resp, nil
}

// prepareBody prepares the request body.
func (r *Request) prepareBody() error {
	if r.body != nil {
		return nil
	}

	if r.jsonBody != nil {
		data, err := json.Marshal(r.jsonBody)
		if err != nil {
			return err
		}
		r.body = bytes.NewReader(data)
	}

	return nil
}
