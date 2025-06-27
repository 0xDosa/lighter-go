//go:build js && wasm

package client

import (
	"fmt"
	"syscall/js"
	"time"
)

// WASM-specific HTTP client that delegates to JavaScript fetch API
type HTTPClient struct {
	endpoint            string
	channelName         string
	fatFingerProtection bool
}

func NewHTTPClient(baseUrl string) *HTTPClient {
	if baseUrl == "" {
		return nil
	}

	return &HTTPClient{
		endpoint:            baseUrl,
		channelName:         "",
		fatFingerProtection: true,
	}
}

func (c *HTTPClient) SetFatFingerProtection(enabled bool) {
	c.fatFingerProtection = enabled
}

type fetchResult struct {
	body   []byte
	status int
	err    error
}

// wasmFetch makes an HTTP request using JavaScript's fetch API
func wasmFetch(method, url string, headers map[string]string, body string) ([]byte, int, error) {
	// Use fetch API for all environments - modern browsers and Node.js both support it
	return wasmFetchFetch(method, url, headers, body)
}

// wasmFetchFetch uses fetch API (Node.js/modern browsers)
func wasmFetchFetch(method, url string, headers map[string]string, body string) ([]byte, int, error) {
	// Create a result channel
	resultChan := make(chan fetchResult, 1)

	// Get global object
	global := js.Global()

	// Check if fetch is available
	if global.Get("fetch").IsUndefined() {
		return nil, 0, fmt.Errorf("fetch API not available")
	}

	// Create fetch options
	fetchOptions := global.Get("Object").New()
	fetchOptions.Set("method", method)

	// Set headers if provided
	if len(headers) > 0 {
		jsHeaders := global.Get("Object").New()
		for k, v := range headers {
			jsHeaders.Set(k, v)
		}
		fetchOptions.Set("headers", jsHeaders)
	}

	// Set body if provided
	if body != "" {
		fetchOptions.Set("body", body)
	}

	// Make the fetch call directly and handle the promises
	fetchPromise := global.Call("fetch", url, fetchOptions)

	// Handle the response
	responseHandler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		response := args[0]
		status := response.Get("status").Int()

		// Get text from response
		textPromise := response.Call("text")

		// Handle text response
		textHandler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			text := args[0].String()
			resultChan <- fetchResult{
				body:   []byte(text),
				status: status,
				err:    nil,
			}
			return nil
		})
		defer textHandler.Release()

		// Handle text error
		textErrorHandler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			resultChan <- fetchResult{
				body:   nil,
				status: status,
				err:    fmt.Errorf("failed to read response text"),
			}
			return nil
		})
		defer textErrorHandler.Release()

		// Chain text promise
		textPromise.Call("then", textHandler).Call("catch", textErrorHandler)
		return nil
	})
	defer responseHandler.Release()

	// Handle fetch error
	fetchErrorHandler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		errMsg := "fetch error"
		if len(args) > 0 && !args[0].IsUndefined() {
			if args[0].Get("message").Truthy() {
				errMsg = args[0].Get("message").String()
			}
		}
		resultChan <- fetchResult{
			body:   nil,
			status: 0,
			err:    fmt.Errorf("fetch failed: %s", errMsg),
		}
		return nil
	})
	defer fetchErrorHandler.Release()

	// Chain fetch promise
	fetchPromise.Call("then", responseHandler).Call("catch", fetchErrorHandler)

	// Wait for result with timeout
	select {
	case result := <-resultChan:
		return result.body, result.status, result.err
	case <-time.After(30 * time.Second):
		return nil, 0, fmt.Errorf("fetch timeout after 30 seconds")
	}
}
