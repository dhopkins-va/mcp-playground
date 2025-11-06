package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DumpEvent is an event handler that dumps received events to stdout
func (c *Client) DumpEvent(data string) error {
	if data == "" {
		return nil
	}

	// Try to parse as JSON for pretty printing
	var eventJSON map[string]interface{}
	if err := json.Unmarshal([]byte(data), &eventJSON); err == nil {
		eventBytes, err := json.MarshalIndent(eventJSON, "", "  ")
		if err == nil {
			fmt.Printf("Event received:\n%s\n\n", string(eventBytes))
			return nil
		}
	}

	// If not JSON or marshaling failed, just print the raw data
	fmt.Printf("Event received (raw):\n%s\n\n", data)
	return nil
}

// processSSEEvents processes SSE events from the response body, looking for an endpoint event
// It sends nil to the channel when an endpoint is found, or an error if something goes wrong
func (c *Client) processSSEEvents(ctx context.Context, respBody io.ReadCloser, endpointChan chan error) {
	defer respBody.Close()

	scanner := bufio.NewScanner(respBody)
	var eventData strings.Builder
	currentEvent := make(map[string]string)

	for scanner.Scan() {
		line := scanner.Text()

		// Check for SSE comment lines (starting with ':') - these are keep-alives
		if strings.HasPrefix(line, ":") {
			fmt.Printf("Keep-Alive %s\n", time.Now().Format(time.RFC3339))
			continue
		}

		// Empty line indicates end of event
		if line == "" {
			// Check if this is a keep-alive event (empty event or event type is keep-alive)
			eventType, hasEventType := currentEvent["event"]
			if eventData.Len() == 0 && len(currentEvent) == 0 {
				// Empty event - likely a keep-alive
				fmt.Printf("Keep-Alive %s\n", time.Now().Format(time.RFC3339))
				continue
			}

			if hasEventType && (eventType == "keep-alive" || eventType == "keepalive") {
				// This is a keep-alive event, discard it but print the time
				fmt.Printf("Keep-Alive %s\n", time.Now().Format(time.RFC3339))
				eventData.Reset()
				currentEvent = make(map[string]string)
				continue
			}

			if eventData.Len() > 0 || len(currentEvent) > 0 {
				// Update the last SSE event timestamp
				c.lastSSEEventMu.Lock()
				c.lastSSEEvent = time.Now()
				c.lastSSEEventMu.Unlock()

				// Parse the accumulated event data
				data := eventData.String()
				eventData.Reset()

				// Try to parse as JSON
				var eventJSON map[string]interface{}
				if data != "" {
					if err := json.Unmarshal([]byte(data), &eventJSON); err != nil {
						// If not JSON, create a simple map with the data
						eventJSON = make(map[string]interface{})
						eventJSON["data"] = data
					}
				} else {
					eventJSON = make(map[string]interface{})
				}

				// Add other SSE fields to the event
				for k, v := range currentEvent {
					if k != "data" {
						eventJSON[k] = v
					}
				}

				// Check if this is a "message" event
				eventType, hasEventType := eventJSON["event"].(string)
				if hasEventType && eventType == "message" {
					// Send the message data to the message channel
					messageData := []byte(data)
					select {
					case c.messageChan <- messageData:
						// Message sent to channel
					case <-ctx.Done():
						// Context cancelled, don't block
						return
					}
				}

				// Check if this is an "endpoint" event
				endpointFound := c.handleEndpointEvent(eventJSON, data)
				if endpointFound {
					// Signal that endpoint was found, but continue processing events
					// This allows us to receive the lize response and other events
					select {
					case endpointChan <- nil:
						// Channel sent, continue processing
					default:
						// Channel already sent, continue processing
					}
				}

				// Reset for next event
				currentEvent = make(map[string]string)
			}
			continue
		}

		// Parse SSE line format: "field: value"
		// SSE spec allows multiple data lines which should be concatenated with \n
		if strings.HasPrefix(line, "data:") {
			data := strings.TrimPrefix(line, "data:")
			data = strings.TrimSpace(data)
			if eventData.Len() > 0 {
				eventData.WriteString("\n")
			}
			eventData.WriteString(data)
			// Store latest data value (for non-JSON case)
			currentEvent["data"] = eventData.String()
		} else if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				field := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				currentEvent[field] = value
			}
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			endpointChan <- ctx.Err()
			return
		default:
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		endpointChan <- fmt.Errorf("error reading SSE stream: %v", err)
		return
	}

	// If we get here, the stream ended without receiving an endpoint
	endpointChan <- fmt.Errorf("SSE stream ended without receiving endpoint event")
}

// handleEndpointEvent checks if the event is an endpoint event and extracts the endpoint
// Returns true if an endpoint was found and set, false otherwise
func (c *Client) handleEndpointEvent(eventJSON map[string]interface{}, rawData string) bool {
	// Try multiple ways to detect and extract the endpoint
	method, hasMethod := eventJSON["method"].(string)
	eventType, hasEventType := eventJSON["event"].(string)

	// Check if method is "endpoint" or event type is "endpoint"
	isEndpointEvent := (hasMethod && method == "endpoint") || (hasEventType && eventType == "endpoint")

	// Also check if the event has an endpoint field directly (might be a notification)
	if endpoint, ok := eventJSON["endpoint"].(string); ok && endpoint != "" {
		c.endpoint = endpoint
		return true
	}

	if isEndpointEvent {
		var endpointStr string
		// For endpoint events, the endpoint might be in the data field
		if dataStr, ok := eventJSON["data"].(string); ok && dataStr != "" {
			endpointStr = dataStr
		} else if rawData != "" && !strings.HasPrefix(strings.TrimSpace(rawData), "{") {
			// Data is not JSON, it's likely the endpoint URL itself
			endpointStr = strings.TrimSpace(rawData)
		}

		if endpointStr != "" {
			// If endpoint is a relative path, combine it with the base URL
			if strings.HasPrefix(endpointStr, "/") {
				// Parse the base URL to get the scheme and host
				baseURL, err := url.Parse(c.mcpUrl)
				if err == nil {
					// Combine base URL with relative path
					endpointURL, err := url.Parse(endpointStr)
					if err == nil {
						endpointURL.Scheme = baseURL.Scheme
						endpointURL.Host = baseURL.Host
						c.endpoint = endpointURL.String()
					} else {
						// Fallback: just prepend the base URL
						c.endpoint = strings.TrimSuffix(c.mcpUrl, "/v1/sse") + endpointStr
					}
				} else {
					// Fallback: use as-is
					c.endpoint = endpointStr
				}
			} else {
				// Already a full URL
				c.endpoint = endpointStr
			}
			return true
		}
		// Extract endpoint from params
		if params, ok := eventJSON["params"].(map[string]interface{}); ok {
			if endpoint, ok := params["endpoint"].(string); ok && endpoint != "" {
				c.endpoint = endpoint
				return true
			}
		}
		// Or check in result
		if result, ok := eventJSON["result"].(map[string]interface{}); ok {
			if endpoint, ok := result["endpoint"].(string); ok && endpoint != "" {
				c.endpoint = endpoint
				return true
			}
		}
		// Or check if result is a string (the endpoint itself)
		if result, ok := eventJSON["result"].(string); ok && result != "" {
			c.endpoint = result
			return true
		}
	}

	return false
}

// ConnectSSE connects to the MCP server via SSE and blocks until it receives an "endpoint" event
// It returns the endpoint URL that should be used for subsequent requests
func (c *Client) ConnectSSE(ctx context.Context, sessionID string) (string, error) {
	if c.token == nil {
		return "", fmt.Errorf("no access token available, call GetOAuth2Token() first")
	}

	// Create a channel to wait for endpoint event
	endpointChan := make(chan error, 1)

	go func() {
		// Create HTTP request
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.mcpUrl, nil)
		if err != nil {
			endpointChan <- fmt.Errorf("failed to create SSE request: %v", err)
			return
		}

		// Set headers for SSE
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token.AccessToken))

		// Send the request with a client that has no timeout for long-lived SSE connections
		client := &http.Client{
			Timeout: 0, // No timeout for SSE connections
		}
		resp, err := client.Do(req)
		if err != nil {
			endpointChan <- fmt.Errorf("failed to connect to SSE endpoint: %v", err)
			return
		}

		// Check response status
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			endpointChan <- fmt.Errorf("SSE connection failed with status %d: %s", resp.StatusCode, string(body))
			return
		}

		// Ensure we're receiving SSE content
		contentType := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "text/event-stream") {
			resp.Body.Close()
			endpointChan <- fmt.Errorf("unexpected content type: %s, expected text/event-stream", contentType)
			return
		}

		// Process SSE events
		c.processSSEEvents(ctx, resp.Body, endpointChan)
	}()

	err := <-endpointChan
	if err != nil {
		return "", err
	}

	// Verify endpoint was set
	if c.endpoint == "" {
		return "", fmt.Errorf("endpoint was not set")
	}

	return c.endpoint, nil
}

// GetLastSSEEvent returns the timestamp of the last SSE event received
func (c *Client) GetLastSSEEvent() time.Time {
	c.lastSSEEventMu.RLock()
	defer c.lastSSEEventMu.RUnlock()
	return c.lastSSEEvent
}
