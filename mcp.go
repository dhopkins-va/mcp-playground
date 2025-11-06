package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	McpToolScope = "mcp:tools"
)

type InitializeRequest struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      int              `json:"id"`
	Method  string           `json:"method"`
	Params  InitializeParams `json:"params"`
}

type InitializeParams struct {
	//SessionID       string       `json:"sessionId"`
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ClientInfo      ClientInfo   `json:"clientInfo"`
}

type Capabilities struct {
	Roots Roots `json:"roots"`
}

type Roots struct {
	ListChanged bool `json:"listChanged"`
}

type ClientInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Version string `json:"version"`
}

type InitializeResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      int              `json:"id"`
	Result  InitializeResult `json:"result"`
}

type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ClientInfo   `json:"serverInfo"`
	Instructions    string       `json:"instructions"`
}
type McpAuthorizationServerInfo struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	RegistrationEndpoint   string   `json:"registration_endpoint"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	ResponseModesSupported []string `json:"response_modes_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
}

type ClientMetadata struct {
	ApplicationType         string   `json:"application_type,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"` // e.g. "none" for SPA/native (PKCE) or "client_secret_basic"
}

type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type McpClient struct {
	mcpUrl         string
	port           int
	authServerInfo *McpAuthorizationServerInfo
	clientInfo     *ClientRegistrationResponse
	token          *oauth2.Token
	codeVerifier   string // PKCE code verifier
	codeChallenge  string // PKCE code challenge
	events         map[int]string
	endpoint       string       // Endpoint URL received from SSE
	lastSSEEvent   time.Time    // Timestamp of the last SSE event received
	lastSSEEventMu sync.RWMutex // Mutex to protect lastSSEEvent
}

func CreateMcpClient(mcpUrl string, port int) *McpClient {
	return &McpClient{
		mcpUrl: mcpUrl,
		port:   port,
		events: make(map[int]string),
	}
}

func (c *McpClient) discoverAuthorizationServer() error {
	u, err := url.Parse(c.mcpUrl)
	if err != nil {
		return fmt.Errorf("failed to parse MCP URL: %v", err)
	}

	wellknownUrl := fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server", u.Scheme, u.Host)

	response, err := http.Get(wellknownUrl)
	if err != nil {
		return fmt.Errorf("failed to get well-known URL: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	var data McpAuthorizationServerInfo
	err = json.Unmarshal(body, &data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body: %v", err)
	}

	c.authServerInfo = &data
	return nil
}

// Dynamically register an OAuth2 Client using the discovered registration_endpoint
func (c *McpClient) registerOAuth2Client() error {
	///Discover (if necessary)
	if c.authServerInfo == nil {
		err := c.discoverAuthorizationServer()
		if err != nil {
			return fmt.Errorf("failed to discover authorization server: %v", err)
		}
	}

	meta := ClientMetadata{
		ApplicationType: "web",
		ClientName:      "MCP Playground",
		RedirectURIs: []string{
			fmt.Sprintf("http://localhost:%d/oauth2/callback", c.port),
		},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none", // PKCE doesn't require client secret
	}

	jsonData, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.authServerInfo.RegistrationEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to register OAuth2 client: %s", response.Status)
	}

	var data ClientRegistrationResponse
	err = json.NewDecoder(response.Body).Decode(&data)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	c.clientInfo = &data
	return nil
}

func (c *McpClient) getOAuth2Token() error {
	if c.clientInfo == nil {
		err := c.registerOAuth2Client()
		if err != nil {
			return fmt.Errorf("failed to register OAuth2 client: %v", err)
		}
	}

	// Check if authorization_code grant type is supported
	supportsAuthCode := false
	for _, grantType := range c.authServerInfo.GrantTypesSupported {
		if grantType == "authorization_code" {
			supportsAuthCode = true
			break
		}
	}

	if !supportsAuthCode {
		return fmt.Errorf("authorization_code grant type is not supported by the server")
	}

	// Start a local server to receive the authorization code
	redirectURL := fmt.Sprintf("http://localhost:%d/oauth2/callback", c.port)
	codeChan := make(chan string, 1)
	errorChan := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			errorMsg := r.URL.Query().Get("error")
			if errorMsg == "" {
				errorMsg = "no authorization code received"
			}
			errorChan <- fmt.Errorf("authorization failed: %s", errorMsg)
			http.Error(w, "Authorization failed", http.StatusBadRequest)
			return
		}

		codeChan <- code
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Authorization successful! You can close this window."))
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", c.port),
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errorChan <- fmt.Errorf("failed to start local server: %v", err)
		}
	}()

	// Generate PKCE code verifier and challenge
	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		return fmt.Errorf("failed to generate PKCE parameters: %v", err)
	}
	c.codeVerifier = codeVerifier
	c.codeChallenge = codeChallenge

	// Create OAuth2 config
	config := &oauth2.Config{
		ClientID:     c.clientInfo.ClientID,
		ClientSecret: "", // No client secret for PKCE flow
		Endpoint: oauth2.Endpoint{
			AuthURL:  c.authServerInfo.AuthorizationEndpoint,
			TokenURL: c.authServerInfo.TokenEndpoint,
		},
		RedirectURL: redirectURL,
		Scopes:      []string{McpToolScope},
	}

	// Generate state parameter for security
	state := fmt.Sprintf("%d", 12345)

	// Build authorization URL using oauth2.Config with PKCE parameters
	authURL := config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// Open the authorization URL in the user's browser
	fmt.Printf("Open the following URL in your browser to authorize the client: %s\n", authURL)

	// Wait for either the authorization code or an error
	var authCode string
	select {
	case authCode = <-codeChan:
		// Success - we got the authorization code
	case err := <-errorChan:
		server.Close()
		return fmt.Errorf("failed to get authorization code: %v", err)
	}

	// Close the local server
	server.Close()

	// Exchange the authorization code for an access token using PKCE
	fmt.Printf("Authorization code: %s\n", authCode)

	// Use oauth2.Config.Exchange with PKCE code_verifier
	ctx := context.Background()
	token, err := config.Exchange(ctx, authCode,
		oauth2.SetAuthURLParam("code_verifier", c.codeVerifier),
	)
	if err != nil {
		return fmt.Errorf("failed to exchange authorization code for token: %v", err)
	}

	fmt.Printf("Token: %+v\n", token)
	c.token = token
	return nil
}

// generatePKCE generates a code verifier and code challenge for PKCE
func generatePKCE() (verifier string, challenge string, err error) {
	// Generate a random code verifier (43-128 characters, URL-safe base64)
	// RFC 7636 recommends 43 characters minimum
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	// Create code challenge by SHA256 hashing the verifier and base64url encoding
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge, nil
}

func (c *McpClient) initialize() error {
	request := InitializeRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: InitializeParams{
			ProtocolVersion: "2025-11-06",
			Capabilities:    Capabilities{},
			ClientInfo: ClientInfo{
				Name:    "MCP Playground",
				Title:   "MCP Playground",
				Version: "1.0.0",
			},
		},
	}
	fmt.Printf("Sending Initialize Request\n")
	requestBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	initRequestUrl := c.endpoint
	if initRequestUrl == "" {
		return fmt.Errorf("endpoint not set, call ConnectSSE first")
	}
	fmt.Printf("Init Request URL: %s\n", initRequestUrl)

	req, err := http.NewRequest(http.MethodPost, initRequestUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	req.Header.Add("authorization", fmt.Sprintf("Bearer %s", c.token.AccessToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("Waiting for 10 seconds...\n")
	time.Sleep(10 * time.Second)
	// //TODO: Read the response from the SSE stream
	// err = c.GetEvent(1)
	// if err != nil {
	// 	return fmt.Errorf("failed to get event: %v", err)
	// }
	return nil
}

func (c *McpClient) GetEvent(id int) error {
	return nil
}

func (c *McpClient) listMCPServerTools() ([]Tool, error) {
	// Create the JSON-RPC request payload
	request := RPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
	}

	// Marshal the request into JSON
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Use the endpoint received from SSE
	if c.endpoint == "" {
		return nil, fmt.Errorf("endpoint not set, call ConnectSSE first")
	}

	// Send the HTTP POST request
	req, err := http.NewRequest(http.MethodPost, c.endpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Add("authorization", fmt.Sprintf("Bearer %s", c.token.AccessToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(body))
	}

	// Read and unmarshal the response
	var rpcResponse RPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// Check for errors in the response
	if rpcResponse.Error != nil {
		return nil, fmt.Errorf("RPC error (code %d): %s", rpcResponse.Error.Code, rpcResponse.Error.Message)
	}

	// Unmarshal the result into the ToolsListResult structure
	var result ToolsListResult
	if err := json.Unmarshal(rpcResponse.Result, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal result: %v", err)
	}
	fmt.Printf("Tools: %+v\n", result.Tools)

	return result.Tools, nil
}

// DumpEvent is an event handler that dumps received events to stdout
func (c *McpClient) DumpEvent(data string) error {
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

// GetLastSSEEvent returns the timestamp of the last SSE event received
func (c *McpClient) GetLastSSEEvent() time.Time {
	c.lastSSEEventMu.RLock()
	defer c.lastSSEEventMu.RUnlock()
	return c.lastSSEEvent
}

// ConnectSSE connects to the MCP server via SSE and blocks until it receives an "endpoint" event
// It returns the endpoint URL that should be used for subsequent requests
func (c *McpClient) ConnectSSE(ctx context.Context, sessionID string) (string, error) {
	if c.token == nil {
		return "", fmt.Errorf("no access token available, call getOAuth2Token() first")
	}

	// Create a channel to wait for endpoint event
	sessionIDChan := make(chan error, 1)

	go func() {
		// Build the SSE endpoint URL
		sseURL := c.mcpUrl //+ "?sessionId=" + sessionID

		// Create HTTP request
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, sseURL, nil)
		if err != nil {
			sessionIDChan <- fmt.Errorf("failed to create SSE request: %v", err)
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
			sessionIDChan <- fmt.Errorf("failed to connect to SSE endpoint: %v", err)
			return
		}
		defer resp.Body.Close()

		// Check response status
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			sessionIDChan <- fmt.Errorf("SSE connection failed with status %d: %s", resp.StatusCode, string(body))
			return
		}

		// Ensure we're receiving SSE content
		contentType := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "text/event-stream") {
			sessionIDChan <- fmt.Errorf("unexpected content type: %s, expected text/event-stream", contentType)
			return
		}

		fmt.Printf("Connected to SSE stream. Waiting for endpoint event...\n")

		// Read SSE events
		scanner := bufio.NewScanner(resp.Body)
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

					fmt.Printf("Event: %s\n", data)
					fmt.Printf("Event JSON: %+v\n", eventJSON)

					// Check if this is an "endpoint" event
					// Try multiple ways to detect and extract the endpoint
					method, hasMethod := eventJSON["method"].(string)
					eventType, hasEventType := eventJSON["event"].(string)

					// Debug: print what we're checking
					fmt.Printf("Checking for endpoint: method=%v (hasMethod=%v), eventType=%v (hasEventType=%v)\n",
						method, hasMethod, eventType, hasEventType)

					// Check if method is "endpoint" or event type is "endpoint"
					isEndpointEvent := (hasMethod && method == "endpoint") || (hasEventType && eventType == "endpoint")

					// Also check if the event has an endpoint field directly (might be a notification)
					if endpoint, ok := eventJSON["endpoint"].(string); ok && endpoint != "" {
						c.endpoint = endpoint
						fmt.Printf("Received endpoint (direct field): %s\n", endpoint)
						sessionIDChan <- nil
					}

					if isEndpointEvent {
						var endpointStr string
						// For endpoint events, the endpoint might be in the data field
						if dataStr, ok := eventJSON["data"].(string); ok && dataStr != "" {
							endpointStr = dataStr
						} else if data != "" && !strings.HasPrefix(strings.TrimSpace(data), "{") {
							// Data is not JSON, it's likely the endpoint URL itself
							endpointStr = strings.TrimSpace(data)
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
							fmt.Printf("Received endpoint: %s\n", c.endpoint)
							sessionIDChan <- nil
						}
						// Extract endpoint from params
						if params, ok := eventJSON["params"].(map[string]interface{}); ok {
							if endpoint, ok := params["endpoint"].(string); ok && endpoint != "" {
								c.endpoint = endpoint
								fmt.Printf("Received endpoint (from params): %s\n", endpoint)
								sessionIDChan <- nil
							}
						}
						// Or check in result
						if result, ok := eventJSON["result"].(map[string]interface{}); ok {
							if endpoint, ok := result["endpoint"].(string); ok && endpoint != "" {
								c.endpoint = endpoint
								fmt.Printf("Received endpoint (from result): %s\n", endpoint)
								sessionIDChan <- nil
							}
						}
						// Or check if result is a string (the endpoint itself)
						if result, ok := eventJSON["result"].(string); ok && result != "" {
							c.endpoint = result
							fmt.Printf("Received endpoint (result as string): %s\n", result)
							sessionIDChan <- nil
						}
					}

					// Call the handler for non-endpoint events
					c.DumpEvent(data)

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
				sessionIDChan <- ctx.Err()
				return
			default:
			}
		}

		// Check for scanner errors
		if err := scanner.Err(); err != nil {
			sessionIDChan <- fmt.Errorf("error reading SSE stream: %v", err)
			return
		}

		// If we get here, the stream ended without receiving an endpoint
		sessionIDChan <- fmt.Errorf("SSE stream ended without receiving endpoint event")
	}()

	err := <-sessionIDChan
	if err != nil {
		return "", err
	}

	// Verify endpoint was set
	if c.endpoint == "" {
		return "", fmt.Errorf("endpoint was not set")
	}

	return c.endpoint, nil
}
