package main

import (
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
	useSSE         bool         // Whether to use SSE
	messageChan    chan []byte  // Channel for receiving message events from SSE
}

func CreateMcpClient(mcpUrl string, port int, useSSE bool) *McpClient {
	return &McpClient{
		mcpUrl:      mcpUrl,
		port:        port,
		events:      make(map[int]string),
		useSSE:      useSSE,
		messageChan: make(chan []byte), // Blocking channel for message events
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
	fmt.Printf("Request Body: %s\n", string(requestBody))
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

	fmt.Printf("Received 202 Accepted, waiting for message from SSE stream...\n")

	// Wait for a message from the message channel
	select {
	case message := <-c.messageChan:
		fmt.Printf("Received message from SSE stream: %s\n", string(message))
		// TODO: Parse and handle the message if needed
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timeout waiting for message from SSE stream")
	}
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
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("Received 202 Accepted, waiting for message from SSE stream...\n")

	// Wait for a message from the message channel
	var message []byte
	select {
	case message = <-c.messageChan:
		fmt.Printf("Received message from SSE stream: %s\n", string(message))
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for message from SSE stream")
	}

	// Parse the message as a JSON-RPC response
	var rpcResponse RPCResponse
	if err := json.Unmarshal(message, &rpcResponse); err != nil {
		return nil, fmt.Errorf("failed to decode message response: %v", err)
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

// GetLastSSEEvent returns the timestamp of the last SSE event received
func (c *McpClient) GetLastSSEEvent() time.Time {
	c.lastSSEEventMu.RLock()
	defer c.lastSSEEventMu.RUnlock()
	return c.lastSSEEvent
}
