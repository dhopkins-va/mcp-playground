package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	McpToolScope       = "mcp:tools"
	McpProtocolVersion = "2025-11-06"
	TransportSSE       = TransportType("sse")
	TransportHTTP      = TransportType("http")
	TransportDiscover  = TransportType("discover")
)

type TransportType string

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

// JSON-RPC request structure
type RPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// JSON-RPC response structure
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// Error structure
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Client struct {
	mcpUrl          string
	port            int
	authServerInfo  *McpAuthorizationServerInfo
	clientInfo      *ClientRegistrationResponse
	token           *oauth2.Token
	codeVerifier    string // PKCE code verifier
	codeChallenge   string // PKCE code challenge
	events          map[int]string
	endpoint        string          // Endpoint URL received from SSE
	lastSSEEvent    time.Time       // Timestamp of the last SSE event received
	lastSSEEventMu  sync.RWMutex    // Mutex to protect lastSSEEvent
	transport       TransportType   // The transport to use
	useSSE          bool            // Whether to use SSE
	sseReady        bool            // Whether SSE is actively listening
	sseReadyMu      sync.RWMutex    // Mutex to protect sseReady
	messageChan     chan []byte     // Channel for receiving message events from SSE
	idCounter       int             // Counter for JSON-RPC request IDs
	idCounterMu     sync.Mutex      // Mutex to protect idCounter
	serverVersion   string          // Server's MCP protocol version
	serverVersionMu sync.RWMutex    // Mutex to protect serverVersion
	sessionId       string          // Session ID
	tools           map[string]Tool // Map of tools indexed by name
	toolsMu         sync.RWMutex    // Mutex to protect tools map
}

func CreateClient(mcpUrl string, port int, transport TransportType) *Client {
	var useSSE bool
	var endpoint string
	if transport == TransportSSE {
		useSSE = true
		endpoint = ""
	} else {
		endpoint = mcpUrl
	}

	return &Client{
		mcpUrl:      mcpUrl,
		port:        port,
		transport:   transport,
		endpoint:    endpoint,
		events:      make(map[int]string),
		useSSE:      useSSE,
		messageChan: make(chan []byte),     // Blocking channel for message events
		idCounter:   0,                     // Start IDs at 0, first call will return 1
		tools:       make(map[string]Tool), // Initialize tools map
	}
}

// nextID returns the next available ID for JSON-RPC requests and increments the counter
func (c *Client) nextID() int {
	c.idCounterMu.Lock()
	defer c.idCounterMu.Unlock()
	c.idCounter++
	return c.idCounter
}

// SetAccessToken sets the access token directly, bypassing OAuth discovery and token exchange
func (c *Client) SetAccessToken(accessToken string) {
	c.token = &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}
}

func (c *Client) Initialize() error {
	//Connect to SSE if it's explicitly specified and not ready
	if c.useSSE && !c.sseReady {
		_, err := c.ConnectSSE(context.Background(), "1234")
		if err != nil {
			return fmt.Errorf("failed to connect to SSE: %v", err)
		}
	}

	request := InitializeRequest{
		JSONRPC: "2.0",
		ID:      c.nextID(),
		Method:  "initialize",
		Params: InitializeParams{
			ProtocolVersion: McpProtocolVersion,
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

	req, err := http.NewRequest(http.MethodPost, initRequestUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json, text/event-stream")
	req.Header.Set("mcp-protocol-version", McpProtocolVersion)
	req.Header.Add("authorization", fmt.Sprintf("Bearer %s", c.token.AccessToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	var body []byte
	switch resp.StatusCode {
	case http.StatusOK:
		body, _ = io.ReadAll(resp.Body)
		c.sessionId = resp.Header.Get("mcp-session-id")
	case http.StatusAccepted:
		if !c.useSSE {
			return fmt.Errorf("Unexpected intialization respoonse: 202 Accepted, but SSE is not forced")
		}
		fmt.Printf("Received 202 Accepted, waiting for message from SSE stream...\n")
		select {
		case msg := <-c.messageChan:
			body = []byte(msg)
		case <-time.After(30 * time.Second):
			return fmt.Errorf("timeout waiting for message from SSE stream")
		}
	case http.StatusNotFound:
		if !c.useSSE {
			c.useSSE = true
			return c.Initialize()
		}
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("Received Initialize Response: %s\n", string(body))
	// Parse the body into the InitializeResponse structure
	var initializeResponse InitializeResponse
	if err := json.Unmarshal(body, &initializeResponse); err != nil {
		return fmt.Errorf("failed to unmarshal initialize response: %v", err)
	}

	// Store the server's MCP protocol version
	c.serverVersion = initializeResponse.Result.ProtocolVersion
	return nil
}
