package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	idCounter      int          // Counter for JSON-RPC request IDs
	idCounterMu    sync.Mutex   // Mutex to protect idCounter
}

func CreateClient(mcpUrl string, port int, useSSE bool) *Client {
	return &Client{
		mcpUrl:      mcpUrl,
		port:        port,
		events:      make(map[int]string),
		useSSE:      useSSE,
		messageChan: make(chan []byte), // Blocking channel for message events
		idCounter:   0,                 // Start IDs at 0, first call will return 1
	}
}

// nextID returns the next available ID for JSON-RPC requests and increments the counter
func (c *Client) nextID() int {
	c.idCounterMu.Lock()
	defer c.idCounterMu.Unlock()
	c.idCounter++
	return c.idCounter
}

func (c *Client) Initialize() error {
	request := InitializeRequest{
		JSONRPC: "2.0",
		ID:      c.nextID(),
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
	case <-c.messageChan:
		break
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timeout waiting for message from SSE stream")
	}
	return nil
}
