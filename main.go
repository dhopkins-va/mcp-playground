package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
)

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

// Tool structure as defined in the MCP specification
type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// Tools list result structure
type ToolsListResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

func main() {
	mcpUrl := "https://mcp.atlassian.com/v1/sse"
	//Discover the authorization server
	mcpClient := CreateMcpClient(mcpUrl, 8090)
	err := mcpClient.discoverAuthorizationServer()
	if err != nil {
		log.Fatalf("Failed to discover authorization server: %v", err)
	}

	//Register an OAuth2 client
	err = mcpClient.registerOAuth2Client()
	if err != nil {
		log.Fatalf("Failed to register OAuth2 client: %v", err)
	}

	//Get an OAuth2 Token
	err = mcpClient.getOAuth2Token()
	if err != nil {
		log.Fatalf("Failed to get OAuth2 token: %v", err)
	}

	// Connect to SSE and wait for endpoint event
	ctx := context.Background()
	endpoint, err := mcpClient.ConnectSSE(ctx, "1234")
	if err != nil {
		log.Fatalf("Failed to connect to SSE or receive endpoint: %v", err)
	}
	fmt.Printf("Received endpoint from SSE: %s\n", endpoint)

	//Initialize the MCP server using the endpoint from SSE
	err = mcpClient.initialize()
	if err != nil {
		log.Fatalf("Failed to initialize MCP server: %v", err)
	}

	tools, err := mcpClient.listMCPServerTools()
	if err != nil {
		log.Fatalf("Failed to list tools: %v", err)
	}
	fmt.Printf("Tools: %+v\n", tools)

	// Keep the program running to receive SSE events
	fmt.Println("Waiting for SSE events... (Press Ctrl+C to exit)")
	select {} // Block forever
}
