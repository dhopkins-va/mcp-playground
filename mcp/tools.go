package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Tools list result structure
type ToolsListResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// Tool represents a single tool in the MCP tools list
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
	Annotations Annotations `json:"annotations"`
}

// InputSchema represents the JSON schema for tool input parameters
type InputSchema struct {
	Type                 string              `json:"type"`
	Properties           map[string]Property `json:"properties"`
	Required             []string            `json:"required,omitempty"`
	AdditionalProperties bool                `json:"additionalProperties"`
	Schema               string              `json:"$schema"`
}

// Property represents a single property in the input schema
type Property struct {
	Type                 string              `json:"type,omitempty"`
	Description          string              `json:"description,omitempty"`
	Enum                 []string            `json:"enum,omitempty"`
	Default              interface{}         `json:"default,omitempty"`
	Items                *Items              `json:"items,omitempty"`
	AnyOf                []AnyOf             `json:"anyOf,omitempty"`
	Properties           map[string]Property `json:"properties,omitempty"`
	Required             []string            `json:"required,omitempty"`
	AdditionalProperties interface{}         `json:"additionalProperties,omitempty"`
	Maximum              *int                `json:"maximum,omitempty"`
}

// Items represents the items type for array properties
type Items struct {
	Type string `json:"type"`
}

// AnyOf represents alternative types for a property
type AnyOf struct {
	Type  string `json:"type,omitempty"`
	Items *Items `json:"items,omitempty"`
}

// Annotations represents tool metadata and hints
type Annotations struct {
	Title           string `json:"title"`
	ReadOnlyHint    bool   `json:"readOnlyHint"`
	DestructiveHint bool   `json:"destructiveHint"`
	IdempotentHint  bool   `json:"idempotentHint"`
	OpenWorldHint   bool   `json:"openWorldHint"`
}

// ToolsResult represents the result structure containing tools
type ToolsResult struct {
	Tools []Tool `json:"tools"`
}

func (c *Client) ListTools() ([]Tool, error) {
	// Create the JSON-RPC request payload
	request := RPCRequest{
		JSONRPC: "2.0",
		ID:      c.nextID(),
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
		break
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

	fmt.Printf("%d tools found\n", len(result.Tools))
	for _, tool := range result.Tools {
		fmt.Printf(" - %s: %s\n", tool.Name, tool.Description)
	}
	return result.Tools, nil
}
