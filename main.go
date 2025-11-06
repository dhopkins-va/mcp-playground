package main

import (
	"context"
	"log"

	"github.com/dhopkins-va/mcp-playground/mcp"
)

func main() {
	mcpUrl := "https://mcp.atlassian.com/v1/sse"
	//Discover the authorization server
	mcpClient := mcp.CreateClient(mcpUrl, 8090, true)
	err := mcpClient.DiscoverAuthorizationServer()
	if err != nil {
		log.Fatalf("Failed to discover authorization server: %v", err)
	}

	//Register an OAuth2 client
	err = mcpClient.RegisterOAuth2Client()
	if err != nil {
		log.Fatalf("Failed to register OAuth2 client: %v", err)
	}

	//Get an OAuth2 Token
	err = mcpClient.GetOAuth2Token()
	if err != nil {
		log.Fatalf("Failed to get OAuth2 token: %v", err)
	}

	// Connect to SSE and wait for endpoint event
	ctx := context.Background()
	_, err = mcpClient.ConnectSSE(ctx, "1234")
	if err != nil {
		log.Fatalf("Failed to connect to SSE or receive endpoint: %v", err)
	}

	//Initialize the MCP server using the endpoint from SSE
	err = mcpClient.Initialize()
	if err != nil {
		log.Fatalf("Failed to initialize MCP server: %v", err)
	}

	_, err = mcpClient.ListTools()
	if err != nil {
		log.Fatalf("Failed to list tools: %v", err)
	}

}
