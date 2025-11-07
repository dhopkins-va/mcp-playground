package main

import (
	"context"
	"fmt"
	"log"

	"github.com/dhopkins-va/mcp-playground/mcp"
	"github.com/spf13/cobra"
)

var (
	serverURL string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "mcp-playground",
		Short: "MCP Playground - A tool for interacting with MCP servers",
		Long:  "MCP Playground is a CLI tool for discovering, connecting to, and interacting with MCP (Model Context Protocol) servers.",
		Run:   run,
	}

	rootCmd.Flags().StringVarP(&serverURL, "server", "s", "", "Address of the MCP server")
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

func run(cmd *cobra.Command, args []string) {
	if serverURL == "" {
		log.Fatalf("Server URL is required. Use --server or -s flag to specify the MCP server address.")
	}

	//Discover the authorization server
	mcpClient := mcp.CreateClient(serverURL, 8090, true)
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

	//List the tools
	_, err = mcpClient.ListTools()
	if err != nil {
		log.Fatalf("Failed to list tools: %v", err)
	}

	//Invoke a tool to list the confluence spaces
	result, err := mcpClient.CallTool("getConfluenceSpaces", map[string]interface{}{
		"cloudId": "https://vendasta.jira.com/wiki/",
		"limit":   1,
	})
	if err != nil {
		log.Fatalf("Failed to invoke tool: %v", err)
	}
	fmt.Printf("Tool invocation result: %+v\n", result)
}
