package main

import (
	"fmt"
	"log"

	"github.com/dhopkins-va/mcp-playground/mcp"
	"github.com/spf13/cobra"
)

var (
	serverURL   string
	accessToken string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "mcp-playground",
		Short: "MCP Playground - A tool for interacting with MCP servers",
		Long:  "MCP Playground is a CLI tool for discovering, connecting to, and interacting with MCP (Model Context Protocol) servers.",
		Run:   run,
	}

	rootCmd.Flags().StringVarP(&serverURL, "server", "s", "", "Address of the MCP server")
	rootCmd.Flags().StringVarP(&accessToken, "access_token", "t", "", "Access token to use (skips OAuth discovery and token exchange)")
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

func run(cmd *cobra.Command, args []string) {
	if serverURL == "" {
		log.Fatalf("Server URL is required. Use --server or -s flag to specify the MCP server address.")
	}

	mcpClient := mcp.CreateClient(serverURL, 8090, mcp.TransportDiscover)

	var err error
	// If access token is provided, use it directly and skip OAuth flow
	if accessToken != "" {
		mcpClient.SetAccessToken(accessToken)
		fmt.Printf("Using provided access token (skipping OAuth2 discovery)\n")
	} else {
		//Discover the authorization server
		err = mcpClient.DiscoverAuthorizationServer()
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
	}

	//Initialize the MCP server
	err = mcpClient.Initialize()
	if err != nil {
		log.Fatalf("Failed to initialize MCP server: %v", err)
	}

	//List the tools
	_, err = mcpClient.ListTools()
	if err != nil {
		log.Fatalf("Failed to list tools: %v", err)
	}

	//Invoke a tool to list the confluence spaces (if it exists)
	if mcpClient.ToolExists("getConfluenceSpaces") {
		result, err := mcpClient.CallTool("getConfluenceSpaces", map[string]interface{}{
			"cloudId": "https://vendasta.jira.com/wiki/",
			"limit":   1,
		})
		if err != nil {
			log.Fatalf("Failed to invoke tool: %v", err)
		}
		fmt.Printf("Tool invocation result: %+v\n", result)
	}

	//Fetch the cortex.yaml from CS (if it exists)
	if mcpClient.ToolExists("get_file_contents") {
		result, err := mcpClient.CallTool("get_file_contents", map[string]interface{}{
			"owner": "vendasta",
			"repo":  "CS",
			"path":  "/cortex.yaml",
		})
		if err != nil {
			log.Fatalf("Failed to invoke tool: %v", err)
		}
		fmt.Printf("Tool invocation result: %+v\n", result)
	}
}
