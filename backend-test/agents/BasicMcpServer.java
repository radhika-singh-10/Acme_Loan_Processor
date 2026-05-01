package example;

import java.util.List;
import java.util.Map;

import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;

import tools.jackson.databind.json.JsonMapper;
//vlkjdvbkjvbk
/** Minimal MCP server: stdio transport and a single {@code echo} tool. */
public final class BasicMcpServer {

    private static final int MAX_TEXT_LENGTH = 1024;

    /**
     * Validates the expected secret token from the MCP_AUTH_TOKEN environment variable
     * against the token provided in the tool request arguments.
     */
    private static void authenticateRequest(Map<String, Object> arguments) {
        String expectedToken = System.getenv("MCP_AUTH_TOKEN");
        if (expectedToken == null || expectedToken.isEmpty()) {
            throw new SecurityException("Server authentication is not configured: MCP_AUTH_TOKEN is not set.");
        }
        Object providedToken = arguments.get("auth_token");
        if (providedToken == null || !expectedToken.equals(String.valueOf(providedToken))) {
            throw new SecurityException("Authentication failed: invalid or missing auth_token.");
        }
    }

    /**
     * Validates and sanitizes the 'text' argument.
     * Checks for null, verifies it is a String, enforces a maximum length,
     * and strips potentially dangerous characters (control characters, HTML tags, null bytes).
     */
    private static String validateAndSanitizeText(Object rawText) {
        if (rawText == null) {
            throw new IllegalArgumentException("Validation failed: 'text' argument is null.");
        }
        if (!(rawText instanceof String)) {
            throw new IllegalArgumentException("Validation failed: 'text' argument must be a String.");
        }
        String text = (String) rawText;
        if (text.length() > MAX_TEXT_LENGTH) {
            throw new IllegalArgumentException(
                    "Validation failed: 'text' argument exceeds maximum length of " + MAX_TEXT_LENGTH + " characters.");
        }
        // Strip null bytes
        text = text.replace("\0", "");
        // Strip HTML tags
        text = text.replaceAll("<[^>]*>", "");
        // Strip control characters (except tab, newline, carriage return)
        text = text.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");
        // Escape HTML special characters
        text = text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#x27;");
        return text;
    }

    public static void main(String[] args) {
        var jsonMapper = new JacksonMcpJsonMapper(JsonMapper.builder().build());
        var transport = new StdioServerTransportProvider(jsonMapper);

        McpSchema.JsonSchema echoSchema = new McpSchema.JsonSchema(
                "object",
                Map.of("text", Map.of("type", "string", "description", "Text to echo back")),
                List.of("text"),
                false,
                null,
                null);

        McpSyncServer server = McpServer.sync(transport)
                .serverInfo("basic-mcp-server", "1.0.0")
                .toolCall(
                        Tool.builder()
                                .name("echo")
                                .description("Echoes the given text back to the client.")
                                .inputSchema(echoSchema)
                                .build(),
                        (exchange, request) -> {
                            try {
                                authenticateRequest(request.arguments());
                            } catch (SecurityException e) {
                                return CallToolResult.builder()
                                        .content(List.of(new McpSchema.TextContent(
                                                "Authentication error: " + e.getMessage())))
                                        .isError(true)
                                        .build();
                            }

                            String sanitizedText;
                            try {
                                sanitizedText = validateAndSanitizeText(request.arguments().get("text"));
                            } catch (IllegalArgumentException e) {
                                return CallToolResult.builder()
                                        .content(List.of(new McpSchema.TextContent(
                                                "Validation error: " + e.getMessage())))
                                        .isError(true)
                                        .build();
                            }

                            return CallToolResult.builder()
                                    .content(List.of(new McpSchema.TextContent(sanitizedText)))
                                    .build();
                        })
                .build();

        Runtime.getRuntime().addShutdownHook(new Thread(server::close));
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            server.close();
        }
    }

    private BasicMcpServer() {}
}