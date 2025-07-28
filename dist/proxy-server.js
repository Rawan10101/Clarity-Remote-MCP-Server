"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const node_crypto_1 = require("node:crypto");
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const streamableHttp_js_1 = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const types_js_1 = require("@modelcontextprotocol/sdk/types.js");
const cors_1 = __importDefault(require("cors"));
const zod_1 = require("zod");
const dotenv = __importStar(require("dotenv"));
// Load environment variables
dotenv.config();
// Get configuration from environment variables or command-line arguments
const getConfigValue = (name, fallback) => {
    // Check command line args first (format: --name=value)
    const commandArg = process.argv.find(arg => arg.startsWith(`--${name}=`));
    if (commandArg) {
        return commandArg.split("=")[1];
    }
    // Check environment variables
    const envValue = process.env[name.toUpperCase()] || process.env[name];
    if (envValue) {
        return envValue;
    }
    return fallback;
};
const app = (0, express_1.default)();
app.use(express_1.default.json());
// Map to store transports by session id
const transports = {};
// Constants for API
const API_BASE_URL = "https://www.clarity.ms/export-data/api/v1/project-live-insights";
// Available metrics that may be returned by the API
const AVAILABLE_METRICS = [
    "ScrollDepth",
    "EngagementTime",
    "Traffic",
    "PopularPages",
    "Browser",
    "Device",
    "OS",
    "Country/Region",
    "PageTitle",
    "ReferrerURL",
    "DeadClickCount",
    "ExcessiveScroll",
    "RageClickCount",
    "QuickbackClick",
    "ScriptErrorCount",
    "ErrorClickCount"
];
// Available dimensions that can be used in queries
const AVAILABLE_DIMENSIONS = [
    "Browser",
    "Device",
    "Country/Region",
    "OS",
    "Source",
    "Medium",
    "Campaign",
    "Channel",
    "URL"
];
// Fetch data from Microsoft's Clarity API
async function fetchClarityData(token, numOfDays = 3, dimensions = []) {
    try {
        // Build parameters for the API request
        const params = new URLSearchParams();
        params.append("numOfDays", numOfDays.toString());
        // Add dimensions if specified (maximum 3 allowed)
        dimensions.slice(0, 3).forEach((dim, index) => {
            params.append(`dimension${index + 1}`, dim);
        });
        // Make the API request
        const url = `${API_BASE_URL}?${params.toString()}&src=mcp`;
        //Debugging output   
        console.error(`Making request to: ${url}`);
        const response = await fetch(url, {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
            }
        });
        if (!response.ok) {
            throw new Error(`API request failed with status ${response.status}: ${response.statusText}`);
        }
        return await response.json();
    }
    catch (error) {
        console.error("Error fetching Clarity data:", error);
        return { error: error instanceof Error ? error.message : "Unknown error" };
    }
}
// To register the get-clarity-data tool
const registerClarityTools = (mcpServer) => {
    mcpServer.tool("get-clarity-data", "Fetch Microsoft Clarity analytics data", {
        numOfDays: zod_1.z.number().min(1).max(3).describe("Number of days to retrieve data for (1-3)"),
        dimensions: zod_1.z.array(zod_1.z.string()).optional().describe("Up to 3 dimensions to filter by (Browser, Device, Country/Region, OS, Source, Medium, Campaign, Channel, URL)"),
        metrics: zod_1.z.array(zod_1.z.string()).optional().describe("Metrics to retrieve (Scroll Depth, Engagement Time, Traffic, Popular Pages, Browser, Device, OS, Country/Region, etc.)"),
        token: zod_1.z.string().optional().describe("Your Clarity API token (optional if provided via environment or command line)"),
    }, async ({ numOfDays, dimensions = [], metrics = [], token }) => {
        // Use provided token or fallback to environment/command-line variables
        const finalToken = token || getConfigValue("clarity_api_token") || getConfigValue("CLARITY_API_TOKEN");
        // Check if token is provided
        if (!finalToken) {
            return {
                content: [
                    {
                        type: "text",
                        text: "No Clarity API token provided. Please provide a token via the \'token\' parameter, CLARITY_API_TOKEN environment variable, or --clarity_api_token command-line argument.",
                    },
                ],
            };
        }
        // Filter out any dimensions not in the available dimensions
        const filteredDimensions = dimensions.filter(d => AVAILABLE_DIMENSIONS.includes(d));
        if (filteredDimensions.length < dimensions.length) {
            console.warn("Some dimensions were invalid and have been filtered out");
        }
        // Fetch data from Clarity API
        const data = await fetchClarityData(finalToken, numOfDays, filteredDimensions);
        // Check for errors
        if (data.error) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Error fetching data: ${data.error}`,
                    },
                ],
            };
        }
        // Filter metrics if specified
        let formattedResult = data;
        if (metrics && metrics.length > 0) {
            // Filter the metrics if requested (case-insensitive match for user convenience)
            formattedResult = data.filter((item) => metrics.some(m => item.metricName.toLowerCase() === m.toLowerCase() ||
                item.metricName.replace(/\s+/g, "").toLowerCase() === m.replace(/\s+/g, "").toLowerCase()));
        }
        const resultText = JSON.stringify(formattedResult, null, 2);
        return {
            content: [
                {
                    type: "text",
                    text: resultText,
                },
            ],
        };
    });
    //Testing
    // Meta-information about the server
    mcpServer.tool("get-server-status", "Get the current status of the Clarity MCP server", {}, async () => {
        const hasToken = !!(getConfigValue("clarity_api_token") || getConfigValue("CLARITY_API_TOKEN"));
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify({
                        server: "@microsoft/clarity-mcp-server-http-only",
                        version: "1.0.0",
                        status: "running",
                        transport: "http",
                        apiTokenConfigured: hasToken,
                        supportedMetrics: AVAILABLE_METRICS,
                        supportedDimensions: AVAILABLE_DIMENSIONS,
                        timestamp: new Date().toISOString(),
                    }, null, 2),
                },
            ],
        };
    });
    // Tool to test connection to Clarity API 
    mcpServer.tool("test-clarity-connection", "Test the connection to Microsoft Clarity API", {
        token: zod_1.z.string().optional().describe("Your Clarity API token (optional if provided via environment or command line)"),
    }, async ({ token }) => {
        const finalToken = token || getConfigValue("clarity_api_token") || getConfigValue("CLARITY_API_TOKEN");
        if (!finalToken) {
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify({
                            success: false,
                            error: "No API token provided",
                            message: "Please provide a token via parameter, environment variable, or command line argument",
                        }, null, 2),
                    },
                ],
            };
        }
        // Test with minimal request (3 day, no dimensions)
        const testResult = await fetchClarityData(finalToken, 3, []);
        if (testResult.error) {
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify({
                            success: false,
                            error: testResult.error,
                            message: "Failed to connect to Clarity API",
                        }, null, 2),
                    },
                ],
            };
        }
        return {
            content: [
                {
                    type: "text",
                    text: JSON.stringify({
                        success: true,
                        message: "Successfully connected to Clarity API",
                        dataPoints: Array.isArray(testResult) ? testResult.length : 0,
                        timestamp: new Date().toISOString(),
                    }, null, 2),
                },
            ],
        };
    });
};
// Add CORS middleware before MCP routes
// Cross origin Resource Sharing (CORS) middleware
// To make the server allows cross-origin requests
app.use((0, cors_1.default)({
    origin: "*", // Allow all website to make requests to the server
    exposedHeaders: ["Mcp-Session-Id"],
    allowedHeaders: ["Content-Type", "mcp-session-id", "Authorization"],
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
}));
// Handle POST requests for client to server 
app.post("/mcp", async (req, res) => {
    // Check for existing session ID
    const sessionId = req.headers["mcp-session-id"];
    let transport;
    if (sessionId && transports[sessionId]) {
        // Reuse existing transport
        transport = transports[sessionId];
    }
    else if (!sessionId && (0, types_js_1.isInitializeRequest)(req.body)) {
        // New initialization request
        transport = new streamableHttp_js_1.StreamableHTTPServerTransport({
            sessionIdGenerator: () => (0, node_crypto_1.randomUUID)(),
            onsessioninitialized: (newSessionId) => {
                // Store the transport by session ID
                transports[newSessionId] = transport;
                const server = new mcp_js_1.McpServer({
                    name: "@microsoft/clarity-mcp-server-http-only",
                    version: "1.0.0",
                });
                registerClarityTools(server);
                server.connect(transport);
            },
        });
        // Delete transport when closed
        transport.onclose = () => {
            if (transport.sessionId) {
                delete transports[transport.sessionId];
            }
        };
    }
    else {
        // Invalid request on Status -> 400
        res.status(400).json({
            jsonrpc: "2.0",
            error: {
                code: -32000,
                message: "Bad Request: No valid session ID provided or invalid initialization request",
            },
            id: null,
        });
        return;
    }
    // Handle the request
    await transport.handleRequest(req, res, req.body);
});
// Will be used for GET and DELETE requests
const handleSessionRequest = async (req, res) => {
    const sessionId = req.headers["mcp-session-id"];
    if (!sessionId || !transports[sessionId]) {
        res.status(400).send("Invalid or missing session ID");
        return;
    }
    const transport = transports[sessionId];
    await transport.handleRequest(req, res);
};
// Handle GET requests for server to client notifications via SSE
app.get("/mcp", handleSessionRequest);
// Handle DELETE requests for session termination
app.delete("/mcp", handleSessionRequest);
// Main function
async function main() {
    // Configuration status
    if (getConfigValue("clarity_api_token") || getConfigValue("CLARITY_API_TOKEN")) {
        console.error("Clarity API token configured via environment/command-line");
    }
    else {
        console.error("No Clarity API token configured, it must be provided with each request");
    }
    console.error(`Supported metrics: ${AVAILABLE_METRICS.join(", ")}`);
    console.error(`Supported dimensions: ${AVAILABLE_DIMENSIONS.join(", ")}`);
    const port = parseInt(process.env.PORT || getConfigValue("port") || "3000");
    const host = process.env.HOST || getConfigValue("host") || "0.0.0.0";
    app.listen(port, host, () => {
        console.error(`Microsoft Clarity MCP Server running on http://${host}:${port}`);
        console.error("Available endpoints:");
        console.error("  POST /mcp - MCP communication (client-to-server)");
        console.error("  GET  /mcp - MCP communication (server-to-client notifications via SSE)");
        console.error("  DELETE /mcp - MCP session termination");
    });
}
// Handle shutdown
process.on("SIGINT", () => {
    console.error("Shutting down Microsoft Clarity MCP Server...");
    process.exit(0);
});
process.on("SIGTERM", () => {
    console.error("Shutting down Microsoft Clarity MCP Server...");
    process.exit(0);
});
// Run the server
if (require.main === module) {
    main().catch((error) => {
        console.error("Fatal error in main():", error);
        process.exit(1);
    });
}
//# sourceMappingURL=proxy-server.js.map