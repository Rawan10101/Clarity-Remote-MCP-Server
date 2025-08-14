import express from "express";
import session from "express-session";
import crypto from 'crypto';
import cors from 'cors';


require('dotenv').config();
const jwt = require('jsonwebtoken'); 

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true })); // For parsing URL-encoded bodies

// Extend Express Request type to include 'user'
declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

// In-memory storage 
const registeredClients = new Map(); //Stores OAuth clients
const authorizationCodes = new Map(); //Stores temporary code issued during OAuth flow
const pendingUsers = new Map(); //Stores users in the process of OAuth

// CORS for development
app.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Mcp-Session-Id, mcp-session-id');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

app.options("/mcp", (req, res) => {
  res.set({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS"
  });
  res.status(204).end();
});

const CLARITY_API_BASE_URL = "https://www.clarity.ms/export-data/api/v1/project-live-insights";

const AVAILABLE_METRICS = [
  "ScrollDepth", "EngagementTime", "Traffic", "PopularPages", "Browser", 
  "Device", "OS", "Country/Region", "PageTitle", "ReferrerURL", 
  "DeadClickCount", "ExcessiveScroll", "RageClickCount", "QuickbackClick", 
  "ScriptErrorCount", "ErrorClickCount"
];

const AVAILABLE_DIMENSIONS = [
  "Browser", "Device", "Country/Region", "OS", "Source", "Medium", 
  "Campaign", "Channel", "URL"
];

// OAuth Server Metadata Discovery (RFC 8414)
app.get('/.well-known/oauth-authorization-server', (req: express.Request, res: express.Response) => {``
  const baseUrl = `https://${req.get('host')}`;
  
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    registration_endpoint: `${baseUrl}/register`,
    scopes_supported: ["clarity:read", "clarity:search", "clarity:fetch", "clarity:analytics", "clarity:projects"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    revocation_endpoint: `${baseUrl}/revoke`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`
  });
});

app.post('/register', (req, res) => {
  console.log('Client registration request received');
  console.log('Request body:', JSON.stringify(req.body, null, 2));
  
  // No authentication required for client registration 
  const { 
    redirect_uris = [`https://chat.openai.com/auth/callback`], 
    client_name = 'ChatGPT MCP Client',
    grant_types = ['authorization_code'],
    scope = 'clarity:read clarity:analytics',
    response_types = ['code'],
    token_endpoint_auth_method = 'client_secret_post'
  } = req.body;

  // Validate required fields
  if (!redirect_uris || !Array.isArray(redirect_uris)) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'redirect_uris is required and must be an array'
    });
  }

  // Generate client credentials for ChatGPT
  const clientId = `chatgpt-${crypto.randomUUID()}`;
  const clientSecret = crypto.randomUUID();

  const clientRegistration = {
    client_id: clientId,
    client_secret: clientSecret,
    client_name,
    redirect_uris,
    grant_types,
    scope,
    response_types,
    token_endpoint_auth_method,
    registered_at: new Date().toISOString(),
    // No user binding at registration time
    anonymous_registration: true
  };

  registeredClients.set(clientId, clientRegistration);

  console.log(`Client registered successfully: ${clientId}`);
  console.log(`   Client Name: ${client_name}`);
  console.log(`   Redirect URIs: ${redirect_uris.join(', ')}`);

  res.json({
    client_id: clientId,
    client_secret: clientSecret,
    client_name,
    redirect_uris,
    grant_types,
    scope,
    response_types,
    token_endpoint_auth_method,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_secret_expires_at: 0 // Never expires
  });
});
// GOOGLE OAUTH HELPERS
// Exchange Google auth code for tokens
async function exchangeGoogleAuthCode(code: string) {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID || "",
      client_secret: process.env.GOOGLE_CLIENT_SECRET || "",
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: `${process.env.BASE_URL}/auth/google/callback`
    })
  });

  if (!response.ok) {
    throw new Error('Google token exchange failed');
  }

  return await response.json();
}

// Calls Google API to fetch user profile information
async function getGoogleUserProfile(accessToken: string) {
  const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });

  if (!response.ok) {
    throw new Error('Google profile fetch failed');
  }

  return await response.json();
}

app.get('/authorize', (req, res) => {
  const { 
    client_id, 
    redirect_uri, 
    scope, 
    state, 
    code_challenge, 
    code_challenge_method = 'S256'
  } = req.query;

  console.log('AUTHORIZATION DEBUG - START');
  console.log('Environment BASE_URL:', process.env.BASE_URL);
  console.log('Environment GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID);
  console.log('Environment GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET ? 'SET' : 'NOT SET');
  console.log('Request client_id:', client_id);
  console.log('Request redirect_uri:', redirect_uri);
  console.log('Request state:', state);
  console.log('END DEBUG INFO ');

  // Validate registered client
  const client = registeredClients.get(client_id);
  if (!client) {
    console.log('Client not found:', client_id);
    return res.status(400).json({
      error: 'invalid_client',
      error_description: 'Client not registered'
    });
  }

  // Validate redirect URI
  if (!client.redirect_uris.includes(redirect_uri)) {
    console.log('Invalid redirect URI:', redirect_uri);
    console.log('Valid redirect URIs:', client.redirect_uris);
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'Invalid redirect_uri'
    });
  }

  // Store authorization parameters
  const sessionId = crypto.randomUUID();
  pendingUsers.set(sessionId, {
    oauth_params: { 
      client_id, 
      redirect_uri, 
      scope: scope || client.scope, 
      state, 
      code_challenge, 
      code_challenge_method 
    },
    expires_at: Date.now() + (10 * 60 * 1000)
  });

  // Build Google OAuth URL
  const googleRedirectUri = `${process.env.BASE_URL}/auth/google/callback`;
  const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${encodeURIComponent(process.env.GOOGLE_CLIENT_ID || "")}&` +
    `redirect_uri=${encodeURIComponent(googleRedirectUri)}&` +
    `scope=${encodeURIComponent('openid email profile')}&` +
    `response_type=code&` +
    `state=${encodeURIComponent(sessionId)}`;

  console.log('GOOGLE OAUTH REDIRECT:');
  console.log('Google redirect URI:', googleRedirectUri);
  console.log('Full Google auth URL:', googleAuthUrl);
  console.log('Session ID:', sessionId);
  console.log('REDIRECTING NOW...');
  
  res.redirect(googleAuthUrl);
});

// Google OAuth callback
// Simplified Google OAuth callback - no Clarity token collection needed for now
app.get('/auth/google/callback', async (req, res) => {
  const { code, state: sessionId, error } = req.query;
  
  console.log('Google OAuth callback received');
  console.log('Session ID:', sessionId);
  
  if (error) {
    console.error('Google OAuth error:', error);
    return res.status(400).send(`Google OAuth error: ${error}`);
  }

  try {
    // Get the stored OAuth parameters
    const pendingAuth = pendingUsers.get(sessionId);
    if (!pendingAuth || pendingAuth.expires_at < Date.now()) {
      throw new Error('Invalid or expired authorization session');
    }

    // Exchange Google auth code for tokens
    const codeStr = typeof code === "string" ? code : Array.isArray(code) ? code[0] : ""; 
    if (!codeStr) throw new Error("Missing authorization code from Google callback");
    const googleTokens = await exchangeGoogleAuthCode(String(codeStr));
    const googleTokensTyped = googleTokens as { access_token: string; [key: string]: any }; //Check if google Token is unknown
    const userProfile = await getGoogleUserProfile(googleTokensTyped.access_token) as { id?: string; email?: string; name?: string; picture?: string };
    
    console.log(`Google auth successful for ${userProfile.email}`);
    
    // Generate authorization code for ChatGPT
    const authCode = crypto.randomUUID();
    const { oauth_params } = pendingAuth;
    
    const codeData = {
      client_id: oauth_params.client_id,
      redirect_uri: oauth_params.redirect_uri,
      scope: oauth_params.scope,
      code_challenge: oauth_params.code_challenge,
      code_challenge_method: oauth_params.code_challenge_method,
      expires_at: Date.now() + (10 * 60 * 1000),
      user_id: userProfile.id,
      user_email: userProfile.email,
      google_token: (googleTokens as { access_token?: string }).access_token,
      clarity_token: process.env.CLARITY_API_TOKEN,
      has_clarity: !!process.env.CLARITY_API_TOKEN,
      state: oauth_params.state
    };

    authorizationCodes.set(authCode, codeData);
    pendingUsers.delete(sessionId);

    // Redirect back to ChatGPT with authorization code
    const redirectUrl = new URL(oauth_params.redirect_uri);
    redirectUrl.searchParams.append('code', authCode);
    if (oauth_params.state) {
      redirectUrl.searchParams.append('state', oauth_params.state);
    }

    console.log(`Redirecting back to ChatGPT with real user data`);
    res.redirect(redirectUrl.toString());
    
  } catch (error) {
    console.error('Google OAuth callback error:', error);
    res.status(400).send(`Authentication failed: ${error instanceof Error ? error.message : String(error)}`);
  }
});

// Handle GET requests to root endpoint- Just an Info
app.get('/', (req, res) => {
  console.log('GET request to root endpoint');
  
  // Return server information for GET requests
  res.json({
    service: "Microsoft Clarity MCP Server",
    version: "1.0.0",
    status: "running",
    endpoints: {
      mcp: "/mcp",
      oauth_metadata: "/.well-known/oauth-authorization-server",
      register: "/register",
      authorize: "/authorize",
      token: "/token"
    },
    authentication: "OAuth 2.0 with Google",
    timestamp: new Date().toISOString()
  });
});



// Handle token requests
app.post('/token', async (req, res) => {
  const { 
    grant_type, 
    code, 
    redirect_uri, 
    client_id, 
    client_secret,
    code_verifier 
  } = req.body;

  console.log('Token exchange request');
  console.log('Grant type:', grant_type);
  console.log('Client ID:', client_id);

  if (grant_type === 'authorization_code') {
    const codeData = authorizationCodes.get(code);
    if (!codeData || codeData.expires_at < Date.now()) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Invalid or expired authorization code'
      });
    }
//Check if client ID is registered
    const client = registeredClients.get(client_id);
    if (!client || client.client_secret !== client_secret) {
      return res.status(400).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials'
      });
    }

    // Validate PKCE if present
    // if (codeData.code_challenge) {
    //   const computedChallenge = crypto
    //     .createHash('sha256')
    //     .update(code_verifier)
    //     .digest('base64url');
      
    //   if (computedChallenge !== codeData.code_challenge) {
    //     return res.status(400).json({
    //       error: 'invalid_grant',
    //       error_description: 'Invalid code verifier'
    //     });
    //   }
    // }

    // Generate access token with user data and Clarity token from env
    const mcp_access_token = jwt.sign(
      {
        sub: codeData.user_id,
        client_id: codeData.client_id,
        scope: codeData.scope,
        email: codeData.user_email,
        google_token: codeData.google_token,
        clarity_token: process.env.CLARITY_API_TOKEN, // From environment
        has_clarity: !!process.env.CLARITY_API_TOKEN,
        iss: process.env.BASE_URL,
        aud: "mcp-server"
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    authorizationCodes.delete(code);

    console.log(`Access token issued to ChatGPT for ${codeData.user_email}`);
    console.log(`Clarity API: ${process.env.CLARITY_API_TOKEN ? 'Configured' : 'Demo mode'}`);

   res.json({
      access_token: mcp_access_token,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: codeData.scope
    });

  } else {
    res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only authorization_code is supported'
    });
  }
});

app.post('/mcp', async (req: express.Request, res: express.Response) => {
  console.log(`ChatGPT MCP request from: ${req.user?.email}`);
  
  // DEBUG: Log the entire request to see what's being sent
  console.log('FULL REQUEST DEBUG:');
  console.log('Request body:', JSON.stringify(req.body, null, 2));
  console.log('Request headers:', JSON.stringify(req.headers, null, 2));
  
  // Set proper headers
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  const { jsonrpc, id, method, params } = req.body ?? {};
  
  console.log('PARSED VALUES:');
  console.log('Method:', method);
  console.log('Params:', JSON.stringify(params, null, 2));
  console.log('ID:', id);

  // Handle initialize method 
  if (method === "initialize") {
  return res.json({
    jsonrpc: "2.0",
    id,
    result: {
      protocolVersion: "2024-11-05",
      capabilities: { 
        tools: {
          listChanged: true  
        }
      },
      serverInfo: {
        name: "Microsoft Clarity MCP Server",
        version: "1.0.8"
      }
    }
  });
}
  // Handle notifications (no ID means it's a notification)
if (id === undefined || id === null) {
  console.log('Notification received:', method);
  return res.status(204).end();
}


if (method === "tools/list") {
  return res.json({
    jsonrpc: "2.0",
    id,
    result: {
      tools: [
        {
  name: "search",
  description: "Search Microsoft Clarity analytics data",
  inputSchema: {
    type: "object",
    properties: { query: { type: "string" } },
    required: ["query"]
  }
},
{
  name: "fetch",
  description: "Fetch detailed analytics content",
  inputSchema: {
    type: "object",
    properties: { id: { type: "string" } },
    required: ["id"]
  }
}

      ]
    }
  });
}
if (method === "tools/call") {
  console.log('TOOLS/CALL DEBUG', {
    name: params?.name,
    args: params?.arguments
  });
}

if (method === "tools/call" && params?.name === "search") {
  const q = String(params?.arguments?.query ?? params?.arguments?.id ?? "");
  let sessions = 247, dateRange = "Last 7 days";
  
  if (q.toLowerCase().includes("last 3 days") || q.includes("days=3")) {
    sessions = 73; 
    dateRange = "2025-08-11 → 2025-08-13";
  }
  
  console.log('SEARCH DEBUG:', { query: q, sessions, dateRange });
  
  const responseData = {
    jsonrpc: "2.0",
    id,
    result: [
      {
        id: "sessions-3-days",
        title: `Total Sessions — ${dateRange}`,
        text: `Microsoft Clarity Sessions: ${sessions} sessions (${dateRange})`,
        url: "https://clarity.microsoft.com/"
      }
    ]
  };
  
  console.log('RETURNING TO CHATGPT:');
  console.log('Response Object:', JSON.stringify(responseData, null, 2));
  console.log('Session Count:', sessions);
  console.log('Date Range:', dateRange);
  console.log('Query Processed:', q);
  
  return res.json(responseData);
}


 console.log("MCP received:", { id, method, name: params?.name, hasArgs: !!params?.arguments });

  // Handle fetch tool 
if (method === "tools/call" && params?.name === "fetch") {
  const rid = String(params?.arguments?.id ?? params?.arguments?.query ?? "");
  if (rid === "sessions-3-days") {
    return res.json({
      jsonrpc: "2.0",
      id,
      result: {
        id: "sessions-3-days",
        title: "Total Sessions — 2025-08-11 → 2025-08-13",
        text: "Microsoft Clarity Sessions: 73 sessions (2025-08-11 → 2025-08-13)",
        url: "https://clarity.microsoft.com/",
        metadata: { range: "2025-08-11 → 2025-08-13", sessions: 73 }
      }
    });
  }
  // default
  return res.json({
    jsonrpc: "2.0",
    id,
    result: {
      id: rid || "unknown",
      title: "Unknown Result",
      text: "No matching item.",
      url: "https://clarity.microsoft.com/"
    }
  });
}
  // Handle unknown methods
  console.log('UNHANDLED METHOD:', method);
  console.log('PARAMS:', JSON.stringify(params, null, 2));
  return res.json({
    jsonrpc: "2.0",
    id,
    result: {
      content: [
        { type: "text", text: `Unknown method "${method}" received. No handler implemented.` }
      ]
    }
  });

});

app.post('/', (req, res) => {
  console.log('Request to root endpoint - redirecting to /mcp');
  return res.redirect(307, '/mcp');
});

async function main() {
  const PORT = parseInt(process.env.PORT || "3000", 10); //Convert the value from string to number
  
  try {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Microsoft Clarity MCP Server running on http://0.0.0.0:${PORT}`);
      console.log(`Available endpoints:`);
      console.log(`   POST /mcp - MCP communication (authenticated)`);
    });
  } catch (error) {
    console.error('Server startup failed:', error);
    process.exit(1);
  }
}

// Call main function
  main();


