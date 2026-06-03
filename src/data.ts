import { ProjectAnalysis } from "./types";

export const TEMPLATE_SCHEMAS = [
  {
    id: "stripe-like",
    name: "Payment Gateway Service (Stripe-like)",
    description: "An OpenAPI definition of a standard payment processing service with missing OAuth guards and open CORS paths.",
    schemaText: `openapi: 3.0.0
info:
  title: Payment Gateway service (v2)
  version: 2.0.0
  description: Handles deposits, charges, and settlement webhooks.
paths:
  /v2/charges/create:
    post:
      summary: Charge a wallet or credit card
      parameters:
        - name: amount
          in: query
          required: true
          schema:
            type: integer
        - name: currency
          in: query
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Refund or Charge processed successfully.
  /v2/webhooks/payout:
    post:
      summary: Webhook receiver for background payouts
      description: Unauthenticated endpoint to trigger settlement logic.
      responses:
        '200':
          description: OK
  /v2/admin/refunds:
    get:
      summary: Retrieve all refund requests.
      description: Returns highly-sensitive card holder names without TLS checks or scopes.
      responses:
        '200':
          description: List of refund requests.`,
  },
  {
    id: "auth-core",
    name: "Auth Service Core (JWT & Session)",
    description: "Core identity system with secure token-exchange endpoints and excellent doc coverage.",
    schemaText: `openapi: 3.0.0
info:
  title: Auth Service Core (JWT Edition)
  version: 1.4.0
  description: High-entropy user authentication platform. Includes 2FA endpoints.
paths:
  /api/auth/register:
    post:
      summary: Create new developer account
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email, password]
              properties:
                 email: { type: string }
                 password: { type: string }
      responses:
        '201':
          description: Account created.
  /api/auth/token:
    post:
      summary: Exchange refresh token for access JWT
      security:
        - BearerAuth: []
      responses:
        '200':
          description: Token response.`,
  },
  {
    id: "inventory",
    name: "Inventory Worker (Bulk Operations)",
    description: "Background sync API with microservice RPC bindings and missing parameter documentation.",
    schemaText: `service InventorySyncService {
  // Syncs bulk inventory from core storage providers
  rpc SyncStock(StockRequest) returns (StockResponse);
  
  // Triggers manual system purge of local product references
  rpc PurgeProducts(PurgeRequest) returns (PurgeResponse);
}`,
  }
];

export const DEFAULT_PROJECTS: ProjectAnalysis[] = [
  {
    id: "payment-gateway-v2",
    projectName: "Payment_Gateway_v2",
    lastScan: "2024-10-24 14:22",
    endpointCount: 124,
    status: "CRITICAL",
    overallScore: 85,
    securityScore: 92,
    documentationScore: 64,
    schemaText: TEMPLATE_SCHEMAS[0].schemaText,
    insights: [
      {
        text: "3 Critical vulnerabilities detected in 'Payment_Gateway_v2'",
        type: "critical",
        timestamp: "2 hours ago"
      },
      {
        text: "Unsecured administrator route discovered at /v2/admin/refunds",
        type: "warning",
        timestamp: "2 hours ago"
      },
      {
        text: "CORS definition successfully verified with zero wildcards",
        type: "success",
        timestamp: "5 hours ago"
      }
    ],
    findings: [
      {
        endpoint: "/v2/admin/refunds",
        severity: "CRITICAL",
        category: "Security Checks",
        description: "Returns highly-sensitive card holder names without TLS or proper auth guards. Exploits allow arbitrary data harvesting."
      },
      {
        endpoint: "/v2/webhooks/payout",
        severity: "CRITICAL",
        category: "Authentication",
        description: "Webhook callback is completely unauthenticated. Attackers can forge webhook signatures to trigger phantom settlements."
      },
      {
        endpoint: "/v2/charges/create",
        severity: "WARNING",
        category: "Documentation",
        description: "Charge API is missing documentation for payload responses, error codes (402, 422), or standard currency strings."
      }
    ],
    remediationReport: `
# API Remediation Report: Payment_Gateway_v2

This report outlines critical architectural flaws discovered during our automated security compilation. Follow implementation guides to secure the payment processing perimeter.

## 🚨 1. Unsecured Refund Database Endpoint (\`/v2/admin/refunds\`)

### Description
The endpoint returns customer refund streams, comprising card-issuer brands, raw transaction amounts, and plain-text cardholder identities. 

### Resolution
Ensure that active JWT bearer tokens with precise scopes (\`refunds:read\`) are enforced, and restrict internal client accesses to secure sub-networks.

\`\`\`typescript
// Enforce JWT Guard & RBAC on Refund Routes (Express.ts Example)
import express, { Request, Response } from 'express';
import { requireAuth, requireScopes } from './auth';

const router = express.Router();

router.get('/v2/admin/refunds', 
  requireAuth, 
  requireScopes(['refunds:read', 'admin']), 
  async (req: Request, res: Response) => {
    const databaseRefunds = await fetchAllRefundLogs();
    res.json({ data: databaseRefunds });
});
\`\`\`

---

## 🔒 2. Unauthenticated payout callback webhook (\`/v2/webhooks/payout\`)

### Description
The settlement payout receptor endpoint accepts state payloads indicating bank payouts. Lack of verification prompts fraudulent re-allocations.

### Resolution
Acquire and verify a cryptographic header signature computed using a shared HMAC webhook secret:

\`\`\`typescript
// HMAC Signature Verification on incoming webhooks
import crypto from 'crypto';

export function verifyWebhookSignature(payload: string, signature: string, secret: string): boolean {
  const computedHash = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  return crypto.timingSafeEqual(Buffer.from(computedHash), Buffer.from(signature));
}
\`\`\`
`
  },
  {
    id: "auth-service-core",
    projectName: "Auth_Service_Core",
    lastScan: "2024-10-23 09:15",
    endpointCount: 42,
    status: "READY",
    overallScore: 98,
    securityScore: 100,
    documentationScore: 96,
    schemaText: TEMPLATE_SCHEMAS[1].schemaText,
    insights: [
      {
        text: "'Auth_Service_Core' reached 100% test coverage",
        type: "success",
        timestamp: "Yesterday"
      },
      {
        text: "AES-256 database token encryption checked and fully secured",
        type: "success",
        timestamp: "Yesterday"
      }
    ],
    findings: [
      {
        endpoint: "/api/auth/register",
        severity: "INFO",
        category: "Policy",
        description: "Ensure that email addresses are checked via double-opt-in verification verification processes to eliminate fake user signups."
      }
    ],
    remediationReport: `
# API Remediation Report: Auth_Service_Core

Excellent overall readiness score achieved. High entropy encryption and rate limit thresholds are correctly aligned.

## 💡 Recommended Hygiene: Register validations

### Description
The user onboarding endpoint is fully documented with schema definitions. However, email domains should be parsed to prevent temp-mail registration pools.

### Code Pattern
\`\`\`typescript
export function isAllowedDomain(email: string): boolean {
  const blocklist = ['mailinator.com', 'tempmail.com', 'throwaway.com'];
  const domain = email.split('@')[1];
  return !blocklist.includes(domain.toLowerCase());
}
\`\`\`
`
  },
  {
    id: "inventory-worker-sync",
    projectName: "Inventory_Worker_Sync",
    lastScan: "2024-10-22 18:45",
    endpointCount: 88,
    status: "NEEDS REVIEW",
    overallScore: 71,
    securityScore: 84,
    documentationScore: 58,
    schemaText: TEMPLATE_SCHEMAS[2].schemaText,
    insights: [
      {
        text: "Undocumented protobuf message elements in 'Inventory_Worker_Sync'",
        type: "warning",
        timestamp: "2 days ago"
      },
      {
        text: "No rate limiter defined for PurgeProducts administration calls",
        type: "critical",
        timestamp: "2 days ago"
      }
    ],
    findings: [
      {
        endpoint: "rpc PurgeProducts",
        severity: "WARNING",
        category: "Rate Limiting",
        description: "The destructive rpc PurgeProducts RPC has no client quotas. Concurrent invocations trigger db lock timeouts."
      },
      {
        endpoint: "rpc SyncStock",
        severity: "WARNING",
        category: "Documentation",
        description: "StockRequest does not state size constraints or currency identifiers, leading to unpredictable warehouse sync updates."
      }
    ],
    remediationReport: `
# API Remediation Report: Inventory_Worker_Sync

Some structural components require adjustments before production grade synchronization is attained.

## 🛠️ 1. Resource Limiting on Purge Routine (\`rpc PurgeProducts\`)

### Guidelines
Apply strict server-side locks or token-bucket rate limiters so administrative purge queries can only execute as sequential cron tasks, preventing resource starvation.

\`\`\`typescript
import rateLimit from 'express-rate-limit';

export const purgeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 mins
  max: 5, // Limit each client identity to 5 purge actions per window
  message: { error: 'Too many destructive payload requests. Retry later.' }
});
\`\`\`
`
  }
];
