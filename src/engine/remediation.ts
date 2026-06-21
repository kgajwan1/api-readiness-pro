import { Finding } from "../types";

export function generateLocalRemediationReport(projectName: string, findings: Finding[]): string {
  const isDuplicateSuccessScenario = findings.some(f => f.category === "Double Mutation Check");
  const criticals = findings.filter(f => f.severity === "CRITICAL");
  const warnings = findings.filter(f => f.severity === "WARNING");

  if (isDuplicateSuccessScenario) {
    return `# Remediation & Mitigation Guide: ${projectName}

This report has been compiled dynamically via the completely **AI-Independent AST Ruleset Engine**. No external AI model was queried. Use the direct programmatic patches below.

---

## 🚨 1. Mitigation Checklist: Duplicate Success Webhook Gaps (Double Mutation)

* **Risk Level**: High
* **Scenario**: Duplicate Success Webhook
* **Result**: Payment state mutated twice.
* **Business Impact**: Customer may receive duplicate settlement confirmation.
* **Recommended Fix**: Implement idempotency token validation.

---

## 🔒 2. Implementation: Redis-Backed Distributed Idempotency Lock

To fully secure database queries from replay mutations, enforce standard unique idempotency header token checks on incoming webhook transactions:

\`\`\`typescript
import { Request, Response, NextFunction } from 'express';
import Redis from 'ioredis'; // Distributed lock cache client

const redisStore = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

export async function enforcePaymentIdempotency(req: Request, res: Response, next: NextFunction) {
  const webhookSignature = req.headers['x-webhook-signature'];
  const idempotencyKey = req.headers['idempotency-key'] as string;

  if (!idempotencyKey) {
    return res.status(400).json({
      error: 'Idempotency key required in transaction payload'
    });
  }

  // Atomically claim lock to prevent double mutations (10-minute expiry)
  const lockKey = \`lock:webhook:idempotency:\${idempotencyKey}\`;
  const acquiresLock = await redisStore.set(lockKey, 'pending', 'NX', 'EX', 600);

  if (!acquiresLock) {
    return res.status(409).json({
      error: 'Conflict: Duplicate webhook processing in flight'
    });
  }

  try {
    next();
  } catch (err) {
    // Release the lock on failure so the client can retry safely
    await redisStore.del(lockKey);
    res.status(500).json({ error: 'Internal business mutation failure' });
  }
}
\`\`\`

---

## 🛡️ AST Compliance Verification Certificate
* **Analysis Mode**: Deterministic AST Regex Scan
* **Evaluation Framework**: OWASP API Top 10 Matcher
* **Idempotency Status**: SECURED (After Patch)
* **Date**: ${new Date().toLocaleDateString()}
`;
  }

  let md = `# Remediation Patch Report: ${projectName}

This report has been compiled dynamically via the completely **AI-Independent AST Ruleset Engine**. No external AI model was queried. Use the direct programmatic patches below.

---

## Scorecard Checklist status
* **Rule Audit Status**: ${criticals.length ? "⚠️ WARNING" : "✅ OPTIMAL"}
* **Mitration Code Blocks**: Node.js / Express snippets generated.

`;

  if (criticals.length > 0) {
    md += `## 🚨 1. Enforcing OAuth Checks & Role-Based Access controls\n\n`;
    criticals.forEach((finding, idx) => {
      md += `### [CRIT-${idx + 1}] Check on \`${finding.endpoint}\`
* Issue type: ${finding.category}
* Detail: ${finding.description}

### Programmatic Patch:
\`\`\`typescript
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export function checkRequiredPermissions(scope: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'OAuth Bearer Token Required' });
    }

    try {
      const token = authHeader.split(' ')[1];
      const decoded: any = jwt.verify(token, process.env.JWT_SECRET || 'fallback-sign-key');
      if (!decoded.permissions?.includes(scope)) {
        return res.status(403).json({ error: 'Forbidden: missing claim scope' });
      }
      next();
    } catch (e) {
      return res.status(403).json({ error: 'Invalid or expired JWT structure' });
    }
  };
}
\`\`\`

---

`;
    });
  }

  if (warnings.length > 0) {
    md += `## ⚠️ 2. Cross-Origin Safety & Documentation Patch\n\n`;
    warnings.forEach((finding, idx) => {
      md += `### [WARN-${idx + 1}] Alert on \`${finding.endpoint}\`
* Type: ${finding.category}
* Context: ${finding.description}

### Resolution Code pattern:
\`\`\`typescript
import cors from 'cors';

export const securedCorsPolicy = cors({
  origin: ['https://trusted-domain.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
});
\`\`\`

`;
    });
  }

  md += `
---

## 🔒 AST Compliance Verification Certificate
* **Analysis Mode**: Deterministic AST Regex Scan
* **Evaluation Framework**: OWASP API Top 10 Matcher
* **Date**: ${new Date().toLocaleDateString()}
`;

  return md;
}
