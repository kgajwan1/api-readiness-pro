import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Use JSON and Text body parsers with generous limits
  app.use(express.json({ limit: "5mb" }));
  app.use(express.urlencoded({ extended: true, limit: "5mb" }));

  // Initialize server-side Gemini client lazily with runtime key storage
  let aiClient: GoogleGenAI | null = null;
  let runtimeGeminiApiKey: string | undefined = process.env.GEMINI_API_KEY;

  function setGeminiApiKey(key: string) {
    runtimeGeminiApiKey = key;
    process.env.GEMINI_API_KEY = key;
    aiClient = null;
  }

  function getAiClient(): GoogleGenAI {
    const apiKey = runtimeGeminiApiKey;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY is not configured. Enter your Gemini key via the UI or environment variables.");
    }
    if (!aiClient) {
      aiClient = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            "User-Agent": "aistudio-build",
          },
        },
      });
    }
    return aiClient;
  }

  // Endpoint for configuring Gemini API key from the frontend
  app.post("/api/gemini-key", (req, res) => {
    const { apiKey } = req.body;
    if (!apiKey || typeof apiKey !== "string" || !apiKey.trim()) {
      return res.status(400).json({ error: "API key is required." });
    }

    setGeminiApiKey(apiKey.trim());
    return res.json({ status: "ok", keyConfigured: true });
  });

  // API endpoint for analysis
  app.post("/api/analyze", async (req, res) => {
    try {
      const { projectName, schemaText, templateId } = req.body;

      if (!schemaText || typeof schemaText !== "string" || !schemaText.trim()) {
        res.status(400).json({ error: "API schema text or description is required for analysis." });
        return;
      }

      console.log(`Starting real Gemini analysis for project: ${projectName || "Unnamed Project"}`);

      const ai = getAiClient();
      const prompt = `
You are an expert API quality, design, and security audit tool. 
Please analyze the following API description, OpenAPI/Swagger schema, or manual endpoint definition, and produce a complete auditor analysis report.

PROJECT NAME: ${projectName || "API Service"}
TEMPLATE TYPE: ${templateId || "Custom"}

API CONTENT TO AUDIT:
-----------------------------
${schemaText}
-----------------------------

Perform the following tasks:
1. Identify all endpoints, paths, methods, and parameters.
2. Verify security hygiene: Look for authentication/authorization headers, API keys, JWT validation, rate limiting metadata, CORS info, lack of SSL details, or exposure of PII / sensitive identifiers.
3. Assess design quality: HTTP methods semantic correctness, status codes structure, restful hierarchy, path naming consistency.
4. Assess documentation completeness: Missing summaries, missing request/response payload examples, or blank parameter description fields.
5. Create a standard scorecard (Overall Readiness, Security Score, Documentation Score, and Status which is 'READY', 'NEEDS REVIEW', or 'CRITICAL').
6. Generate 2 to 4 actionable insights with categorized relative times (e.g. "Just now", "2 minutes ago").
7. Generate a comprehensive findings list.
8. Author a deeply thorough and beautiful Markdown remediation report that contains code snippet examples (e.g., in Express, Python, or Go) showing how to patch the critical vulnerability issues.

Return the result as a raw JSON payload fitting the required responseSchema precisely.
      `;

      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              overallScore: {
                type: Type.INTEGER,
                description: "Integer score from 0 to 100 on overall readiness and design correctness",
              },
              securityScore: {
                type: Type.INTEGER,
                description: "Security score from 0 to 100 focusing on authentication, encryption, and protection against OWASP Top 10 API issues",
              },
              documentationScore: {
                type: Type.INTEGER,
                description: "Documentation score from 0 to 100 assessing the coverage of parameter keys, types, summaries, and payload schemas",
              },
              endpointCount: {
                type: Type.INTEGER,
                description: "The total number of API paths/methods detected",
              },
              status: {
                type: Type.STRING,
                description: "Must be 'READY' (all scores >= 80), 'NEEDS REVIEW' (scores >= 50 but some < 80), or 'CRITICAL' (any core parameter < 50 or severe security flaw)",
              },
              findings: {
                type: Type.ARRAY,
                description: "A detailed list of the developer findings and vulnerabilities",
                items: {
                  type: Type.OBJECT,
                  properties: {
                    endpoint: {
                      type: Type.STRING,
                      description: "E.g. 'POST /api/v1/checkout' or 'GLOBAL'",
                    },
                    severity: {
                      type: Type.STRING,
                      description: "Value must be one of 'CRITICAL', 'WARNING', or 'INFO'",
                    },
                    category: {
                      type: Type.STRING,
                      description: "E.g. 'Security', 'Design Rest', 'Documentation', 'Configuration'",
                    },
                    description: {
                      type: Type.STRING,
                      description: "Summary description of what is weak or missing, with suggestions",
                    },
                  },
                  required: ["endpoint", "severity", "category", "description"],
                },
              },
              insights: {
                type: Type.ARRAY,
                description: "2 to 4 micro-insights that appear in quick notifications",
                items: {
                  type: Type.OBJECT,
                  properties: {
                    text: {
                      type: Type.STRING,
                      description: "Brief insight string, e.g., 'Unauthenticated admin routes found' or 'No description on query parameters'",
                    },
                    type: {
                      type: Type.STRING,
                      description: "Must be 'critical' (for hazards), 'warning' (for medium problems), or 'success' (for positive achievements)",
                    },
                    timestamp: {
                      type: Type.STRING,
                      description: "A relative string representing timing, e.g., 'Just now', '1 minute ago', '2 hours ago'",
                    },
                  },
                  required: ["text", "type", "timestamp"],
                },
              },
              remediationReport: {
                type: Type.STRING,
                description: "The extensive auditor-grade Markdown remediation report. Include structure, bullet points, headers, and code samples indicating fixes.",
              },
            },
            required: [
              "overallScore",
              "securityScore",
              "documentationScore",
              "endpointCount",
              "status",
              "findings",
              "insights",
              "remediationReport",
            ],
          },
        },
      });

      const responseText = response.text;
      if (!responseText) {
        throw new Error("Empty response returned from the Gemini API model.");
      }

      const parsedResult = JSON.parse(responseText.trim());
      res.json(parsedResult);
    } catch (error: any) {
      console.error("Analysis route error:", error);
      res.status(500).json({
        error: error.message || "Failed to analyze the specified API schema. Please check GEMINI_API_KEY setup.",
      });
    }
  });

  // Provide health status endpoint
  app.get("/api/health", (req, res) => {
    res.json({ status: "healthy", keyConfigured: !!runtimeGeminiApiKey });
  });

  // Serve Frontend depending on environment
  if (process.env.NODE_ENV !== "production") {
    console.log("Starting in DEVELOPMENT mode with Vite Middleware.");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    console.log("Starting in PRODUCTION mode. Serving pre-compiled assets from dist.");
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`API Readiness Pro Server listen on http://localhost:${PORT}`);
  });
}

startServer();
