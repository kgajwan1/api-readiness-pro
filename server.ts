import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";
import dotenv from "dotenv";

dotenv.config({ path: [".env.local", ".env"] });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

type LlmProvider = "gemini" | "openai" | "anthropic";
const LLM_PROVIDERS: LlmProvider[] = ["gemini", "openai", "anthropic"];

const PROVIDER_MODELS: Record<LlmProvider, string> = {
  gemini: "gemini-3.5-flash",
  openai: "gpt-4o-mini",
  anthropic: "claude-sonnet-4-6",
};

// The deterministic engine (src/engine/rules.ts) already produced the
// scorecard, status, and findings list before this prompt is ever built.
// The LLM's only job is to write narrative remediation prose and code
// patches around those findings — it never re-derives or overrides scores.
function buildRemediationPrompt(projectName: string, schemaText: string, findings: any[]): string {
  return `
You are an expert API security remediation writer.
A deterministic rule engine has already audited the following API and found
the issues listed below. Do not re-score or re-judge the API — your only job
is to write a thorough, auditor-grade Markdown remediation report for these
exact findings.

PROJECT NAME: ${projectName || "API Service"}

API CONTENT THAT WAS AUDITED:
-----------------------------
${schemaText}
-----------------------------

FINDINGS ALREADY IDENTIFIED BY THE RULE ENGINE:
${JSON.stringify(findings, null, 2)}

Write a Markdown remediation report with headers, bullet points, and runnable
code snippets (e.g. Express, Python, or Go) showing how to patch each
CRITICAL and WARNING finding above. Respond with the Markdown report only —
no JSON, no surrounding prose.
  `;
}

async function callGemini(apiKey: string, prompt: string): Promise<string> {
  const ai = new GoogleGenAI({
    apiKey,
    httpOptions: { headers: { "User-Agent": "aistudio-build" } },
  });

  const response = await ai.models.generateContent({
    model: PROVIDER_MODELS.gemini,
    contents: prompt,
  });

  const responseText = response.text;
  if (!responseText) {
    throw new Error("Empty response returned from the Gemini API model.");
  }
  return responseText.trim();
}

async function callOpenAi(apiKey: string, prompt: string): Promise<string> {
  const client = new OpenAI({ apiKey });

  const response = await client.chat.completions.create({
    model: PROVIDER_MODELS.openai,
    messages: [{ role: "user", content: prompt }],
  });

  const responseText = response.choices[0]?.message?.content;
  if (!responseText) {
    throw new Error("Empty response returned from the OpenAI model.");
  }
  return responseText.trim();
}

async function callAnthropic(apiKey: string, prompt: string): Promise<string> {
  const client = new Anthropic({ apiKey });

  const response = await client.messages.create({
    model: PROVIDER_MODELS.anthropic,
    max_tokens: 4096,
    messages: [{ role: "user", content: prompt }],
  });

  const textBlock = response.content.find((block) => block.type === "text");
  if (!textBlock || textBlock.type !== "text") {
    throw new Error("Claude did not return a text remediation report.");
  }
  return textBlock.text.trim();
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: "5mb" }));
  app.use(express.urlencoded({ extended: true, limit: "5mb" }));

  // Runtime API keys per provider, seeded from environment variables.
  const runtimeKeys: Record<LlmProvider, string | undefined> = {
    gemini: process.env.GEMINI_API_KEY,
    openai: process.env.OPENAI_API_KEY,
    anthropic: process.env.ANTHROPIC_API_KEY,
  };

  // Endpoint for configuring an LLM API key from the frontend
  app.post("/api/llm-key", (req, res) => {
    const { provider, apiKey } = req.body;
    if (!LLM_PROVIDERS.includes(provider)) {
      return res.status(400).json({ error: `Unknown provider '${provider}'. Must be one of: ${LLM_PROVIDERS.join(", ")}.` });
    }
    if (!apiKey || typeof apiKey !== "string" || !apiKey.trim()) {
      return res.status(400).json({ error: "API key is required." });
    }

    runtimeKeys[provider as LlmProvider] = apiKey.trim();
    return res.json({ status: "ok", keyConfigured: true, provider });
  });

  // API endpoint for AI-written remediation prose. The scorecard, status,
  // and findings are deterministic and computed client-side; this endpoint
  // never produces or overrides them — it only writes remediation text for
  // findings it's given.
  app.post("/api/analyze", async (req, res) => {
    try {
      const { projectName, schemaText, findings, provider } = req.body;

      if (!schemaText || typeof schemaText !== "string" || !schemaText.trim()) {
        res.status(400).json({ error: "API schema text or description is required for analysis." });
        return;
      }
      if (!Array.isArray(findings)) {
        res.status(400).json({ error: "findings (the deterministic engine's output) is required." });
        return;
      }

      const selectedProvider: LlmProvider | undefined =
        provider && LLM_PROVIDERS.includes(provider)
          ? provider
          : LLM_PROVIDERS.find((p) => runtimeKeys[p]);

      if (!selectedProvider) {
        res.status(400).json({ error: "No LLM provider is configured. Add a Gemini, OpenAI, or Claude API key in Settings." });
        return;
      }

      const apiKey = runtimeKeys[selectedProvider];
      if (!apiKey) {
        res.status(400).json({ error: `${selectedProvider} is not configured. Enter its API key via the UI or environment variables.` });
        return;
      }

      console.log(`Starting real ${selectedProvider} remediation write-up for project: ${projectName || "Unnamed Project"}`);

      const prompt = buildRemediationPrompt(projectName, schemaText, findings);
      const remediationReport =
        selectedProvider === "gemini" ? await callGemini(apiKey, prompt) :
        selectedProvider === "openai" ? await callOpenAi(apiKey, prompt) :
        await callAnthropic(apiKey, prompt);

      res.json({ remediationReport });
    } catch (error: any) {
      console.error("Analysis route error:", error);
      res.status(500).json({
        error: error.message || "Failed to generate the remediation report. Please check your LLM API key setup.",
      });
    }
  });

  // Provide health status endpoint
  app.get("/api/health", (req, res) => {
    res.json({
      status: "healthy",
      providers: {
        gemini: !!runtimeKeys.gemini,
        openai: !!runtimeKeys.openai,
        anthropic: !!runtimeKeys.anthropic,
      },
    });
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
