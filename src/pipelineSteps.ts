export interface PipelineStep {
  id: string;
  name: string;
  subLabel: string;
  desc: string;
  logPattern: string[];
}

export const PIPELINE_STEPS: PipelineStep[] = [
  {
    id: "upload",
    name: "Upload Package",
    subLabel: "OpenAPI + Code + Config",
    desc: "Ingesting files, directory configurations, and swagger specifications.",
    logPattern: [
      "Detected package.json, openapi.yaml, and code sources",
      "Scanning file tree topology for API entry points",
      "Package payload parsed: 12 submodules, 3 routes modules"
    ]
  },
  {
    id: "parser",
    name: "AST Route Matcher",
    subLabel: "Syntax & Structure Analysis",
    desc: "Compiling programmatic endpoint trees and router definitions.",
    logPattern: [
      "Evaluating router structures without AI dependencies",
      "Mapping relative endpoint pathways with middleware indices",
      "Binding input parameters and payload boundaries"
    ]
  },
  {
    id: "extractor",
    name: "Domain Extractor",
    subLabel: "Data Model Recovery",
    desc: "Extracting entity boundaries, data models, and dependency trees.",
    logPattern: [
      "Extracting domain entities: 'User', 'PaymentIntent', 'Subscription'",
      "Evaluating request payload schemas against DB boundaries",
      "Tracing internal subservice data dependency trees"
    ]
  },
  {
    id: "graph",
    name: "State Graph Builder",
    subLabel: "Action Transition Maps",
    desc: "Constructing reactive graphs of possible API state transitions.",
    logPattern: [
      "Constructing state transition nodes representing controller logic",
      "Tracing state paths with transition rules: init -> pending -> captured",
      "Graph resolved: 18 state transitions, 3 cyclic loops found"
    ]
  },
  {
    id: "simulation",
    name: "Simulation Engine",
    subLabel: "Failure Scenario Runner",
    desc: "Subjecting the state graph to concurrent edge cases and fuzzing.",
    logPattern: [
      "Simulating threat vectors: network latency, token expiry, null references",
      "Triggering failure scenario runner: 5 hazard injections initiated",
      "Detected drift in failure recovery handling under load scenario"
    ]
  },
  {
    id: "risk",
    name: "Risk Engine",
    subLabel: "Threat Rating & Scoring",
    desc: "Scoring vulnerabilities based on OWASP Top 10 and STRIDE security thresholds.",
    logPattern: [
      "Analyzing security gaps against OWASP API Security Top 10",
      "Risk Score adjusted: High exposure on unauthorized transition in gateway",
      "Categorizing risk tags: BOLA, Broken authentication, Mass Assignment"
    ]
  },
  {
    id: "explanation",
    name: "AI Explanation Layer",
    subLabel: "Gemini Remediator (Optional)",
    desc: "Enabling semantic feedback and custom code patches on-demand.",
    logPattern: [
      "Securing AI endpoint triggers",
      "Ready to synthesize custom explanation summaries on clicked vulnerabilities"
    ]
  },
  {
    id: "dashboard",
    name: "UI Dashboard",
    subLabel: "Visual Output Delivery",
    desc: "Syncing audit telemetry to active scorecards and findings lists.",
    logPattern: [
      "Formulating metrics payload: Readiness 92%, Security 88%",
      "Pushing real-time updates to live telemetry visualizer",
      "Analysis pipeline execution completed!"
    ]
  }
];
