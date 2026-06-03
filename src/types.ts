export interface Finding {
  endpoint: string;
  severity: "CRITICAL" | "WARNING" | "INFO";
  category: string;
  description: string;
}

export interface Insight {
  text: string;
  type: "critical" | "warning" | "success";
  timestamp: string;
}

export interface ProjectAnalysis {
  id: string;
  projectName: string;
  lastScan: string;
  endpointCount: number;
  status: "READY" | "NEEDS REVIEW" | "CRITICAL";
  overallScore: number;
  securityScore: number;
  documentationScore: number;
  schemaText: string;
  findings: Finding[];
  insights: Insight[];
  remediationReport: string;
}
