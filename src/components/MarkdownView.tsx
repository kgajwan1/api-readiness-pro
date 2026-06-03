import React, { useState } from "react";
import { Check, Copy } from "lucide-react";

interface MarkdownViewProps {
  content: string;
}

export default function MarkdownView({ content }: MarkdownViewProps) {
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const handleCopy = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedText(code);
    setTimeout(() => setCopiedText(null), 2000);
  };

  if (!content) {
    return <div className="text-on-surface-variant italic text-sm">No remediation guide compiled yet. Trigger a scan first.</div>;
  }

  // Basic markdown parser that splits by lines and parses custom block structures (headers, code blocks)
  const lines = content.split("\n");
  const parsedNodes: React.ReactNode[] = [];

  let inCodeBlock = false;
  let codeBlockLines: string[] = [];
  let codeBlockLang = "";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Handle code block boundaries
    if (line.trim().startsWith("```")) {
      if (inCodeBlock) {
        // End code block
        const codeText = codeBlockLines.join("\n");
        const currentLang = codeBlockLang;
        const currentRef = `code-${i}`;

        parsedNodes.push(
          <div key={currentRef} className="my-4 bg-surface rounded-lg border border-outline-variant overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 bg-surface-container border-b border-outline-variant text-[11px] text-on-surface-variant font-mono">
              <span>{currentLang.toUpperCase() || "CODE SNIPPET"}</span>
              <button
                onClick={() => handleCopy(codeText)}
                className="flex items-center gap-1.5 px-2 py-1 rounded bg-surfacehover:bg-surface-container-high text-on-surface hover:text-primary transition-colors cursor-pointer"
              >
                {copiedText === codeText ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-secondary" />
                    <span className="text-secondary text-[10px]">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-4 overflow-x-auto text-xs font-mono text-primary leading-relaxed bg-[#020617]">
              <code>{codeText}</code>
            </pre>
          </div>
        );

        inCodeBlock = false;
        codeBlockLines = [];
      } else {
        // Start code block
        inCodeBlock = true;
        codeBlockLang = line.trim().slice(3) || "typescript";
      }
      continue;
    }

    if (inCodeBlock) {
      codeBlockLines.push(line);
      continue;
    }

    const trimmed = line.trim();

    // Headers
    if (trimmed.startsWith("# ")) {
      parsedNodes.push(
        <h1 key={`h1-${i}`} className="text-xl md:text-2xl font-bold text-on-surface tracking-tight mt-6 mb-3 border-b border-outline-variant pb-2">
          {trimmed.slice(2)}
        </h1>
      );
    } else if (trimmed.startsWith("## ")) {
      parsedNodes.push(
        <h2 key={`h2-${i}`} className="text-lg font-semibold text-primary/90 tracking-tight mt-5 mb-2.5">
          {trimmed.slice(3)}
        </h2>
      );
    } else if (trimmed.startsWith("### ")) {
      parsedNodes.push(
        <h3 key={`h3-${i}`} className="text-base font-semibold text-secondary mt-4 mb-2">
          {trimmed.slice(4)}
        </h3>
      );
    }
    // Blockquotes
    else if (trimmed.startsWith("> ")) {
      parsedNodes.push(
        <blockquote key={`bq-${i}`} className="border-l-4 border-primary pl-4 py-1.5 my-3 bg-surface-container-low rounded-r-md text-on-surface-variant italic text-sm">
          {trimmed.slice(2)}
        </blockquote>
      );
    }
    // Lists
    else if (trimmed.startsWith("- ")) {
      parsedNodes.push(
        <li key={`li-${i}`} className="ml-4 list-disc text-sm text-on-surface-variant mb-1.5 leading-relaxed">
          {trimmed.slice(2)}
        </li>
      );
    } else if (/^\d+\.\s/.test(trimmed)) {
      const contentStr = trimmed.replace(/^\d+\.\s/, "");
      parsedNodes.push(
        <li key={`ol-${i}`} className="ml-4 list-decimal text-sm text-on-surface-variant mb-1.5 leading-relaxed">
          {contentStr}
        </li>
      );
    }
    // Horizontal separator
    else if (trimmed === "---") {
      parsedNodes.push(<hr key={`hr-${i}`} className="my-6 border-outline-variant" />);
    }
    // Empty line
    else if (trimmed === "") {
      parsedNodes.push(<div key={`space-${i}`} className="h-2" />);
    }
    // Standard paragraph with bold formatting
    else {
      // Basic bold parser replacement
      const matches = trimmed.match(/\*\*(.*?)\*\*/g);
      let renderedText: React.ReactNode = trimmed;

      if (matches) {
        let textParts: React.ReactNode[] = [];
        let curStr = trimmed;
        matches.forEach((match, index) => {
          const rawMatch = match.slice(2, -2);
          const splitIndex = curStr.indexOf(match);
          if (splitIndex > 0) {
            textParts.push(curStr.substring(0, splitIndex));
          }
          textParts.push(<strong key={`bold-${i}-${index}`} className="font-semibold text-on-surface">{rawMatch}</strong>);
          curStr = curStr.substring(splitIndex + match.length);
        });
        if (curStr) {
          textParts.push(curStr);
        }
        renderedText = textParts;
      }

      parsedNodes.push(
        <p key={`p-${i}`} className="text-sm text-on-surface-variant mb-3 leading-relaxed">
          {renderedText}
        </p>
      );
    }
  }

  return <div className="markdown-body text-on-surface-variant select-text">{parsedNodes}</div>;
}
