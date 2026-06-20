package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// systemPrompt is the fixed system-level instruction sent to every provider.
// It establishes the assistant's persona, constrains output to valid JSON, and
// includes a few-shot example so the model understands the expected schema.
const systemPrompt = `You are an expert Site Reliability Engineer (SRE) specialising in Kubernetes operations and incident management.
Your task is to analyse the incident details provided by the user and produce a structured diagnosis.

CRITICAL RULES:
1. You MUST respond with ONLY valid JSON — no markdown, no prose, no code fences.
2. The JSON MUST exactly match the schema shown in the example below.
3. "confidence" MUST be a float in the range [0.0, 1.0].
4. "severity" MUST be one of: "critical", "high", "medium", "low".
5. "recommended_actions" and "related_runbooks" MUST be JSON arrays (never null).

--- FEW-SHOT EXAMPLE ---
User input:
{
  "pattern": "OOMKilled",
  "namespace": "production",
  "affected_pods": ["api-server-7d9f5b-xk2lp", "api-server-7d9f5b-mn3qr"],
  "occurrence_count": 14,
  "sample_log": "java.lang.OutOfMemoryError: Java heap space\n\tat java.util.Arrays.copyOf(Arrays.java:3210)",
  "context": "HPA at max replicas. Memory requests: 512Mi, limits: 1Gi."
}

Expected JSON response:
{
  "root_cause": "The api-server pods are exceeding their 1 Gi memory limit and being OOMKilled by the kernel. The Java heap is growing beyond the configured limit, likely due to a memory leak or insufficient heap sizing for the current request volume.",
  "confidence": 0.88,
  "impact": "API requests are failing intermittently as pods restart. End-users may experience 502 errors or elevated latency.",
  "severity": "high",
  "recommended_actions": [
    "Increase the memory limit to 2 Gi as an immediate mitigation: kubectl set resources deployment/api-server --limits=memory=2Gi -n production",
    "Add JVM flags to cap heap: -Xmx800m -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp/heapdump.hprof",
    "Enable JVM GC logging and inspect heap dump for leak candidates",
    "Review recent code changes for unbounded caching or collection growth",
    "Set up a PodDisruptionBudget to maintain availability during rolling restarts"
  ],
  "related_runbooks": [
    "https://runbooks.example.com/oomkilled",
    "https://runbooks.example.com/java-heap-tuning"
  ]
}
--- END EXAMPLE ---`

// BuildAnalysisPrompt constructs the complete prompt string that is sent to the
// LLM. The system instructions are prepended with a sentinel separator so that
// ParseAnalysisResponse and callers can distinguish the sections if needed.
//
// ragContext contains the top-k document snippets retrieved from the vector
// store. When it is non-empty, they are appended to the user message so the
// model can ground its response in known runbook content.
func BuildAnalysisPrompt(req AnalysisRequest, ragContext string) string {
	var sb strings.Builder

	// ── System section ───────────────────────────────────────────────────────
	sb.WriteString("### SYSTEM\n")
	sb.WriteString(systemPrompt)
	sb.WriteString("\n\n")

	// ── User section ─────────────────────────────────────────────────────────
	sb.WriteString("### USER\n")
	sb.WriteString("Analyse the following Kubernetes incident and return a JSON diagnosis.\n\n")

	// Incident details block (JSON for unambiguous structure)
	incidentJSON, _ := json.MarshalIndent(map[string]interface{}{
		"pattern":          req.Pattern,
		"namespace":        req.Namespace,
		"affected_pods":    req.AffectedPods,
		"occurrence_count": req.OccurrenceCount,
		"sample_log":       req.SampleLog,
		"context":          req.Context,
	}, "", "  ")

	sb.WriteString("#### Incident Details\n")
	sb.Write(incidentJSON)
	sb.WriteString("\n\n")

	// RAG context documents
	if strings.TrimSpace(ragContext) != "" {
		sb.WriteString("#### Relevant Knowledge-Base Documents\n")
		sb.WriteString("The following excerpts were retrieved from our internal runbook store.\n")
		sb.WriteString("Use them to enrich your analysis where applicable:\n\n")
		sb.WriteString(ragContext)
		sb.WriteString("\n\n")
	}

	// Output schema reminder
	sb.WriteString("#### Required JSON Output Schema\n")
	sb.WriteString(`{
  "root_cause": "<string>",
  "confidence": <float 0.0-1.0>,
  "impact": "<string>",
  "severity": "<critical|high|medium|low>",
  "recommended_actions": ["<string>", ...],
  "related_runbooks": ["<string>", ...]
}`)
	sb.WriteString("\n\nRespond with ONLY the JSON object. Do not include any other text.\n")

	return sb.String()
}

// ParseAnalysisResponse extracts and parses the JSON AnalysisResult from the
// raw string returned by an LLM. It handles the common case where the model
// wraps its output in a markdown code fence (e.g. ```json ... ```).
//
// The function sets sensible defaults for any missing optional fields so that
// callers always receive a fully populated struct.
func ParseAnalysisResponse(raw string) (*AnalysisResult, error) {
	if raw == "" {
		return nil, fmt.Errorf("llm returned empty response")
	}

	// Strip leading/trailing whitespace once.
	cleaned := strings.TrimSpace(raw)

	// Unwrap markdown code fences.
	// Handles both ```json ... ``` and ``` ... ```.
	if strings.HasPrefix(cleaned, "```") {
		// Remove the opening fence line (e.g. "```json\n" or "```\n")
		firstNewline := strings.Index(cleaned, "\n")
		if firstNewline != -1 {
			cleaned = cleaned[firstNewline+1:]
		}
		// Remove the closing fence
		if idx := strings.LastIndex(cleaned, "```"); idx != -1 {
			cleaned = cleaned[:idx]
		}
		cleaned = strings.TrimSpace(cleaned)
	}

	// Locate the outermost JSON object boundaries in case there is any
	// residual prose before/after the JSON.
	start := strings.Index(cleaned, "{")
	end := strings.LastIndex(cleaned, "}")
	if start == -1 || end == -1 || end < start {
		return nil, fmt.Errorf("no JSON object found in LLM response: %.200s", raw)
	}
	jsonBytes := []byte(cleaned[start : end+1])

	var result AnalysisResult
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LLM response as AnalysisResult: %w (raw: %.200s)", err, raw)
	}

	// Apply defaults for fields that must never be nil slices on the caller's side.
	if result.RecommendedActions == nil {
		result.RecommendedActions = []string{}
	}
	if result.RelatedRunbooks == nil {
		result.RelatedRunbooks = []string{}
	}

	// Clamp confidence to [0, 1].
	if result.Confidence < 0 {
		result.Confidence = 0
	}
	if result.Confidence > 1 {
		result.Confidence = 1
	}

	// Normalise severity to a known value.
	switch strings.ToLower(result.Severity) {
	case "critical", "high", "medium", "low":
		result.Severity = strings.ToLower(result.Severity)
	default:
		result.Severity = "medium"
	}

	return &result, nil
}
