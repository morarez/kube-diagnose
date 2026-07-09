package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/morarez/kube-diagnose/internal/aggregator"
	"github.com/morarez/kube-diagnose/internal/llm"
)

// handlers holds the HTTP handler dependencies.
type handlers struct {
	store    *aggregator.IncidentStore
	analyzer *llm.Analyzer
	logger   *zap.Logger
}

// ─── API Handlers ─────────────────────────────────────────────────────────────

// apiListIncidents returns all incidents as JSON.
func (h *handlers) apiListIncidents(w http.ResponseWriter, _ *http.Request) {
	records := h.store.List()
	sort.Slice(records, func(i, j int) bool {
		return records[i].LastSeen.After(records[j].LastSeen)
	})

	type incidentJSON struct {
		Fingerprint  string    `json:"fingerprint"`
		Pattern      string    `json:"pattern"`
		Namespace    string    `json:"namespace"`
		Count        int64     `json:"count"`
		Severity     string    `json:"severity"`
		Resolved     bool      `json:"resolved"`
		FirstSeen    time.Time `json:"firstSeen"`
		LastSeen     time.Time `json:"lastSeen"`
		AffectedPods int       `json:"affectedPods"`
		RootCause    string    `json:"rootCause,omitempty"`
		Confidence   float64   `json:"confidence,omitempty"`
	}

	out := make([]incidentJSON, 0, len(records))
	for _, rec := range records {
		item := incidentJSON{
			Fingerprint:  rec.Fingerprint,
			Pattern:      rec.Pattern,
			Namespace:    rec.Namespace,
			Count:        rec.Count,
			Severity:     rec.Severity,
			Resolved:     rec.Resolved,
			FirstSeen:    rec.FirstSeen,
			LastSeen:     rec.LastSeen,
			AffectedPods: len(rec.AffectedPods),
		}
		if rec.Analysis != nil {
			item.RootCause = rec.Analysis.RootCause
			item.Confidence = rec.Analysis.Confidence
		}
		out = append(out, item)
	}
	writeJSON(w, out)
}

// apiGetIncident returns a single incident by fingerprint.
func (h *handlers) apiGetIncident(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fingerprint")
	rec, ok := h.store.Get(fp)
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	pods := make([]string, 0, len(rec.AffectedPods))
	for p := range rec.AffectedPods {
		pods = append(pods, p)
	}
	sort.Strings(pods)

	type detail struct {
		Fingerprint   string                         `json:"fingerprint"`
		Pattern       string                         `json:"pattern"`
		Namespace     string                         `json:"namespace"`
		PolicyName    string                         `json:"policyName"`
		Count         int64                          `json:"count"`
		Severity      string                         `json:"severity"`
		Resolved      bool                           `json:"resolved"`
		FirstSeen     time.Time                      `json:"firstSeen"`
		LastSeen      time.Time                      `json:"lastSeen"`
		SampleMessage string                         `json:"sampleMessage"`
		AffectedPods  []string                       `json:"affectedPods"`
		Analysis      *aggregator.AnalysisResultData `json:"analysis,omitempty"`
	}
	writeJSON(w, detail{
		Fingerprint:   rec.Fingerprint,
		Pattern:       rec.Pattern,
		Namespace:     rec.Namespace,
		PolicyName:    rec.PolicyName,
		Count:         rec.Count,
		Severity:      rec.Severity,
		Resolved:      rec.Resolved,
		FirstSeen:     rec.FirstSeen,
		LastSeen:      rec.LastSeen,
		SampleMessage: rec.SampleMessage,
		AffectedPods:  pods,
		Analysis:      rec.Analysis,
	})
}

// apiStats returns platform stats.
func (h *handlers) apiStats(w http.ResponseWriter, _ *http.Request) {
	records := h.store.List()
	active, resolved := 0, 0
	for _, rec := range records {
		if rec.Resolved {
			resolved++
		} else {
			active++
		}
	}
	stats := map[string]interface{}{
		"totalIncidents":    len(records),
		"activeIncidents":   active,
		"resolvedIncidents": resolved,
	}
	if h.analyzer != nil {
		for k, v := range h.analyzer.Stats() {
			stats[k] = v
		}
	}
	writeJSON(w, stats)
}

// ─── Page Handlers ────────────────────────────────────────────────────────────

// indexPage renders the main dashboard page.
func (h *handlers) indexPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	records := h.store.List()
	active := 0
	critical := 0
	for _, rec := range records {
		if !rec.Resolved {
			active++
			if rec.Severity == "critical" {
				critical++
			}
		}
	}
	data := map[string]interface{}{
		"ActiveIncidents":   active,
		"CriticalIncidents": critical,
		"TotalIncidents":    len(records),
	}
	renderTemplate(w, indexHTML, data)
}

// incidentsPage renders the incidents list.
func (h *handlers) incidentsPage(w http.ResponseWriter, _ *http.Request) {
	records := h.store.List()
	sort.Slice(records, func(i, j int) bool {
		return records[i].LastSeen.After(records[j].LastSeen)
	})

	type row struct {
		Fingerprint        string
		Pattern            string
		Namespace          string
		Count              int64
		Severity           string
		SeverityClass      string
		AffectedPods       int
		LastSeen           string
		Resolved           bool
		RootCause          string
		Confidence         string
		Impact             string
		RecommendedActions []string
	}

	rows := make([]row, 0, len(records))
	for _, rec := range records {
		rootCause := "No analysis"
		confidence := "N/A"
		impact := "N/A"
		var actions []string
		if rec.Analysis != nil {
			rootCause = rec.Analysis.RootCause
			confidence = fmt.Sprintf("%.0f%%", rec.Analysis.Confidence*100)
			impact = rec.Analysis.Impact
			actions = rec.Analysis.RecommendedActions
		}
		rows = append(rows, row{
			Fingerprint:        rec.Fingerprint,
			Pattern:            truncate(rec.Pattern, 80),
			Namespace:          rec.Namespace,
			Count:              rec.Count,
			Severity:           rec.Severity,
			SeverityClass:      severityClass(rec.Severity),
			AffectedPods:       len(rec.AffectedPods),
			LastSeen:           rec.LastSeen.Format("2006-01-02 15:04:05"),
			Resolved:           rec.Resolved,
			RootCause:          rootCause,
			Confidence:         confidence,
			Impact:             impact,
			RecommendedActions: actions,
		})
	}
	renderTemplate(w, incidentsHTML, map[string]interface{}{"Incidents": rows})
}

// incidentDetailPage renders a single incident detail page.
func (h *handlers) incidentDetailPage(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fingerprint")
	rec, ok := h.store.Get(fp)
	if !ok {
		http.NotFound(w, r)
		return
	}

	pods := make([]string, 0, len(rec.AffectedPods))
	for p := range rec.AffectedPods {
		pods = append(pods, p)
	}
	sort.Strings(pods)

	data := map[string]interface{}{
		"Record":        rec,
		"AffectedPods":  pods,
		"FirstSeen":     rec.FirstSeen.Format(time.RFC3339),
		"LastSeen":      rec.LastSeen.Format(time.RFC3339),
		"SeverityClass": severityClass(rec.Severity),
	}
	renderTemplate(w, incidentDetailHTML, data)
}

// knowledgeBasePage renders the knowledge base page.
func (h *handlers) knowledgeBasePage(w http.ResponseWriter, _ *http.Request) {
	stats := map[string]interface{}{}
	if h.analyzer != nil {
		stats = h.analyzer.Stats()
	}
	renderTemplate(w, knowledgeBaseHTML, stats)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func renderTemplate(w http.ResponseWriter, tmplStr string, data interface{}) {
	tmpl, err := template.New("page").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
	}).Parse(tmplStr)
	if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		h := &handlers{}
		_ = h
	}
}

func severityClass(s string) string {
	switch s {
	case "critical":
		return "severity-critical"
	case "high":
		return "severity-high"
	case "medium":
		return "severity-medium"
	default:
		return "severity-low"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ─── Inline HTML Templates ────────────────────────────────────────────────────

const baseCSS = `
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --critical: #f85149; --high: #d29922; --medium: #3fb950; --low: #58a6ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    line-height: 1.6;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  nav {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0 2rem;
    display: flex;
    align-items: center;
    gap: 2rem;
    height: 56px;
  }
  nav .brand { font-size: 1.1rem; font-weight: 700; color: var(--text); }
  nav .brand span { color: var(--accent); }
  nav a { color: var(--muted); font-size: 0.9rem; }
  nav a:hover { color: var(--text); }
  .container { max-width: 1280px; margin: 0 auto; padding: 2rem; }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }
  .stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .stat {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    text-align: center;
  }
  .stat .value { font-size: 2.5rem; font-weight: 700; color: var(--accent); }
  .stat .label {
    font-size: 0.8rem;
    color: var(--muted);
    margin-top: 0.25rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left;
    padding: 0.75rem 1rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
  }
  td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.875rem; vertical-align: middle; }
  tr:hover td { background: rgba(88,166,255,0.05); }
  .badge {
    display: inline-block;
    padding: 0.2em 0.6em;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
  }
  .severity-critical { background: rgba(248,81,73,0.2); color: var(--critical); }
  .severity-high { background: rgba(210,153,34,0.2); color: var(--high); }
  .severity-medium { background: rgba(63,185,80,0.2); color: var(--medium); }
  .severity-low { background: rgba(88,166,255,0.2); color: var(--low); }
  .page-title { font-size: 1.5rem; font-weight: 700; margin-bottom: 1.5rem; }
  .mono {
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: 0.8rem;
    background: var(--bg);
    padding: 0.2em 0.5em;
    border-radius: 4px;
  }
  pre {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
    overflow: auto;
    font-size: 0.8rem;
    max-height: 300px;
  }
  .tag {
    display: inline-block;
    background: rgba(88,166,255,0.1);
    color: var(--accent);
    border: 1px solid rgba(88,166,255,0.3);
    border-radius: 4px;
    padding: 0.15em 0.5em;
    font-size: 0.75rem;
    margin: 0.15rem;
  }
</style>`

const navHTML = `
<nav>
  <span class="brand">⚡ Kube-<span>Diagnose</span></span>
  <a href="/">Overview</a>
  <a href="/incidents">Incidents</a>
  <a href="/knowledge-base">Knowledge Base</a>
</nav>`

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kube-Diagnose — Dashboard</title>
<meta name="description" content="AI-powered Kubernetes Log Intelligence Platform dashboard">` + baseCSS + `
</head>
<body>` + navHTML + `
<div class="container">
  <h1 class="page-title">Platform Overview</h1>
  <div class="stat-grid">
    <div class="stat"><div class="value">{{.ActiveIncidents}}</div><div class="label">Active Incidents</div></div>
    <div class="stat">
      <div class="value" style="color:var(--critical)">{{.CriticalIncidents}}</div>
      <div class="label">Critical</div>
    </div>
    <div class="stat"><div class="value">{{.TotalIncidents}}</div><div class="label">Total Incidents</div></div>
  </div>
  <div class="card">
    <h2 style="margin-bottom:1rem;font-size:1rem;color:var(--muted)">QUICK ACTIONS</h2>
    <p><a href="/incidents">→ View all incidents</a></p>
  </div>
  <div class="card" style="border-color:rgba(88,166,255,0.3)">
    <h2 style="margin-bottom:0.5rem;font-size:0.9rem;color:var(--muted)">HOW IT WORKS</h2>
    <p style="font-size:0.875rem;color:var(--muted)">
      Kube-Diagnose watches pod logs across namespaces, fingerprints ERROR/FATAL patterns,
      groups them into incidents, and uses RAG + LLM to suggest root causes and remediation steps.
      LLM is only called when RAG confidence is below your configured threshold.
    </p>
  </div>
</div>
</body></html>`

const incidentsHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Incidents — Kube-Diagnose</title>` + baseCSS + `
<style>
.modal {
  display: none;
  position: fixed;
  z-index: 1000;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0,0,0,0.6);
  align-items: center;
  justify-content: center;
}
.modal-content {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  width: 90%;
  max-width: 600px;
  padding: 1.5rem;
  position: relative;
  box-shadow: 0 4px 12px rgba(0,0,0,0.5);
  text-align: left;
}
.modal-close {
  position: absolute;
  right: 1.25rem;
  top: 0.75rem;
  cursor: pointer;
  font-size: 1.5rem;
  color: var(--muted);
}
.modal-close:hover {
  color: var(--text);
}
</style>
</head>
<body>` + navHTML + `
<div class="container">
  <h1 class="page-title">Incidents</h1>
  {{if not .Incidents}}
    <div class="card" style="text-align:center;color:var(--muted)">No incidents detected yet.</div>
  {{end}}
  {{if .Incidents}}
  <div class="card" style="padding:0;overflow:hidden">
  <table>
    <thead><tr>
      <th>Pattern</th><th>Namespace</th><th>Severity</th>
      <th>Count</th><th>Pods</th><th>Analysis</th><th>Confidence</th><th>Last Seen</th><th>Status</th>
    </tr></thead>
    <tbody>
    {{range .Incidents}}
    <tr>
      <td><a href="/incidents/{{.Fingerprint}}" title="{{.Pattern}}">{{.Pattern}}</a></td>
      <td><span class="tag">{{.Namespace}}</span></td>
      <td><span class="badge {{.SeverityClass}}">{{.Severity}}</span></td>
      <td>{{.Count}}</td>
      <td>{{.AffectedPods}}</td>
      <td>
        {{if ne .RootCause "No analysis"}}
          <button onclick="document.getElementById('modal-{{.Fingerprint}}').style.display='flex'" style="background:var(--accent); color:var(--bg); border:none; border-radius:4px; padding:0.25rem 0.5rem; font-size:0.75rem; font-weight:600; cursor:pointer;">View</button>
        {{else}}
          <span style="color:var(--muted); font-size:0.75rem;">None</span>
        {{end}}
      </td>
      <td><span class="badge severity-low">{{.Confidence}}</span></td>
      <td><span class="mono">{{.LastSeen}}</span></td>
      <td>
        {{if .Resolved}}
          <span style="color:var(--medium)">✓ Resolved</span>
        {{else}}
          <span style="color:var(--critical)">● Active</span>
        {{end}}
      </td>
    </tr>
    {{if ne .RootCause "No analysis"}}
    <div id="modal-{{.Fingerprint}}" class="modal" onclick="if(event.target == this) this.style.display='none'">
      <div class="modal-content" style="max-height:80vh; overflow-y:auto;">
        <span class="modal-close" onclick="document.getElementById('modal-{{.Fingerprint}}').style.display='none'">&times;</span>
        <h2 style="font-size:1.1rem; margin-bottom:1.25rem; border-bottom:1px solid var(--border); padding-bottom:0.5rem; color:var(--accent); font-weight:700;">AI Diagnosis Details</h2>
        <div style="margin-bottom:1.25rem;">
          <h3 style="font-size:0.8rem; color:var(--muted); text-transform:uppercase; margin-bottom:0.25rem; font-weight:600;">Root Cause</h3>
          <p style="font-size:0.875rem; color:var(--text); line-height:1.5; white-space:pre-wrap;">{{.RootCause}}</p>
        </div>
        <div style="margin-bottom:1.25rem;">
          <h3 style="font-size:0.8rem; color:var(--muted); text-transform:uppercase; margin-bottom:0.25rem; font-weight:600;">Impact</h3>
          <p style="font-size:0.875rem; color:var(--text); line-height:1.5; white-space:pre-wrap;">{{.Impact}}</p>
        </div>
        {{if .RecommendedActions}}
        <div>
          <h3 style="font-size:0.8rem; color:var(--muted); text-transform:uppercase; margin-bottom:0.5rem; font-weight:600;">Recommended Actions</h3>
          <ul style="font-size:0.875rem; color:var(--text); line-height:1.5; padding-left:1.25rem; margin:0;">
            {{range .RecommendedActions}}
              <li style="margin-bottom:0.5rem;">{{.}}</li>
            {{end}}
          </ul>
        </div>
        {{end}}
      </div>
    </div>
    {{end}}
    {{end}}
    </tbody>
  </table>
  </div>
  {{end}}
</div>
</body></html>`

const incidentDetailHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Incident — Kube-Diagnose</title>` + baseCSS + `
</head>
<body>` + navHTML + `
<div class="container">
  <p style="margin-bottom:1rem"><a href="/incidents">← Back to incidents</a></p>
  <h1 class="page-title">
    <span class="badge {{.SeverityClass}}" style="margin-right:0.5rem">{{.Record.Severity}}</span>
    Incident Detail
  </h1>
  <div class="card">
    <h2 style="font-size:0.8rem;color:var(--muted);margin-bottom:0.5rem">ERROR PATTERN</h2>
    <pre>{{.Record.Pattern}}</pre>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem">
    <div class="card">
      <h2 style="font-size:0.8rem;color:var(--muted);margin-bottom:0.75rem">INCIDENT METADATA</h2>
      <table><tbody>
        <tr>
          <td style="color:var(--muted);width:40%">Fingerprint</td>
          <td><span class="mono">{{.Record.Fingerprint}}</span></td>
        </tr>
        <tr><td style="color:var(--muted)">Namespace</td><td><span class="tag">{{.Record.Namespace}}</span></td></tr>
        <tr><td style="color:var(--muted)">Policy</td><td>{{.Record.PolicyName}}</td></tr>
        <tr><td style="color:var(--muted)">Occurrences</td><td>{{.Record.Count}}</td></tr>
        <tr><td style="color:var(--muted)">First Seen</td><td><span class="mono">{{.FirstSeen}}</span></td></tr>
        <tr><td style="color:var(--muted)">Last Seen</td><td><span class="mono">{{.LastSeen}}</span></td></tr>
        <tr><td style="color:var(--muted)">Resolved</td><td>{{.Record.Resolved}}</td></tr>
      </tbody></table>
    </div>
    <div class="card">
      <h2 style="font-size:0.8rem;color:var(--muted);margin-bottom:0.75rem">AFFECTED PODS ({{len .AffectedPods}})</h2>
      {{range .AffectedPods}}<span class="tag">{{.}}</span>{{end}}
      {{if not .AffectedPods}}<span style="color:var(--muted)">None recorded</span>{{end}}
    </div>
  </div>
  {{if .Record.Analysis}}
  <div class="card" style="border-color:rgba(88,166,255,0.3)">
    <h2 style="font-size:0.8rem;color:var(--muted);margin-bottom:0.75rem">
      AI ANALYSIS
      <span class="badge severity-low" style="margin-left:0.5rem">{{.Record.Analysis.AnalysisSource}}</span>
      <span style="float:right;color:var(--muted)">
        Confidence: {{printf "%.0f" (mul .Record.Analysis.Confidence 100)}}%
      </span>
    </h2>
    <p style="margin-bottom:1rem"><strong>Root Cause:</strong> {{.Record.Analysis.RootCause}}</p>
    <p style="margin-bottom:1rem"><strong>Impact:</strong> {{.Record.Analysis.Impact}}</p>
    {{if .Record.Analysis.RecommendedActions}}
    <h3 style="font-size:0.85rem;margin-bottom:0.5rem">Recommended Actions</h3>
    <ol style="padding-left:1.25rem">
      {{range .Record.Analysis.RecommendedActions}}<li style="margin-bottom:0.5rem">{{.}}</li>{{end}}
    </ol>
    {{end}}
  </div>
  {{end}}
  <div class="card">
    <h2 style="font-size:0.8rem;color:var(--muted);margin-bottom:0.5rem">SAMPLE LOG MESSAGE</h2>
    <pre>{{.Record.SampleMessage}}</pre>
  </div>
</div>
</body></html>`

const knowledgeBaseHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Knowledge Base — Kube-Diagnose</title>` + baseCSS + `
</head>
<body>` + navHTML + `
<div class="container">
  <h1 class="page-title">Knowledge Base & LLM Stats</h1>
  <div class="card">
    <h2 style="font-size:0.8rem;color:var(--muted);margin-bottom:1rem">LLM USAGE STATS</h2>
    <table><tbody>
      <tr><td style="color:var(--muted)">LLM Calls (this hour)</td><td>{{index . "llm_calls_this_hour"}}</td></tr>
      <tr><td style="color:var(--muted)">Max Calls per Hour</td><td>{{index . "max_calls_per_hour"}}</td></tr>
      <tr><td style="color:var(--muted)">Cache Size</td><td>{{index . "cache_size"}}</td></tr>
      <tr><td style="color:var(--muted)">Cache Hits (total)</td><td>{{index . "cache_hits_total"}}</td></tr>
      <tr><td style="color:var(--muted)">RAG Shortcuts (total)</td><td>{{index . "rag_shortcuts_total"}}</td></tr>
      <tr><td style="color:var(--muted)">LLM Calls (total)</td><td>{{index . "llm_calls_total"}}</td></tr>
    </tbody></table>
  </div>
  <div class="card" style="border-color:rgba(63,185,80,0.3)">
    <h2 style="font-size:0.8rem;color:var(--muted);margin-bottom:0.5rem">KNOWLEDGE BASE COLLECTIONS</h2>
    <p style="font-size:0.875rem;color:var(--muted)">Documents are indexed in Qdrant across three collections:
    <strong>runbooks</strong>, <strong>incidents</strong> (resolved), and <strong>metadata</strong>.
    Add Markdown runbooks to <code>/etc/kube-diagnose/runbooks/</code> or
    configure a ConfigMap reference in your LogIntelligencePlatform CR.</p>
  </div>
</div>
</body></html>`
