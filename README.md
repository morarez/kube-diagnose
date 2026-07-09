# Kube-Diagnose: AI-Powered Kubernetes Log Intelligence Platform

`kube-diagnose` is a Kubernetes-native operator (built with Kubebuilder) that watches container logs, groups similar error patterns using SimHash, performs Retrieval-Augmented Generation (RAG) using a Qdrant vector database, and leverages cloud LLMs to analyze root causes and generate actionable remediation recommendations.

It includes an embedded, real-time web dashboard (powered by HTMX).

![screenshot](img/screenshot.png)

---

## Features

*   **Zero Sidecars Required**: Streams logs directly from the Kubernetes API (`pods/log` streaming) with automatic reconnection and lifecycle management.
*   **Intelligent Log Grouping (SimHash)**: Normalizes raw logs (strips IPs, UUIDs, timestamps, and numbers) and computes a 64-bit SimHash. Merges new logs into existing `Incident` custom resources if the Hamming distance is $\le 3$ to prevent alert fatigue.
*   **RAG-First Cost Minimization**: Queries a Qdrant vector database seeded with your team's runbooks, guides, and past resolutions first. If a matched resolution has high confidence ($\ge 0.75$), it resolves the incident locally, bypassing cloud LLM APIs.
*   **Built-in Real-Time Dashboard**: Serve a responsive, dark-themed dashboard directly from the operator process showing active incidents, pattern frequencies, and knowledge-base status.
*   **GitOps-Friendly Configuration**: Fully configured using Kubernetes Custom Resource Definitions (CRDs).


---

## Getting Started

### Prerequisites
*   Go v1.24+
*   Docker
*   A local Kubernetes cluster (e.g. Minikube, Kind, or Rancher Desktop)
*   `kubectl` installed and configured
*   OpenAI or Anthropic API Keys

---

### Local Development Setup

1.  **Spin up the Dev Stack**:
    Start the local Qdrant vector database:
    ```bash
    docker-compose -f deploy/docker-compose.yaml up -d
    ```
    This automatically downloads and runs **Qdrant** on port `:6333`.

2.  **Generate and Install CRDs**:
    Generate CRD manifests and install them into your cluster:
    ```bash
    make install
    ```

3.  **Run the Operator Locally**:
    Start the operator process on your machine, bound to your current active kubeconfig context:
    ```bash
    make run
    ```
    *Note: The built-in dashboard will be served at `http://localhost:8080`.*

---

## Configuration Examples

Cloud-based providers require an API key stored in a Kubernetes Secret:

### Step 1: Create a Secret with API Keys
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: platform-credentials
  namespace: default
type: Opaque
stringData:
  openai-key: sk-proj-yourActualOpenAIApiKey...
  anthropic-key: sk-ant-sid01-yourActualAnthropicApiKey...
```

### Step 2: Apply the Platform Config (`LogIntelligencePlatform`)
```yaml
apiVersion: diagnose.diagnose.k8s.io/v1alpha1
kind: LogIntelligencePlatform
metadata:
  name: platform-config
spec:
  dashboardEnabled: true
  dashboardPort: 8080
  embedding:
    provider: openai
    model: text-embedding-3-small
    apiKeySecretRef:
      name: platform-credentials
      key: openai-key
  qdrant:
    host: localhost
    httpPort: 6333
    collectionPrefix: dev-kube-diagnose
  llm:
    provider: openai
    model: gpt-4o-mini
    apiKeySecretRef:
      name: platform-credentials
      key: openai-key
  analysis:
    ragConfidenceThreshold: "0.75"
    criticalRAGConfidenceThreshold: "0.90"
    maxLLMCallsPerHour: 100
    llmCacheTTL: 24h
```

---

## 🧪 Verification & Commands

### Run Unit Tests
Bootstraps a mock Kubernetes control plane (via `envtest`), installs CRDs, and verifies all controller reconciliation flows:
```bash
make test
```

### Run Linter
Validates code style, formatting, static analysis, and syntax correctness:
```bash
make lint
```

### Build Binary
Builds the operator manager binary into `bin/manager`:
```bash
make build
```

---

## License
This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
