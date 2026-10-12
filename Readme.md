# 🔒 Secure Notes Platform — End-to-End DevSecOps Architecture

[![Security Pipeline](https://github.com/your-org/secure-notes/actions/workflows/devsecops-pipeline.yml/badge.svg)](https://github.com/your-org/secure-notes/actions)
[![Kubernetes Policy Engine](https://img.shields.io/badge/Policy%20Engine-Kyverno-blue.svg)](https://kyverno.io/)
[![Scanner](https://img.shields.io/badge/Security%20Scanner-Trivy-blueviolet.svg)](https://trivy.dev/)
[![Zero-Trust](https://img.shields.io/badge/Architecture-Zero--Trust-green.svg)](#security-architecture)

A hardened, microservices-based Secure Notes application built on **Amazon EKS**, leveraging a zero-trust architecture and a continuous **DevSecOps** pipeline. 

This repository demonstrates the practical implementation of **Policy-as-Code (PaC)**, shift-left security scanning, container hardening, immutable supply chain verification, and in-cluster admission enforcement.

---

## 🏛️ System & Security Architecture

The platform separates the **Frontend (React)** and **Backend API (Go)** into isolated microservices running in a dedicated `secure-notes` namespace. Network traffic and workload permissions adhere strictly to least-privilege access model.

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                   DEVSECOPS CI/CD PIPELINE                               │
│                                                                                          │
│  [ Dev Push ] ──► [ Secret & CVE Scans ] ──► [ PaC Check ] ──► [ OIDC ECR ] ──► [ SBOM ] │
└──────────────────────────────────────────────────────────────┬───────────────────────────┘
                                                               │
                                                     kubectl apply (OIDC)
                                                               │
┌──────────────────────────────────────────────────────────────▼───────────────────────────┐
│                                   AMAZON EKS CLUSTER                                     │
│                                                                                          │
│    ┌────────────────────────────────────────────────────────────────────────────────┐    │
│    │               Kyverno Admission Controller (In-Cluster Gatekeeper)             │    │
│    └────────────────────────────────────────┬───────────────────────────────────────┘    │
│                                             │ Intercepts API Requests                    │
│                                             ▼                                            │
│    ┌────────────────────────────────────────────────────────────────────────────────┐    │
│    │  secure-notes Namespace (Network Policies + Non-Root Read-Only Workloads)      │    │
│    │                                                                                │    │
│    │   [ Frontend Pod ] ───── mTLS (Istio) ─────► [ API Pod ] ─────► [ Database ]    │    │
│    │                                                                                │    │
│    └────────────────────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Security at Every Layer (Defense-in-Depth)

Security is implemented in 4 distinct layers: Code/Config, Artifact/Build, Pipeline, and Cluster Runtime.

### 1. Code & Configuration Layer (Shift-Left)
* **Zero Secrets in Git:** All secrets (JWT keys, DB credentials) are stored using Kubernetes Secrets and injected dynamically via environment variables or secret store CSI drivers.
* **Static Application Security Testing (SAST):** Local code dependencies and Go/Node modules are continuously checked for vulnerabilities against national CVE databases.
* **Policy-as-Code (PaC):** Infrastructure-as-Code (IaC) and Kubernetes manifests are pre-validated against Open Policy Agent (OPA) / Rego and Kyverno CLI policies before merging.

### 2. Container & Image Security
* **Distroless / Minimal Base Images:** Containers run on minimal base images (e.g., `distroless` or `alpine`), removing unnecessary binaries, shells (`sh`/`bash`), and utilities to drastically minimize attack surface.
* **Non-Root Execution:** All containers run explicitly as unprivileged users (`runAsNonRoot: true`, UID `10001`).
* **Read-Only Filesystems:** Container filesystems are mounted read-only (`readOnlyRootFilesystem: true`). Ephemeral workspace needs use scoped `emptyDir` volumes mounted exclusively at `/tmp`.
* **Capability Drop:** Containers drop all Linux capabilities (`capabilities.drop: ["ALL"]`) to prevent privilege escalation.

### 3. Supply Chain & Pipeline Security (CI/CD)
* **Passwordless OIDC Authentication:** GitHub Actions authenticates to AWS ECR/EKS via IAM OIDC Federation—eliminating static, long-lived `AWS_ACCESS_KEY_ID` tokens in repository secrets.
* **Automated SBOM Generation:** Software Bill of Materials (SBOM) in **SPDX JSON** format are generated natively during every build using Trivy and published as pipeline artifacts.
* **Action Pinning:** Third-party GitHub Actions are pinned to verified versions (`vX.Y.Z`) or immutable Git commit SHAs.

### 4. Runtime & Cluster Security (Amazon EKS)
* **Kyverno In-Cluster Gatekeeper:** Operates as a `ValidatingWebhookConfiguration` inside EKS. Any `kubectl apply` attempt that violates security policies (e.g., missing `readOnlyRootFilesystem` or running as `root`) is **rejected at the K8s API level**.
* **Zero-Trust Network Policies:** Default deny-all ingress traffic. Frontend communicates with Backend over strict internal network rules.
* **Seccomp Isolation:** All workloads apply `seccompProfile.type: RuntimeDefault` to restrict system calls available to running processes.

---

## 🛠️ Security Tooling Matrix

| Tool | Focus Area | Execution Location | Function |
| :--- | :--- | :--- | :--- |
| **Trivy** | Vulnerabilities & Secrets | Local CLI & CI/CD Pipeline | Scans filesystem, dependencies, Docker images, and generates SBOMs |
| **Kyverno CLI** | Policy-as-Code | Local CLI & CI/CD Pipeline | Pre-validates Kubernetes YAMLs against security standards pre-deployment |
| **Kyverno Operator**| Admission Control | Inside K8s Cluster | Active Gatekeeper; enforces runtime security policies and rejects non-compliant pods |
| **AWS OIDC** | Identity & Access | GitHub Actions to AWS | Short-lived, keyless authentication for pipeline operations |
| **Cosign / Sigstore**| Supply Chain Integrity | CI/CD & Kyverno | Signs built images and verifies signatures before execution |

---

## 📋 Policy Enforcement Example

Workloads are evaluated against strictly enforced rules both locally/CI (via CLI) and at runtime (via Kyverno):

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: enforce-pod-security-hardened
spec:
  validationFailureAction: Enforce   # Hard enforcement: Rejects non-compliant workloads
  rules:
    - name: require-non-root-and-readonly
      match:
        any:
        - resources:
            kinds: ["Pod"]
      validate:
        message: "Workloads must set securityContext.runAsNonRoot=true and readOnlyRootFilesystem=true."
        pattern:
          spec:
            containers:
              - securityContext:
                  runAsNonRoot: true
                  readOnlyRootFilesystem: true
```

---

## 🚀 Local Security Validation Workflow

Before committing changes, developers can validate manifests and code against project security policies locally:

### 1. Run Local Policy-as-Code Check
```bash
# Validate local Kubernetes manifests using Kyverno CLI
kyverno apply ./policies --resource ./k8s
```

### 2. Scan Filesystem & Dependencies for Vulnerabilities
```bash
# Scan local directory for secrets and high/critical vulnerabilities
trivy fs --severity HIGH,CRITICAL .
```

### 3. Scan Built Container Image
```bash
# Build local test image
docker build -t secure-notes-api:local ./backend

# Scan local image with Trivy
trivy image --severity HIGH,CRITICAL secure-notes-api:local
```

---

## 🔄 CI/CD DevSecOps Pipeline Flow

Every push or pull request to the `main` branch triggers the automated security workflow defined in `.github/workflows/devsecops-pipeline.yml`:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DEVSECOPS STAGE PIPELINE                        │
├───────────────┬────────────────────────────────────────────────────────┤
│ Stage 1       │ Source Code & Dependency Scan (Trivy FS)               │
│ Stage 2       │ Manifest Policy Validation (Kyverno CLI)               │
│ Stage 3       │ Image Build & Vulnerability Scan (Trivy Action)        │
│ Stage 4       │ Native SBOM Generation (SPDX Artifact Archive)         │
│ Stage 5       │ OIDC Authentication & Push to Amazon ECR               │
│ Stage 6       │ EKS Deployment & In-Cluster Kyverno Gatekeeper Audit   │
└───────────────┴────────────────────────────────────────────────────────┘
```

---

## 📄 License & Maintainers

Maintained by the **DevSecOps & Security Engineering Team**.  
Distributed under the **MIT License**.