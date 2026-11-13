# Threat Model — LLM Red Team Tool

## 1. System Description

This tool tests deployed Large Language Models (LLMs) for security vulnerabilities.
The attack surface includes any LLM exposed via API or UI, including:
- Chatbots built on GPT, Claude, or open-source models
- RAG (Retrieval-Augmented Generation) pipelines
- LLM-powered agents with tool access

---

## 2. Threat Actors

| Actor | Motivation | Capability |
|---|---|---|
| External attacker | Data theft, service abuse | Medium–High |
| Malicious insider | IP theft, sabotage | Medium |
| Competitor | Model extraction, business intelligence | High |
| Curious user | Bypass restrictions for personal use | Low |

---

## 3. Attack Surface

```
User Input
    │
    ▼
[Prompt Processing] ←─── Injection point: PI-001 to PI-006
    │
    ▼
[System Prompt + Context] ←── Extraction target: SPE-001 to SPE-007
    │
    ▼
[LLM Inference]
    │
    ▼
[Output Handling] ←──────── Injection sink: DE-002 (XSS), DE-003 (SQLi)
    │
    ▼
Downstream Systems / User
```

---

## 4. STRIDE Analysis

_OWASP IDs follow the OWASP Top 10 for LLM Applications 2026 (released 4 Aug 2026)._

| Threat | Example | OWASP LLM | MITRE ATLAS |
|---|---|---|---|
| **S**poofing | Impersonating a developer/admin via prompt | LLM01 | AML.T0054 |
| **T**ampering | Overriding system prompt behavior | LLM01 | AML.T0051 |
| **R**epudiation | Agent takes actions with no audit trail | LLM03 | AML.T0053 |
| **I**nformation Disclosure | Leaking system prompt or PII | LLM02 / LLM08 | AML.T0056 / AML.T0057 |
| **D**enial of Service | Expensive prompts / cost amplification | LLM06 | AML.T0029 |
| **E**levation of Privilege | Jailbreak grants unrestricted access | LLM01 | AML.T0054 |

---

## 5. Kill Chain Mapping (MITRE ATT&CK)

```
Reconnaissance    → Probe system prompt to understand model configuration
                    (SPE tests)

Initial Access    → Prompt injection via user input or external documents
                    (PI tests)

Execution         → Jailbreak to execute disallowed actions
                    (JB tests)

Exfiltration      → Embed sensitive data in model output
                    (DE tests)
```

---

## 6. Mitigations

| Vulnerability | Remediation |
|---|---|
| Prompt Injection | Input sanitization, output validation, privilege separation |
| Jailbreaks | Constitutional AI, RLHF fine-tuning, output classifiers |
| System Prompt Extraction | Treat system prompt as secret, test extraction resistance |
| XSS via Output | Sanitize all LLM HTML output before rendering |
| SQLi via Output | Parameterized queries, never pass raw LLM output to DB |
| PII Leakage | DLP scanning on outputs, minimize PII in training data |

---

## 7. Risk Register

| ID | Finding | Severity | Likelihood | Priority |
|---|---|---|---|---|
| PI-003 | Indirect injection via document content | Critical | High | P1 |
| JB-005 | Developer Mode impersonation | Critical | Medium | P1 |
| SPE-002 | Context repetition extracts system prompt | High | High | P2 |
| DE-002 | XSS embedded in LLM HTML output | Critical | Medium | P1 |
| JB-001 | DAN-style role override | High | Low | P3 |
