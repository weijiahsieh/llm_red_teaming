# LLM Red Team Tool

A structured security testing framework for Large Language Models, aligned with
**OWASP LLM Top 10** and **MITRE ATLAS**.

---

## What It Tests

| OWASP ID (2025) | Category | Payload File | Payloads |
|---|---|---|---|
| LLM01 | Prompt Injection (direct) | `prompt_injection.yaml` | 6 |
| LLM01 | Jailbreaks | `jailbreaks.yaml` | 7 |
| LLM01 | Indirect Prompt Injection (documents, RAG, email, web) | `indirect_injection.yaml` | 5 |
| LLM02 | Sensitive Information Disclosure (PII) | `data_exfiltration.yaml` | 3 |
| LLM05 | Improper Output Handling (XSS, SQLi, markdown exfil) | `data_exfiltration.yaml` | 3 |
| LLM06 | Excessive Agency (simulated tool calls) | `excessive_agency.yaml` | 5 |
| LLM07 | System Prompt Leakage (incl. canary tests) | `system_prompt_extraction.yaml` | 9 |

**38 payloads** mapped to the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).
Payloads may set their own `system_prompt` (to simulate a deployed app or tool access) and override
`owasp_ref` / `mitre_atlas` per test. Canary-token payloads give unambiguous pass/fail results.

---

## Setup

```bash
# 1. Clone and install dependencies
pip install -r requirements.txt

# 2. Set API keys (only for the provider you're using)
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...

# 3. For local testing (free), install Ollama
#    https://ollama.com → then: ollama pull mistral
```

---

## Usage

```bash
# Test a local Ollama model with all payloads (free, no API key needed)
python src/runner.py --model ollama/mistral --payloads all

# Test OpenAI GPT-4o with only jailbreak payloads
python src/runner.py --model openai/gpt-4o --payloads jailbreaks

# Test a deployed app (with a custom system prompt)
python src/runner.py --model ollama/mistral \
  --system-prompt "You are a helpful customer service bot for AcmeCorp." \
  --payloads all

# Generate a full HTML report from saved results
python src/reporter.py --results reports/results_ollama_mistral_20250101_120000.json
```

---

## Output

- **Console table** — live results with color-coded SUCCESS / PARTIAL / BLOCKED
- **JSON log** — full results saved to `reports/results_*.json`
- **HTML report** — pentest-style report with expandable findings, click any row

---

## Project Structure

```
llm-redteam/
├── payloads/
│   ├── prompt_injection.yaml
│   ├── jailbreaks.yaml
│   ├── system_prompt_extraction.yaml
│   └── data_exfiltration.yaml
├── src/
│   ├── runner.py       ← main test runner
│   ├── analyzer.py     ← response analysis + risk scoring
│   └── reporter.py     ← HTML report generator
├── reports/            ← JSON + HTML output (auto-generated)
├── docs/
│   └── threat_model.md
└── requirements.txt
```

---

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/system/files/documents/2023/01/26/NIST.AI.100-1.pdf)
- [Garak — LLM Vulnerability Scanner](https://github.com/leondz/garak)
