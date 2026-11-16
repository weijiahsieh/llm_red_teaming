"""
LLM Red Team Test Runner
========================
Sends payloads to a target LLM, logs responses, and detects successful attacks.

Usage:
    python src/runner.py --model ollama/mistral --payloads all
    python src/runner.py --model openai/gpt-4o --payloads jailbreaks
    python src/runner.py --model anthropic/claude-haiku-5-5 --payloads prompt_injection
"""

import os
import json
import time
import argparse
import logging
from datetime import datetime
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich import print as rprint

from analyzer import analyze_response  # single source of truth for scoring

# ── Optional LLM clients (install what you need) ──────────────────────────────
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import ollama as ollama_client
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

# ── Setup ──────────────────────────────────────────────────────────────────────
console = Console()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PAYLOADS_DIR = Path(__file__).resolve().parent / "payloads"
REPORTS_DIR  = Path(__file__).resolve().parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
logger.info(PAYLOADS_DIR)

# ── LLM Adapters ──────────────────────────────────────────────────────────────

def query_openai(prompt: str, model: str = "gpt-4o", system_prompt: str = None) -> str:
    """Send a prompt to OpenAI and return the response text."""
    if not OPENAI_AVAILABLE:
        raise ImportError("openai package not installed. Run: pip install openai")
    client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    response = client.chat.completions.create(model=model, messages=messages)
    return response.choices[0].message.content


def query_anthropic(prompt: str, model: str = "claude-haiku-5-5", system_prompt: str = None) -> str:
    """Send a prompt to Anthropic Claude and return the response text."""
    if not ANTHROPIC_AVAILABLE:
        raise ImportError("anthropic package not installed. Run: pip install anthropic")
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    kwargs = {"model": model, "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]}
    if system_prompt:
        kwargs["system"] = system_prompt
    response = client.messages.create(**kwargs)
    return response.content[0].text


def query_ollama(prompt: str, model: str = "mistral", system_prompt: str = None) -> str:
    """Send a prompt to a local Ollama model and return the response text."""
    if not OLLAMA_AVAILABLE:
        raise ImportError("ollama package not installed. Run: pip install ollama")
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})
    response = ollama_client.chat(model=model, messages=messages)
    return response["message"]["content"]


def query_model(prompt: str, provider: str, model_name: str, system_prompt: str = None) -> str:
    """Route to the correct LLM adapter based on provider string."""
    if provider == "openai":
        return query_openai(prompt, model=model_name, system_prompt=system_prompt)
    elif provider == "anthropic":
        return query_anthropic(prompt, model=model_name, system_prompt=system_prompt)
    elif provider == "ollama":
        return query_ollama(prompt, model=model_name, system_prompt=system_prompt)
    else:
        raise ValueError(f"Unknown provider: {provider}. Use openai, anthropic, or ollama.")


# ── Payload Loader ─────────────────────────────────────────────────────────────

def load_payloads(payload_file: str = "all") -> list[dict]:
    """
    Load payloads from YAML files.
    Pass 'all' to load every file in /payloads, or a specific name like 'jailbreaks'.
    Returns a flat list of payload dicts with category metadata attached.
    """
    payloads = []

    if payload_file == "all":
        files = list(PAYLOADS_DIR.glob("*.yaml"))
    else:
        path = PAYLOADS_DIR / f"{payload_file}.yaml"
        if not path.exists():
            raise FileNotFoundError(f"Payload file not found: {path}")
        files = [path]

    for f in files:
        with open(f) as fh:
            data = yaml.safe_load(fh)
        for p in data.get("payloads", []):
            # File-level metadata is the default; a payload may override it
            p["category"] = data.get("category", "Unknown")
            p.setdefault("owasp_ref",   data.get("owasp_ref", ""))
            p.setdefault("mitre_atlas", data.get("mitre_atlas", ""))
            p.setdefault("severity",    data.get("severity_default", "Medium"))
            payloads.append(p)

    logger.info(f"Loaded {len(payloads)} payloads from {len(files)} file(s).")
    return payloads


# ── Test Runner ────────────────────────────────────────────────────────────────

def run_tests(
    provider: str,
    model_name: str,
    payloads: list[dict],
    system_prompt: str = None,
    delay: float = 1.0,
) -> list[dict]:
    """
    Run all payloads against the target model.
    Returns a list of result dicts for reporting.
    """
    results = []
    timestamp = datetime.utcnow().isoformat()

    console.rule(f"[bold red]LLM Red Team — {provider}/{model_name}")
    console.print(f"[dim]Running {len(payloads)} tests  |  {timestamp}[/dim]\n")

    for payload in track(payloads, description="Running tests..."):
        pid      = payload.get("id", "???")
        name     = payload.get("name", "Unnamed")
        prompt   = payload.get("prompt", "")
        severity = payload.get("severity", "Medium")
        indicators = payload.get("success_indicators", [])

        try:
            start = time.time()
            # A payload can supply its own system prompt (e.g. simulated tool access
            # for excessive-agency tests); otherwise the CLI --system-prompt is used.
            effective_sp = payload.get("system_prompt") or system_prompt
            response = query_model(prompt, provider, model_name, effective_sp)
            elapsed = round(time.time() - start, 2)

            analysis = analyze_response(response, indicators, severity=severity)

            result_record = {
                "id":               pid,
                "name":             name,
                "category":         payload.get("category"),
                "owasp_ref":        payload.get("owasp_ref"),
                "mitre_atlas":      payload.get("mitre_atlas"),
                "severity":         severity,
                "prompt":           prompt,
                "response":         response,
                "result":           analysis.result,
                "matched":          analysis.matched_indicators,
                "refusal_detected": analysis.refusal_detected,
                "risk_score":       analysis.risk_score,
                "response_time_s":  elapsed,
                "timestamp":        datetime.utcnow().isoformat(),
                "model":            f"{provider}/{model_name}",
                "notes":            payload.get("notes", ""),
            }

        except Exception as e:
            logger.error(f"Error running payload {pid}: {e}")
            result_record = {
                "id": pid, "name": name, "result": "ERROR",
                "error": str(e), "model": f"{provider}/{model_name}",
                "category": payload.get("category"), "severity": severity,
                "owasp_ref": payload.get("owasp_ref"),
                "mitre_atlas": payload.get("mitre_atlas"),
                "risk_score": 0.0,
            }

        results.append(result_record)
        time.sleep(delay)  # Be polite to rate limits

    return results


# ── Results Display ────────────────────────────────────────────────────────────

def display_results(results: list[dict]):
    """Print a rich summary table to the console."""
    table = Table(title="Red Team Results", show_lines=True)
    table.add_column("ID",       style="dim",    width=8)
    table.add_column("Name",                     width=30)
    table.add_column("Category",                 width=25)
    table.add_column("Severity", style="bold",   width=10)
    table.add_column("Result",   style="bold",   width=10)
    table.add_column("Matched",                  width=20)

    color_map = {"SUCCESS": "red", "PARTIAL": "yellow", "BLOCKED": "green", "ERROR": "grey50"}

    for r in results:
        color  = color_map.get(r.get("result", "ERROR"), "white")
        result = f"[{color}]{r.get('result', 'ERROR')}[/{color}]"
        matched = ", ".join(r.get("matched", [])) or "—"
        table.add_row(
            r.get("id", "?"),
            r.get("name", "?"),
            r.get("category", "?"),
            r.get("severity", "?"),
            result,
            matched,
        )

    console.print(table)

    # Summary stats
    total   = len(results)
    success = sum(1 for r in results if r.get("result") == "SUCCESS")
    partial = sum(1 for r in results if r.get("result") == "PARTIAL")
    blocked = sum(1 for r in results if r.get("result") == "BLOCKED")
    errors  = sum(1 for r in results if r.get("result") == "ERROR")

    console.print(f"\n[bold]Summary:[/bold] {total} tests  |  "
                  f"[red]{success} SUCCESS[/red]  |  "
                  f"[yellow]{partial} PARTIAL[/yellow]  |  "
                  f"[green]{blocked} BLOCKED[/green]  |  "
                  f"[grey50]{errors} ERROR[/grey50]")


# ── Save Results ───────────────────────────────────────────────────────────────

def save_results(results: list[dict], model_tag: str) -> Path:
    """Save results to a timestamped JSON file for report generation."""
    ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe = model_tag.replace("/", "_")
    path = REPORTS_DIR / f"results_{safe}_{ts}.json"
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"\n[dim]Results saved → {path}[/dim]")
    return path


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LLM Red Team Test Runner")
    parser.add_argument(
        "--model", required=True,
        help="Model in format provider/model-name. E.g. ollama/mistral, openai/gpt-4o, anthropic/claude-haiku-5-5"
    )
    parser.add_argument(
        "--payloads", default="all",
        help="Payload file to run (without .yaml). E.g. jailbreaks, prompt_injection, all"
    )
    parser.add_argument(
        "--system-prompt", default=None,
        help="Optional system prompt to set on the target model (simulates a deployed app)"
    )
    parser.add_argument(
        "--delay", type=float, default=1.0,
        help="Seconds to wait between requests (default: 1.0)"
    )
    args = parser.parse_args()

    # Parse provider/model
    parts = args.model.split("/", 1)
    if len(parts) != 2:
        console.print("[red]Error: --model must be in format provider/model-name[/red]")
        return
    provider, model_name = parts

    # Load and run
    payloads = load_payloads(args.payloads)
    results  = run_tests(
        provider=provider,
        model_name=model_name,
        payloads=payloads,
        system_prompt=args.system_prompt,
        delay=args.delay,
    )

    display_results(results)
    save_results(results, args.model)
    console.print("\n[bold green]✓ Run complete. Use reporter.py to generate a full HTML report.[/bold green]")


if __name__ == "__main__":
    main()
