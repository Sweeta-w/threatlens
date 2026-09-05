"""
app.py
------
ThreatLens: IP, Domain & URL Safety Analyzer.

This file owns everything sources.py explicitly does not:
    - Streamlit UI
    - Input validation orchestration
    - Iterating the SOURCES registry
    - Building the LLM prompt from whatever SOURCES returned
    - Calling the Groq LLM API
    - Parsing / displaying the verdict and AI insight
    - Rendering source results generically

sources.py is imported, never the other way around.
"""

from __future__ import annotations

import html
import json
import os
import time
from typing import Any

import requests
import streamlit as st

from sources import SOURCES, is_valid_domain, is_valid_ip, is_valid_url

GROQ_API_KEY_ENV = "GROQ_API_KEY"
GROQ_MODEL = "openai/gpt-oss-120b"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_TIMEOUT_SECONDS = 30
CACHE_TTL_SECONDS = 300  # short-lived cache to avoid hammering APIs on rerun

VALID_VERDICTS = {"SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"}
VALID_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}

VERDICT_STYLE = {
    "SAFE": {"emoji": "🟢", "st_fn": "success"},
    "SUSPICIOUS": {"emoji": "🟠", "st_fn": "warning"},
    "MALICIOUS": {"emoji": "🔴", "st_fn": "error"},
    "UNKNOWN": {"emoji": "⚪", "st_fn": "info"},
}


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

def get_secret(name: str) -> str | None:
    try:
        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass
    return os.environ.get(name)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_target(target_type: str, target: str) -> str | None:
    """Return an error message if invalid, otherwise None."""
    target = target.strip()
    if not target:
        return "Please enter a value to analyze."

    if target_type == "IP Address" and not is_valid_ip(target):
        return "Please enter a valid IPv4 or IPv6 address."
    if target_type == "Domain" and not is_valid_domain(target):
        return "Please enter a valid domain (e.g. example.com)."
    if target_type == "URL" and not is_valid_url(target):
        return "Please enter a valid URL (e.g. https://example.com/page)."
    return None


# ---------------------------------------------------------------------------
# Source collection (cached briefly to avoid duplicate calls on rerun)
# ---------------------------------------------------------------------------

@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def collect_source_results(target_type: str, target: str) -> list[dict[str, Any]]:
    """Iterate the SOURCES registry and gather every source's result.

    A failure in one source must never prevent the others from running.
    """
    results = []
    for source_name, source_function in SOURCES.items():
        try:
            result = source_function(target_type, target)
        except Exception as exc:  # belt-and-suspenders: a source must never crash the app
            result = {
                "source": source_name,
                "status": "error",
                "data": {},
                "error": f"Unexpected error: {exc}",
            }
        results.append(result)
    return results


# ---------------------------------------------------------------------------
# Groq prompt construction + call
# ---------------------------------------------------------------------------

KNOWLEDGE_LEVEL_GUIDANCE = {
    "Beginner": (
        "Write for a beginner. Use plain, everyday language. Avoid jargon such as "
        "detailed DNS terminology or obscure threat-intelligence vocabulary. "
        "Explain what each finding means, why it matters, and what the user should "
        "pay attention to, as if you were explaining it to someone with no security "
        "background."
    ),
    "Intermediate": (
        "Write for someone with basic cybersecurity familiarity. You may use terms "
        "like detection ratio, reputation, registrar, creation date, and DNS "
        "information, but still explain how they relate to the verdict."
    ),
    "Expert": (
        "Write for a security practitioner. Provide technically detailed analysis "
        "covering threat-intelligence indicators, detection confidence, reputation "
        "signals, registration metadata, infrastructure relationships if available, "
        "and explicitly note limitations, uncertainty, or conflicting evidence "
        "between sources."
    ),
}


def build_prompt(
    target_type: str,
    target: str,
    knowledge_level: str,
    source_results: list[dict[str, Any]],
) -> str:
    """Build the LLM prompt purely from what SOURCES returned.

    This function never references "VirusTotal" or "WHOIS" by name in its
    control flow -- it loops over whatever came back from the registry, so a
    new source is automatically included with zero changes here.
    """
    evidence_blocks = []
    for result in source_results:
        name = result.get("source", "Unknown Source")
        if result.get("status") == "success":
            evidence_blocks.append(
                f"Source: {name}\nStatus: success\nData: {json.dumps(result.get('data', {}), default=str)}"
            )
        else:
            evidence_blocks.append(
                f"Source: {name}\nStatus: error\nError: {result.get('error')}"
            )
    evidence_text = "\n\n".join(evidence_blocks) if evidence_blocks else "No sources returned data."

    guidance = KNOWLEDGE_LEVEL_GUIDANCE.get(knowledge_level, KNOWLEDGE_LEVEL_GUIDANCE["Intermediate"])

    prompt = f"""You are a cybersecurity analysis assistant embedded in a tool called ThreatLens.
Your job is to evaluate whether a target is SAFE, SUSPICIOUS, MALICIOUS, or UNKNOWN, based
strictly on the evidence provided below. You are not a replacement for a professional
security investigation.

Target: {target}
Target type: {target_type}
Knowledge level of the reader: {knowledge_level}

Writing style instructions: {guidance}

Evidence collected from intelligence sources:

{evidence_text}

Rules you must follow:
1. Only use the evidence provided above. Do not invent detections, malware families,
   ownership history, vulnerabilities, threat actors, or incidents that are not present
   in the evidence.
2. Treat each source result as a signal, not proof. A clean result does not guarantee
   safety; a single flagged detection does not guarantee malicious intent. Distinguish
   between evidence, inference, and uncertainty in your summary.
3. If a source failed or returned no data, say so plainly rather than filling in a guess.
4. If the combined evidence is insufficient to make a reasonable determination (for
   example, all sources failed or returned empty data), choose the verdict UNKNOWN.
5. Respond with ONLY a single JSON object, no markdown fences, no commentary outside
   the JSON, matching exactly this shape:

{{
  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN",
  "confidence": "LOW" | "MEDIUM" | "HIGH",
  "summary": "short paragraph explaining the overall assessment",
  "key_findings": ["short bullet", "short bullet", "..."],
  "recommendation": "practical next step for the user"
}}
"""
    return prompt


def call_groq(prompt: str) -> dict[str, Any]:
    """Call the Groq chat-completions API and return a dict with either
    parsed JSON or a raw fallback.

    Groq exposes an OpenAI-compatible REST endpoint, so this is a plain
    HTTP POST via `requests` -- no extra SDK dependency needed.
    """
    api_key = get_secret(GROQ_API_KEY_ENV)
    if not api_key:
        return {
            "parsed": None,
            "raw_text": None,
            "error": "Groq API key (GROQ_API_KEY) is not configured.",
        }

    try:
        response = requests.post(
            GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
            },
            timeout=GROQ_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        raw_text = (payload["choices"][0]["message"]["content"] or "").strip()
    except requests.exceptions.Timeout:
        return {"parsed": None, "raw_text": None, "error": "Groq request timed out."}
    except requests.exceptions.RequestException as exc:
        return {"parsed": None, "raw_text": None, "error": f"Groq request failed: {exc}"}
    except (KeyError, IndexError, ValueError) as exc:
        return {"parsed": None, "raw_text": None, "error": f"Unexpected Groq response format: {exc}"}

    cleaned = raw_text
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)
    except (json.JSONDecodeError, TypeError):
        return {"parsed": None, "raw_text": raw_text, "error": None}

    return {"parsed": parsed, "raw_text": raw_text, "error": None}


def normalize_ai_result(ai_response: dict[str, Any]) -> dict[str, Any]:
    """Coerce whatever the LLM returned into a safe, display-ready shape."""
    parsed = ai_response.get("parsed")

    if not isinstance(parsed, dict):
        return {
            "verdict": "UNKNOWN",
            "confidence": "LOW",
            "summary": None,
            "key_findings": [],
            "recommendation": None,
            "raw_fallback": ai_response.get("raw_text"),
            "error": ai_response.get("error"),
        }

    verdict = str(parsed.get("verdict", "UNKNOWN")).upper()
    if verdict not in VALID_VERDICTS:
        verdict = "UNKNOWN"

    confidence = str(parsed.get("confidence", "LOW")).upper()
    if confidence not in VALID_CONFIDENCE:
        confidence = "LOW"

    key_findings = parsed.get("key_findings", [])
    if not isinstance(key_findings, list):
        key_findings = []
    key_findings = [str(item) for item in key_findings][:10]

    return {
        "verdict": verdict,
        "confidence": confidence,
        "summary": str(parsed.get("summary")) if parsed.get("summary") else None,
        "key_findings": key_findings,
        "recommendation": str(parsed.get("recommendation")) if parsed.get("recommendation") else None,
        "raw_fallback": None,
        "error": None,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_verdict(ai_result: dict[str, Any]) -> None:
    verdict = ai_result["verdict"]
    style = VERDICT_STYLE.get(verdict, VERDICT_STYLE["UNKNOWN"])
    st_fn = getattr(st, style["st_fn"])
    st_fn(f"{style['emoji']} **{verdict}** — Confidence: {ai_result['confidence'].title()}")


def render_ai_insight(ai_result: dict[str, Any]) -> None:
    st.subheader("AI Insight")

    if ai_result.get("error"):
        st.error(html.escape(ai_result["error"]))
        return

    if ai_result.get("raw_fallback") is not None:
        st.caption("The AI response could not be parsed as structured JSON. Showing raw output:")
        st.text(ai_result["raw_fallback"])
        return

    if ai_result.get("summary"):
        st.markdown("**Summary**")
        st.write(ai_result["summary"])

    if ai_result.get("key_findings"):
        st.markdown("**Key Findings**")
        for finding in ai_result["key_findings"]:
            st.markdown(f"- {finding}")

    if ai_result.get("recommendation"):
        st.markdown("**Recommendation**")
        st.write(ai_result["recommendation"])


def render_source_results(source_results: list[dict[str, Any]]) -> None:
    st.subheader("Source Results")

    for result in source_results:
        source_name = result.get("source", "Unknown Source")
        status = result.get("status")
        icon = "✅" if status == "success" else "⚠️"

        with st.expander(f"{icon} {source_name}"):
            if status != "success":
                st.warning(result.get("error") or "This source did not return a result.")
                continue

            data = result.get("data", {})
            if not data:
                st.info("No data returned.")
                continue

            # Generic rendering: operate on whatever keys/values came back,
            # rather than branching on the source's identity.
            for key, value in data.items():
                label = key.replace("_", " ").title()
                if isinstance(value, (list, tuple)):
                    if value:
                        st.markdown(f"**{label}:**")
                        for item in value:
                            st.markdown(f"- {item}")
                    else:
                        st.markdown(f"**{label}:** _none_")
                elif isinstance(value, dict):
                    if value:
                        st.markdown(f"**{label}:**")
                        st.json(value)
                    else:
                        st.markdown(f"**{label}:** _none_")
                else:
                    display_value = value if value not in (None, "") else "_unknown_"
                    st.markdown(f"**{label}:** {display_value}")


# ---------------------------------------------------------------------------
# Streamlit page
# ---------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="centered")

    st.title("🛡️ ThreatLens")
    st.caption("IP, Domain & URL Safety Analyzer — powered by VirusTotal, WHOIS, and Groq.")
    st.divider()

    missing = [name for name in ("VT_API_KEY", "GROQ_API_KEY") if not get_secret(name)]
    if missing:
        st.warning(
            "Missing configuration for: "
            + ", ".join(missing)
            + ". Set these as environment variables or Streamlit secrets before analyzing."
        )

    target_type = st.selectbox("Target Type", ["IP Address", "Domain", "URL"])
    target = st.text_input(
        "Target",
        placeholder={
            "IP Address": "8.8.8.8",
            "Domain": "example.com",
            "URL": "https://example.com/login",
        }[target_type],
    )
    knowledge_level = st.selectbox("Knowledge Level", ["Beginner", "Intermediate", "Expert"])

    analyze_clicked = st.button("🔍 Analyze", type="primary")

    if not analyze_clicked:
        st.info("This tool is for general security awareness and education, not a substitute for a professional investigation.")
        return

    error = validate_target(target_type, target)
    if error:
        st.error(error)
        return

    normalized_target = target.strip()

    with st.spinner("Collecting source intelligence..."):
        source_results = collect_source_results(target_type, normalized_target)

    with st.spinner("Analyzing target..."):
        prompt = build_prompt(target_type, normalized_target, knowledge_level, source_results)
        ai_response = call_groq(prompt)
        ai_result = normalize_ai_result(ai_response)

    st.divider()
    st.subheader("Analysis Result")
    render_verdict(ai_result)
    st.write("")
    render_ai_insight(ai_result)
    st.divider()
    render_source_results(source_results)


if __name__ == "__main__":
    main()
