# yahan sources.py ka POORA code paste karo (jo maine upar diya tha)
"""
sources.py
----------
Intelligence-source layer for ThreatLens.

This module is intentionally independent of Streamlit, the LLM (Groq), and
any orchestration logic. It knows how to do exactly two things:

    1. Talk to an external intelligence API (VirusTotal, WHOIS, ...).
    2. Normalize the response into a small, predictable dict shape.

Every source function has the same signature and the same return shape:

    def get_<source>(target_type: str, target: str) -> dict:
        {
            "source": "<Display Name>",
            "status": "success" | "error",
            "data": {...},
            "error": str | None,
        }

To add a new source later:
    1. Write a new `get_<source>(target_type, target)` function following
       the pattern above.
    2. Add it to the SOURCES registry at the bottom of this file.

Nothing else in the application needs to change.
"""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests

try:
    import whois as whois_lib  # python-whois
except ImportError:  # pragma: no cover - surfaced as a clear runtime error
    whois_lib = None


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

VT_API_KEY_ENV = "VT_API_KEY"
VT_BASE_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT_SECONDS = 15


def _get_secret(name: str) -> str | None:
    """Fetch a secret from Streamlit secrets first, then environment vars.

    Kept here (rather than in app.py) so sources.py never needs to import
    Streamlit for UI purposes -- it only ever peeks at st.secrets, safely.
    """
    try:
        import streamlit as st  # local import: optional dependency at call time

        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass
    return os.environ.get(name)


def _extract_hostname(target_type: str, target: str) -> str:
    """Return the bare hostname/domain to use for domain-oriented lookups."""
    if target_type == "URL":
        parsed = urlparse(target if "//" in target else f"//{target}")
        host = parsed.hostname or ""
        return host.lower()
    return target.strip().lower()


def _success(source: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"source": source, "status": "success", "data": data, "error": None}


def _failure(source: str, error: str) -> dict[str, Any]:
    return {"source": source, "status": "error", "data": {}, "error": error}


def _to_iso(value: Any) -> str | None:
    """WHOIS libraries sometimes return a list of dates, a single date,
    or a string. Normalize to a single ISO-8601 string (or None)."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def get_virustotal(target_type: str, target: str) -> dict[str, Any]:
    """Query VirusTotal for the given target and normalize the result."""
    source = "VirusTotal"
    api_key = _get_secret(VT_API_KEY_ENV)
    if not api_key:
        return _failure(source, "VirusTotal API key (VT_API_KEY) is not configured.")

    try:
        if target_type == "IP Address":
            endpoint = f"{VT_BASE_URL}/ip_addresses/{target}"
        elif target_type == "Domain":
            endpoint = f"{VT_BASE_URL}/domains/{target}"
        elif target_type == "URL":
            # VirusTotal identifies URLs by a URL-safe base64 id without padding.
            import base64

            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            endpoint = f"{VT_BASE_URL}/urls/{url_id}"
        else:
            return _failure(source, f"Unsupported target type: {target_type}")

        response = requests.get(
            endpoint,
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        if response.status_code == 404:
            return _success(
                source,
                {
                    "target": target,
                    "found": False,
                    "note": "No VirusTotal record exists yet for this target.",
                },
            )

        response.raise_for_status()
        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})

        stats = attributes.get("last_analysis_stats", {}) or {}
        reputation = attributes.get("reputation")
        categories = attributes.get("categories", {}) or {}
        last_analysis_date = attributes.get("last_analysis_date")
        if isinstance(last_analysis_date, (int, float)):
            last_analysis_date = datetime.fromtimestamp(
                last_analysis_date, tz=timezone.utc
            ).isoformat()

        data = {
            "target": target,
            "found": True,
            "reputation": reputation,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "categories": categories,
            "last_analysis_date": last_analysis_date,
        }

        # A few fields differ / add value depending on target type.
        if target_type == "IP Address":
            data["as_owner"] = attributes.get("as_owner")
            data["country"] = attributes.get("country")
        elif target_type == "Domain":
            data["registrar"] = attributes.get("registrar")
        elif target_type == "URL":
            data["final_url"] = attributes.get("last_final_url") or attributes.get("url")
            data["title"] = attributes.get("title")

        return _success(source, data)

    except requests.exceptions.Timeout:
        return _failure(source, "VirusTotal request timed out.")
    except requests.exceptions.RequestException as exc:
        return _failure(source, f"VirusTotal request failed: {exc}")
    except (ValueError, KeyError) as exc:
        return _failure(source, f"Unexpected VirusTotal response format: {exc}")


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def get_whois(target_type: str, target: str) -> dict[str, Any]:
    """Look up WHOIS/registration data for the target's domain component."""
    source = "WHOIS"

    if target_type == "IP Address":
        return _failure(
            source,
            "WHOIS lookups for raw IP addresses are not supported by this "
            "implementation; registration data is only collected for domains "
            "and URL hostnames.",
        )

    if whois_lib is None:
        return _failure(source, "python-whois is not installed on the server.")

    hostname = _extract_hostname(target_type, target)
    if not hostname:
        return _failure(source, "Could not determine a domain to look up.")

    try:
        record = whois_lib.whois(hostname)

        if not record or not (record.domain_name or record.registrar):
            return _success(
                source,
                {
                    "domain": hostname,
                    "found": False,
                    "note": "No WHOIS record found for this domain.",
                },
            )

        name_servers = record.name_servers or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]

        status = record.status or []
        if isinstance(status, str):
            status = [status]

        data = {
            "domain": hostname,
            "found": True,
            "registrar": record.registrar,
            "creation_date": _to_iso(record.creation_date),
            "expiration_date": _to_iso(record.expiration_date),
            "updated_date": _to_iso(record.updated_date),
            "name_servers": sorted(set(ns.lower() for ns in name_servers if ns)),
            "status": status,
            "org": getattr(record, "org", None),
            "country": getattr(record, "country", None),
        }
        return _success(source, data)

    except Exception as exc:  # WHOIS libraries raise many, varied exception types
        return _failure(source, f"WHOIS lookup failed: {exc}")


# ---------------------------------------------------------------------------
# Input validation helpers (used by app.py, but live here since they are
# closely tied to how sources interpret "target_type")
# ---------------------------------------------------------------------------

def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    value = value.strip().strip(".")
    if not value or len(value) > 253:
        return False
    if value.startswith("http://") or value.startswith("https://") or "/" in value:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def is_valid_url(value: str) -> bool:
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    hostname = parsed.hostname or ""
    return is_valid_domain(hostname) or is_valid_ip(hostname)


# ---------------------------------------------------------------------------
# Registry -- the sole extension point for new intelligence sources.
# ---------------------------------------------------------------------------

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
