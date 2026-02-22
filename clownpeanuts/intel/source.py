"""Source IP enrichment and summary helpers."""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Any


_COUNTRIES: tuple[tuple[str, str], ...] = (
    ("US", "United States"),
    ("CA", "Canada"),
    ("GB", "United Kingdom"),
    ("DE", "Germany"),
    ("FR", "France"),
    ("NL", "Netherlands"),
    ("IN", "India"),
    ("JP", "Japan"),
    ("SG", "Singapore"),
    ("AU", "Australia"),
    ("BR", "Brazil"),
    ("ZA", "South Africa"),
)

_ORGS: tuple[str, ...] = (
    "TransitWave Networks",
    "BlueNorth Telecom",
    "EdgeMesh Hosting",
    "VectorSky Systems",
    "Aperture Fiber",
    "Signal Harbor",
    "Nimbus Relay",
    "Catalyst Backbone",
)


def enrich_source_ip(source_ip: str) -> dict[str, Any]:
    raw = source_ip.strip()
    if not raw:
        return _unknown_source()

    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return _unknown_source()

    if not ip.is_global:
        return {
            "source_ip": raw,
            "asn": {
                "label": "AS-PRIVATE",
                "number": 0,
                "organization": "Private or Reserved Network",
            },
            "geolocation": {
                "country_code": "ZZ",
                "country": "Private/Reserved",
                "region": "N/A",
                "city": "N/A",
                "lat": None,
                "lon": None,
                "confidence": "inferred-non-global",
            },
            "ip_traits": _traits(ip),
        }

    digest = hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()
    seed = int(digest[:8], 16)
    country_code, country = _COUNTRIES[seed % len(_COUNTRIES)]
    organization = _ORGS[seed % len(_ORGS)]
    asn_number = 1000 + (int(digest[8:12], 16) % 64511)
    lat = ((int(digest[12:16], 16) % 14000) / 100.0) - 70.0
    lon = ((int(digest[16:20], 16) % 34000) / 100.0) - 170.0
    city_suffix = digest[20:24].upper()
    return {
        "source_ip": raw,
        "asn": {
            "label": f"AS{asn_number}",
            "number": asn_number,
            "organization": organization,
        },
        "geolocation": {
            "country_code": country_code,
            "country": country,
            "region": "simulated-region",
            "city": f"node-{city_suffix}",
            "lat": round(lat, 3),
            "lon": round(lon, 3),
            "confidence": "simulated-deterministic",
        },
        "ip_traits": _traits(ip),
    }


def summarize_sources(source_contexts: list[dict[str, Any]]) -> dict[str, Any]:
    asn_counts: dict[str, dict[str, Any]] = {}
    country_counts: dict[str, dict[str, Any]] = {}
    private_sessions = 0
    global_sessions = 0

    for context in source_contexts:
        if not isinstance(context, dict):
            continue
        traits = context.get("ip_traits", {})
        if not isinstance(traits, dict):
            traits = {}
        if bool(traits.get("is_global")):
            global_sessions += 1
        else:
            private_sessions += 1

        asn = context.get("asn", {})
        if isinstance(asn, dict):
            label = str(asn.get("label", "")).strip()
            if label:
                entry = asn_counts.setdefault(
                    label,
                    {
                        "asn": label,
                        "organization": str(asn.get("organization", "")).strip(),
                        "sessions": 0,
                    },
                )
                entry["sessions"] = int(entry["sessions"]) + 1

        geo = context.get("geolocation", {})
        if isinstance(geo, dict):
            code = str(geo.get("country_code", "")).strip()
            country = str(geo.get("country", "")).strip()
            if code:
                entry = country_counts.setdefault(
                    code,
                    {
                        "country_code": code,
                        "country": country,
                        "sessions": 0,
                    },
                )
                entry["sessions"] = int(entry["sessions"]) + 1

    asns = sorted(asn_counts.values(), key=lambda item: (-int(item["sessions"]), str(item["asn"])))
    countries = sorted(country_counts.values(), key=lambda item: (-int(item["sessions"]), str(item["country_code"])))
    return {
        "asns": asns,
        "countries": countries,
        "unique_asns": len(asns),
        "unique_countries": len(countries),
        "global_sessions": global_sessions,
        "private_sessions": private_sessions,
    }


def _traits(ip: ipaddress._BaseAddress) -> dict[str, Any]:
    return {
        "ip_version": ip.version,
        "is_private": bool(ip.is_private),
        "is_loopback": bool(ip.is_loopback),
        "is_multicast": bool(ip.is_multicast),
        "is_reserved": bool(ip.is_reserved),
        "is_global": bool(ip.is_global),
    }


def _unknown_source() -> dict[str, Any]:
    return {
        "source_ip": "",
        "asn": {"label": "AS-UNKNOWN", "number": 0, "organization": "Unknown"},
        "geolocation": {
            "country_code": "ZZ",
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "lat": None,
            "lon": None,
            "confidence": "unknown",
        },
        "ip_traits": {
            "ip_version": 0,
            "is_private": False,
            "is_loopback": False,
            "is_multicast": False,
            "is_reserved": False,
            "is_global": False,
        },
    }
