"""IP geolocation with MaxMind when a DB is present, otherwise a demo lookup.

Drop a GeoLite2-City.mmdb at backend/data/GeoLite2-City.mmdb (or set GEOIP_DB)
to switch from the demo table to MaxMind — same response shape either way.
"""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from pathlib import Path

DEMO_GEO: dict[str, dict] = {
    "8.8.8.8": {
        "country": "United States",
        "city": "Mountain View",
        "lat": 37.4056,
        "lon": -122.0775,
        "asn": "AS15169 Google LLC",
    },
    "1.1.1.1": {
        "country": "Australia",
        "city": "Sydney",
        "lat": -33.8688,
        "lon": 151.2093,
        "asn": "AS13335 Cloudflare",
    },
    "52.96.41.145": {
        "country": "United States",
        "city": "Washington",
        "lat": 38.9072,
        "lon": -77.0369,
        "asn": "AS8075 Microsoft",
    },
    "185.220.101.1": {
        "country": "Germany",
        "city": "Nuremberg",
        "lat": 49.4521,
        "lon": 11.0767,
        "asn": "AS60729 Tor exit (demo)",
    },
    "45.155.205.233": {
        "country": "Netherlands",
        "city": "Amsterdam",
        "lat": 52.3676,
        "lon": 4.9041,
        "asn": "AS174 Cogent (demo threat)",
    },
    "203.0.113.10": {
        "country": "Documentation",
        "city": "TEST-NET-3",
        "lat": 0.0,
        "lon": 0.0,
        "asn": "AS64496 Example",
    },
}

DEMO_TOR_EXITS = {"185.220.101.1", "185.220.102.8"}
DEMO_THREAT_IPS = {"45.155.205.233", "185.220.101.1"}


def _db_path() -> Path | None:
    raw = os.getenv("GEOIP_DB")
    if raw:
        path = Path(raw)
        return path if path.is_file() else None
    fallback = Path(__file__).resolve().parents[1] / "data" / "GeoLite2-City.mmdb"
    return fallback if fallback.is_file() else None


@lru_cache(maxsize=1)
def _maxmind_reader():
    path = _db_path()
    if path is None:
        return None
    try:
        import geoip2.database  # type: ignore
    except ImportError:
        return None
    return geoip2.database.Reader(str(path))


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and addr.is_global


def geolocate(ip: str) -> dict:
    base = {
        "ip": ip,
        "country": None,
        "city": None,
        "lat": None,
        "lon": None,
        "asn": None,
        "source": "none",
        "is_tor": ip in DEMO_TOR_EXITS,
        "is_threat": ip in DEMO_THREAT_IPS,
    }

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return base

    if not addr.is_global:
        base.update({"country": "Private/Internal", "source": "rfc1918"})
        return base

    reader = _maxmind_reader()
    if reader is not None:
        try:
            city = reader.city(ip)
            base.update(
                {
                    "country": city.country.name,
                    "city": city.city.name,
                    "lat": city.location.latitude,
                    "lon": city.location.longitude,
                    "source": "maxmind",
                }
            )
            return base
        except Exception:
            pass

    demo = DEMO_GEO.get(ip)
    if demo:
        base.update({**demo, "source": "demo-geoip"})
        return base

    base.update({"country": "Unknown", "source": "demo-geoip"})
    return base
