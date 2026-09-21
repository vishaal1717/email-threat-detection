# Email Threat Detection — backend demo

FastAPI service for the Outlook add-on / SIH investigator flow: parse a raw message, map **hops + GeoIP**, **MITRE ATT&CK**, and **IOCs**, then store the result in SQLite (open `backend/data/intel.db` in DBeaver).

We use **FastAPI only** (not Flask + FastAPI). Same job, one framework, automatic `/docs`.

## Run

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

- Health: `GET http://127.0.0.1:8000/health`
- Swagger: http://127.0.0.1:8000/docs
- Sample: `curl -s -X POST http://127.0.0.1:8000/api/analyze/raw -H 'Content-Type: application/json' --data @samples/phishing.json`

## Endpoints

| Method | Path | Why |
| --- | --- | --- |
| GET | `/health` | Liveness |
| POST | `/api/analyze/raw` | `{ "headers", "body" }` → hops, MITRE, IOCs, risk; saved to SQLite |
| GET | `/api/analyses` | Recent cases |
| GET | `/api/analyses/{id}` | One case (map + ATT&CK + IOCs) |
| GET | `/api/analyses/{id}/iocs.csv` | IOC export for responders |

## Stack vs SIH poster

| Poster | This demo |
| --- | --- |
| Python | Python 3 |
| Flask + FastAPI | FastAPI |
| MaxMind GeoIP | MaxMind if `backend/data/GeoLite2-City.mmdb` (or `GEOIP_DB`) exists, else a demo GeoIP table |
| DBeaver | SQLite file DBeaver can open |
| BGP/ASN, Tor, threat intel | Demo ASN + Tor/threat IP lists (swap for real feeds later) |
| React / Tailwind | Next: Outlook add-in + dashboard consume this API |

## Outlook later

The add-in only needs to POST the current item’s headers and body to `/api/analyze/raw` and render `risk`, `hops`, `mitre`, and `iocs`.
