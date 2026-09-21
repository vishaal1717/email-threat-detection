from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Email Threat Detection API")

# Let a browser on any origin call this API during local development.
# (Browsers normally block cross-origin requests unless the server opts in.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRawRequest(BaseModel):
    headers: str
    body: str


def headers_to_dict(raw_headers: str) -> dict[str, str]:
    """Turn raw email header text into {name: value} pairs."""
    parsed: dict[str, str] = {}
    for line in raw_headers.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        parsed[name.strip()] = value.strip()
    return parsed


@app.get("/health")
def health() -> dict[str, str]:
    """Quick check that the server is up."""
    return {"status": "ok"}


@app.post("/api/analyze/raw")
def analyze_raw(payload: AnalyzeRawRequest) -> dict:
    """Accept raw email headers + body; for now only split headers into a dict."""
    return {"headers": headers_to_dict(payload.headers)}
