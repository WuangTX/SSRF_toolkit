# 🏗️ Complete Callback Server Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   MICROSERVICE PENTEST TOOLKIT                          │
│                        Complete System Flow                             │
└─────────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│  PowerShell Script: run_with_ngrok_and_app.ps1                       │
│  ═══════════════════════════════════════════════════════════════      │
│                                                                       │
│  STEP 1: Start Callback Server 🚀                                    │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  tools/callback_server.py (Port 8888)                       │    │
│  │  ─────────────────────────────────────────────────────────  │    │
│  │  • Flask application with SQLite database                   │    │
│  │  • Routes: /, /api/callbacks, /health, /<path>             │    │
│  │  • Serves: templates/dashboard.html                         │    │
│  │  • Database: tools/callbacks.db                             │    │
│  │  • Auto-detects service from User-Agent                     │    │
│  └─────────────────────────────────────────────────────────────┘    │
│           │                                                           │
│           │ Health check: http://localhost:8888/health               │
│           ▼                                                           │
│  [✅ Callback server is healthy]                                      │
│                                                                       │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                       │
│  STEP 2: Start ngrok Tunnel 🌐                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  ngrok http 8888                                            │    │
│  │  ────────────────────────────────────────────────────────   │    │
│  │  • Creates public HTTPS tunnel                              │    │
│  │  • Exposes localhost:8888 to internet                       │    │
│  │  • API: http://127.0.0.1:4040/api/tunnels                   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│           │                                                           │
│           │ Poll ngrok API for public URL                            │
│           ▼                                                           │
│  [✅ ngrok public URL: https://abc123.ngrok.io]                       │
│                                                                       │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                       │
│  STEP 3: Start Web UI 🎨                                             │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  web_ui/app.py (Port 5000)                                  │    │
│  │  ────────────────────────────────────────────────────────   │    │
│  │  • Main toolkit interface                                   │    │
│  │  • Shows callback server status banner                      │    │
│  │  • Auto-detects callback URL every 10s                      │    │
│  │  • Link to callback dashboard                               │    │
│  └─────────────────────────────────────────────────────────────┘    │
│           │                                                           │
│           │ Starts in foreground (logs visible)                      │
│           ▼                                                           │
│  [🌐 Access: http://localhost:5000]                                   │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘


┌───────────────────────────────────────────────────────────────────────┐
│                      USER INTERACTION FLOW                            │
└───────────────────────────────────────────────────────────────────────┘

┌─────────────────────┐
│  User's Browser     │
│  localhost:5000     │
└─────────────────────┘
          │
          │ 1. Opens Web UI
          ▼
┌─────────────────────────────────────────────────────────┐
│  Web UI (index.html)                                    │
│  ───────────────────────────────────────────────────    │
│  ┌───────────────────────────────────────────────────┐ │
│  │ 🎯 Callback Server Status Banner                  │ │
│  │ ─────────────────────────────────────────────────  │ │
│  │ ✓ Callback Server: https://abc123.ngrok.io       │ │
│  │ 📊 Open Dashboard  [New Tab]                      │ │
│  └───────────────────────────────────────────────────┘ │
│                                                         │
│  JavaScript checks every 10s:                           │
│  1. Try ngrok API: http://127.0.0.1:4040/api/tunnels   │
│  2. Fallback: http://localhost:8888/health             │
│  3. Update status banner and link                       │
└─────────────────────────────────────────────────────────┘
          │
          │ 2. Click "Open Dashboard"
          ▼
┌─────────────────────────────────────────────────────────┐
│  Callback Dashboard (dashboard.html)                    │
│  Port 8888 or ngrok URL                                 │
│  ───────────────────────────────────────────────────    │
│                                                         │
│  ┌─────────────┐ ┌──────────────┐ ┌─────────────────┐ │
│  │📊 Total: 45 │ │⏰ Last: 2s ago│ │🏷️ Services: 5  │ │
│  └─────────────┘ └──────────────┘ └─────────────────┘ │
│                                                         │
│  Service Filters:                                       │
│  [All] [Python] [Java] [Node.js] [PHP] [Go] [curl]     │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │ ID │ Time │ Method │ Path │ IP │ Service │ Action │ │
│  ├────┼──────┼────────┼──────┼────┼─────────┼────────┤ │
│  │ 45 │ 2s   │ GET    │/test │... │ python  │ View   │ │
│  │ 44 │ 5s   │ POST   │/api  │... │ java    │ View   │ │
│  │ ... (pagination: 100 per page)                   │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
│  [⏮ Prev] Page 1 of 5 [⏭ Next]  [20|50|100|200]       │
│                                                         │
│  [💾 Export JSON] [🗑️ Clear All] [🔄 Auto-refresh: ✓]  │
└─────────────────────────────────────────────────────────┘
          │
          │ 3. JavaScript auto-refreshes every 2s
          ▼
┌─────────────────────────────────────────────────────────┐
│  API Calls to localhost:8888/api/callbacks             │
│  ───────────────────────────────────────────────────    │
│  • GET /api/callbacks?limit=100&offset=0               │
│  • GET /api/callbacks/:id (detail modal)               │
│  • DELETE /api/callbacks (clear all)                   │
└─────────────────────────────────────────────────────────┘
          │
          │ 4. Flask processes request
          ▼
┌─────────────────────────────────────────────────────────┐
│  SQLite Database: tools/callbacks.db                    │
│  ───────────────────────────────────────────────────    │
│  Table: callbacks                                       │
│  ┌─────────────────────────────────────────────────┐   │
│  │ id │ timestamp │ path │ method │ remote_addr   │   │
│  │ headers │ body │ body_length │ user_agent      │   │
│  │ service_detected │ created_at                   │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Indexes:                                               │
│  • idx_timestamp (DESC)                                 │
│  • idx_service                                          │
└─────────────────────────────────────────────────────────┘


┌───────────────────────────────────────────────────────────────────────┐
│                   CALLBACK RECEPTION FLOW                             │
└───────────────────────────────────────────────────────────────────────┘

┌─────────────────────┐
│  External Service   │
│  (Target SSRF)      │
└─────────────────────┘
          │
          │ HTTP request to payload URL
          ▼
┌─────────────────────────────────────────────────────────┐
│  ngrok: https://abc123.ngrok.io/callback-endpoint      │
│  ───────────────────────────────────────────────────    │
│  • Public HTTPS tunnel                                  │
│  • Forwards to localhost:8888                           │
└─────────────────────────────────────────────────────────┘
          │
          │ Tunnel to local machine
          ▼
┌─────────────────────────────────────────────────────────┐
│  callback_server.py: Catch-all route                    │
│  ───────────────────────────────────────────────────    │
│  @app.route('/<path:p>', methods=[ALL])                 │
│                                                         │
│  1. Extract request data:                               │
│     • Path, method, remote IP                           │
│     • Headers (User-Agent, etc.)                        │
│     • Body (POST data, JSON, etc.)                      │
│                                                         │
│  2. Detect service from User-Agent:                     │
│     • Python: requests, urllib, httpx                   │
│     • Java: apache-httpclient, okhttp                   │
│     • Node.js: axios, got                               │
│     • PHP: guzzle                                       │
│     • Go: go-http                                       │
│     • etc.                                              │
│                                                         │
│  3. Store in database:                                  │
│     • INSERT INTO callbacks (...)                       │
│     • Thread-safe with Lock                             │
│                                                         │
│  4. Return: 'OK', 200                                   │
└─────────────────────────────────────────────────────────┘
          │
          │ Database stored
          ▼
┌─────────────────────────────────────────────────────────┐
│  Dashboard auto-refresh (2s interval)                   │
│  ───────────────────────────────────────────────────    │
│  • Fetches /api/callbacks                               │
│  • Updates table with new callback                      │
│  • Shows: 🔴 NEW badge on recent callbacks              │
│  • User sees real-time callback appear                  │
└─────────────────────────────────────────────────────────┘


┌───────────────────────────────────────────────────────────────────────┐
│                        FILE DEPENDENCIES                              │
└───────────────────────────────────────────────────────────────────────┘

tools/callback_server.py
├── Imports:
│   ├── flask (Flask, request, jsonify, render_template)
│   ├── logging
│   ├── datetime
│   ├── threading (Lock)
│   ├── os
│   ├── json
│   ├── sqlite3
│   └── pathlib (Path)
│
├── Database:
│   └── tools/callbacks.db (auto-created)
│
└── Template:
    └── tools/templates/dashboard.html

tools/templates/dashboard.html
├── Standalone HTML (no dependencies)
├── Inline CSS (dark theme)
└── Vanilla JavaScript:
    ├── fetch API for AJAX calls
    ├── DOM manipulation
    ├── Event listeners
    └── setInterval for auto-refresh

web_ui/templates/index.html
├── Modified sections:
│   ├── Callback server status banner
│   └── JavaScript: updateCallbackServerInfo()
│
└── External dependencies:
    ├── ngrok API: http://127.0.0.1:4040/api/tunnels
    └── Callback health: http://localhost:8888/health

tools/run_with_ngrok_and_app.ps1
├── Parameters:
│   ├── NgrokPath (default: "ngrok")
│   ├── CallbackPort (default: 8888)
│   └── NgrokWaitSeconds (default: 10)
│
└── Launches:
    ├── tools/callback_server.py (python)
    ├── ngrok http 8888 (background)
    └── web_ui/app.py (foreground)


┌───────────────────────────────────────────────────────────────────────┐
│                          PORT MAPPING                                 │
└───────────────────────────────────────────────────────────────────────┘

Port 5000   → Web UI (main toolkit interface)
             • Scan configuration
             • Test runner
             • Callback server status banner
             • Link to callback dashboard

Port 8888   → Callback Server (dashboard + receiver)
             • Dashboard UI: /
             • API endpoints: /api/callbacks, /api/callbacks/:id
             • Health check: /health
             • Catch-all receiver: /<any-path>

Port 4040   → ngrok Admin UI
             • Web interface: http://127.0.0.1:4040
             • API: http://127.0.0.1:4040/api/tunnels
             • Inspect requests
             • Replay requests

Public URL  → ngrok Tunnel (HTTPS)
             • Example: https://abc123.ngrok.io
             • Forwards to localhost:8888
             • Accessible from internet
             • Changes on each ngrok restart


┌───────────────────────────────────────────────────────────────────────┐
│                    DATA FLOW: REQUEST TO DISPLAY                      │
└───────────────────────────────────────────────────────────────────────┘

1. External HTTP Request
   └─> https://abc123.ngrok.io/test-endpoint

2. ngrok Tunnel Forwards
   └─> http://localhost:8888/test-endpoint

3. Flask Catch-all Route
   └─> @app.route('/<path:p>')
       └─> Extract: path, method, IP, headers, body

4. Service Detection
   └─> User-Agent: "python-requests/2.28.1"
       └─> Detected: "python"

5. Database Insert
   └─> INSERT INTO callbacks (...)
       └─> Returns: callback_id=45

6. Dashboard Auto-refresh (every 2s)
   └─> fetch('/api/callbacks?limit=100&offset=0')

7. API Response
   └─> JSON: {total: 45, callbacks: [{id: 45, ...}, ...]}

8. JavaScript Renders Table
   └─> renderTable(callbacks)
       └─> Creates table rows with data

9. User Sees New Callback
   └─> Row appears in table with "View" button

10. User Clicks "View"
    └─> fetch('/api/callbacks/45')
        └─> Modal shows full details


┌───────────────────────────────────────────────────────────────────────┐
│                      CLEANUP ON EXIT (Ctrl+C)                         │
└───────────────────────────────────────────────────────────────────────┘

User presses Ctrl+C in terminal
│
└─> Web UI (python web_ui/app.py) exits
    │
    └─> PowerShell finally {} block executes
        │
        ├─> Kill ngrok process (pid)
        │   └─> ngrok stops → tunnel closes
        │
        └─> Kill callback server process (pid)
            └─> callback_server.py stops → port 8888 released
                │
                └─> SQLite database file persists
                    └─> Data preserved for next run


┌───────────────────────────────────────────────────────────────────────┐
│                       EXAMPLE USAGE SCENARIO                          │
└───────────────────────────────────────────────────────────────────────┘

Step 1: Pentester starts toolkit
  PS> .\tools\run_with_ngrok_and_app.ps1
  
  Output:
  ======================================================================
  🚀 STEP 1: Starting Callback Server
  ======================================================================
  Starting callback server on port 8888...
  ✅ Callback server is healthy: healthy
  
  ======================================================================
  🌐 STEP 2: Starting ngrok tunnel
  ======================================================================
  Starting ngrok: ngrok http 8888
  Waiting for ngrok to expose tunnels...
  ✅ ngrok public URL detected: https://def456.ngrok.io
  
  ======================================================================
  🎨 STEP 3: Starting Web UI (port 5000)
  ======================================================================
  🌐 Access web UI at: http://localhost:5000
  📊 Access callback dashboard at: https://def456.ngrok.io

Step 2: Pentester opens web UI
  Browser: http://localhost:5000
  
  Sees banner:
  ✓ Callback Server: https://def456.ngrok.io
  📊 Open Dashboard

Step 3: Pentester clicks "Open Dashboard"
  New tab opens: https://def456.ngrok.io
  
  Dashboard shows:
  - 0 Total Callbacks
  - Empty table
  - Ready to receive

Step 4: Pentester tests SSRF on target
  Target application: http://vulnerable-app.com
  
  SSRF payload: https://def456.ngrok.io/ssrf-test-001
  
  Submits form with payload

Step 5: Target makes request
  Target's backend executes:
  GET https://def456.ngrok.io/ssrf-test-001
  
  → ngrok forwards to callback server
  → callback_server.py receives and stores
  → Database: id=1, path=/ssrf-test-001, service=python

Step 6: Dashboard auto-refreshes
  After 2 seconds:
  - Table updates with new callback
  - Stats: "1 Total Callbacks"
  - Row shows: ID=1, Method=GET, Path=/ssrf-test-001

Step 7: Pentester views details
  Clicks "View" button
  
  Modal shows:
  - Full headers
  - Request body
  - Remote IP (target's server IP)
  - Detected service: Python
  - Timestamp

Step 8: Export evidence
  Clicks "Export JSON"
  
  Downloads: callbacks_export_2024-01-15_14-30-45.json
  
  Contains all callback data for report
