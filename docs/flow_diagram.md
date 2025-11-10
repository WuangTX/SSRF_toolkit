# Flow diagram — Microservice Pentest Toolkit

Below is a visual flow of the toolkit showing how inputs move through the system, which modules are involved, and how findings are confirmed and stored.

> Note: This file uses Mermaid. In VS Code you can use a Mermaid preview extension or view the file on GitHub/GitLab which render Mermaid diagrams. A simple ASCII fallback is included below the diagram.

## Mermaid flowchart

```mermaid
flowchart TD
  subgraph UI [Web UI]
    UI((Web UI / CLI))
  end

  subgraph Parsers [Input Parsers]
    Burp[Burp/HAR Parser\n(`utils/burp_parser.py`)]
    HAR[HAR Parser\n(`utils/har_parser.py`)]
  end

  subgraph Discovery [Discovery / Reconnaissance]
    EDV2[EndpointDiscoveryV2\n(`blackbox/reconnaissance/endpoint_discovery_v2.py`)]
    JS[JS Analyzer\n(`reconnaissance/js_analyzer.py`)]
    Wordlist[Wordlist -> `wordlists/common.txt`]
  end

  subgraph Fuzz [Fuzzing / Testing]
    ParamFuzzer[Parameter Fuzzer\n(`parameter_fuzzer.py`)]
    Payloads[SSRF Payloads\n(callbacks, metadata endpoints, gopher/file templates)]
  end

  subgraph Detection [Detection]
    Callback[External Callback Server\n(`blackbox/detection/external_callback.py`)]
    Content[Content-based Evidence Check\n(JSON/body keyword matching)]
  end

  subgraph Core [Core / Persistence]
    Config[`core/config.py`]
    DB[`core/database.py`]
    Logger[`core/logger.py`]
    Reports[Reports / UI results]
  end

  UI -->|Upload Burp/HAR| Burp
  UI -->|Upload Burp/HAR| HAR
  UI -->|No upload: start discovery| EDV2
  Burp -->|Parsed requests| UI

  %% Targeted flow when Burp/HAR present
  Burp -->|targeted mode| ParamFuzzer
  HAR -->|targeted mode| ParamFuzzer

  %% Discovery-driven flow when no file
  EDV2 -->|discovers endpoints| ParamFuzzer
  Wordlist --> EDV2
  JS --> EDV2

  %% Fuzzing -> send tests
  ParamFuzzer --> Payloads
  Payloads -->|send test requests (reuse headers/cookies)| DetectionNode[Send Test Requests]
  DetectionNode --> Callback
  DetectionNode --> Content

  %% Evidence paths
  Callback -->|callback received| DB
  Content -->|metadata keywords found| DB
  DB --> Reports
  DB --> UI

  %% Core integrations
  UI --> Config
  ParamFuzzer --> Logger
  DetectionNode --> Logger
  Callback --> Logger

  style UI fill:#f5faff,stroke:#2b6cb0
  style Parsers fill:#fff7ed,stroke:#c17f00
  style Discovery fill:#f0fff4,stroke:#15803d
  style Fuzz fill:#fff0f6,stroke:#be185d
  style Detection fill:#f0f9ff,stroke:#0369a1
  style Core fill:#f8fafc,stroke:#334155

  classDef important fill:#fff2cc,stroke:#b45309
  class DB important

``` 

---

## ASCII fallback (no Mermaid renderer)

Web UI (web_ui/app.py)
  ├─> Upload Burp/HAR -> Burp/HAR Parser (utils/burp_parser.py / utils/har_parser.py)
  │     └─> Parsed requests -> Focused SSRF testing
  └─> No upload -> EndpointDiscoveryV2 (wordlist, sitemap, JS) -> discovered endpoints

Focused SSRF testing / Discovery -> Parameter Fuzzer -> Payload templates
  └─> Send test requests (re-use recorded headers/cookies when possible)
        ├─> External Callback Server (outbound -> attacker-controlled) -> if callback received -> store finding
        └─> Direct Response -> Content-based evidence check (search for metadata keywords such as `ami-id`, `instance-id`, `local-ipv4`, `meta-data`) -> if match -> store finding

Findings stored in core/database.py -> surfaced to UI reports

## Key files & responsibilities

- `web_ui/app.py` — orchestrates scans, accepts uploads, toggles targeted mode when Burp/HAR present, starts background scan threads.
- `utils/burp_parser.py` — parse Burp Suite exports, decode base64 request blobs, return structured request objects with headers and post_data.
- `blackbox/reconnaissance/endpoint_discovery_v2.py` — discovery engine using `wordlists/common.txt`, sitemap, robots, JS analysis.
- `parameter_fuzzer.py` — mutate parameters and inject SSRF payloads.
- `blackbox/detection/external_callback.py` — callback server and callback queue for confirming outbound requests.
- `core/database.py` — persist findings and sessions.
- `core/config.py` — configuration (e.g., `wordlist_path`) and runtime options.

## How detection confirmation works (summary)

1. External callback detection: inject payloads that point to a callback listener (tool-run or hosted) and wait for the callback server to receive an inbound request — high-confidence confirmation if callback arrives.
2. Content-based detection: when a test request returns a direct response, parse the response body (JSON/plaintext) and match against metadata keywords (AMI/instance IDs, meta-data paths). Use this to confirm SSRF even when outbound callbacks are blocked.
3. Both methods are used together to reduce false negatives: first attempt callbacks; also always inspect direct responses for evidence.


## Next steps (suggested)
- Add a small `docs/ssrf_payloads.txt` with curated metadata-targeting payloads (e.g., `http://169.254.169.254/latest/meta-data/`, `http://[AWS-metadata]/...`, gopher templates where supported).
- Add a unit test that runs `run_focused_ssrf_testing` on the sample Burp export and asserts a confirmed finding when the response contains metadata keywords.


---

_File created: `docs/flow_diagram.md`_
