# PROFILER v2.0

**Personal Intelligence Terminal** — A single-file Python 3 tool for profile management, OSINT auto-enrichment, and entity expansion. No external dependencies (stdlib only).

## Features

- **Profile Management** — Create, edit, search, link profiles with records, photos, locations, reminders
- **OSINT Auto-Enrichment** — From just a name, auto-gathers info from Wikipedia, Google News, social platform presence, DNS/RDAP, email/phone validation
- **Entity Expansion** — `profiler expand "CompanyName"` → identifies the entity and auto-creates profiles for its major people, subsidiaries, and related organizations, all linked
- **Relationships** — Link profiles, visualize the network graph
- **Encryption** — PBKDF2-HMAC-SHA256 + HMAC-CTR with authentication tag
- **Backup / Export / Import** — JSON, CSV, scheduled backups
- **Reports** — HTML dossier generation per profile
- **Case View** — Chronological timeline of all records + OSINT findings
- **Dedup / Merge** — Detect and merge duplicate profiles
- **Contact Scrape** — Extract phone/email/age/location from found profiles
- **Deep OSINT** — Integrates with sherlock, holehe, subfinder, phoneinfoga (if installed)
- **Reverse Image Search** — Bing-powered image search from the CLI
- **Phone Contacts Import** — Import from termux-contact-list (Android)
- **Recurring OSINT** — Schedule daily/weekly/monthly OSINT runs with change log
- **Network Scanning** — Profile websites (DNS, TLS, ports, subdomains, IP) and scan WiFi/Bluetooth networks
- **Custom Plugin System** — Add your own tools (command/URL/Python), usable by you AND the AI
- **Custom AI Provider** — Bring your own OpenAI-compatible API key (OpenAI, Groq, OpenRouter, DeepSeek, local, etc.)

## Quick Install

```bash
sh install.sh
# or manually:
cp profiler.py /usr/bin/profiler
chmod +x /usr/bin/profiler
```

## Quick Start

```bash
profiler                    # interactive menu
profiler add "Alice" --phone X --email Y
profiler list
profiler osint "Alice"      # auto OSINT enrichment
profiler expand "TechCorp"  # build entity network
profiler network "example.com"  # scan a website
profiler graph              # relationship graph
profiler case "Alice"       # chronological dossier
profiler report "Alice"     # HTML report
```

## OSINT Example

```
> profiler osint "Some Person"
  → Wikipedia: biography summary
  → Google News: live headlines
  → Web presence: related pages
  → All auto-appended to profile timeline
```

## Entity Expansion Example

```
> profiler expand "TechCorp"
  → Identified as: technology company
  → Created profiles: main company + key people + subsidiaries + related
  → All linked in the relationship graph
  → OSINT auto-enriched on each
```

## AI Provider (Optional)

Configure your own provider (API key not bundled):

```bash
profiler ai config
# → enter base URL, API key, model
profiler ai ask "research this person and add to their profile"
```

Works with any OpenAI-compatible API: OpenAI, Groq, OpenRouter, DeepSeek, Together, LM Studio, local servers, etc.

## Network Scanning

Profile a website or scan nearby networks:

```bash
profiler network "example.com"    # DNS, TLS cert, open ports, IP geolocation, subdomains
profiler network --wifi           # scan WiFi networks (Termux)
profiler network --bluetooth      # scan Bluetooth devices (Termux)
```

Website scans auto-save as a profile when you confirm. WiFi/Bluetooth scans
need the Termux API on Android; on PC/Linux use external tools.

## Custom Plugins (AI-usable)

Add your own tools — command-line tools, HTTP endpoints, or inline Python:

```bash
profiler plugin add       # interactive setup
profiler plugin list
profiler plugin run <name> <arg>
profiler plugin remove <name>
```

Plugins are exposed to the AI, which can call them automatically:

```
> profiler ai ask "use mytool on this input"
PLUGIN> mytool some input
AI> <result>
```

Plugin types:
- `command` — local CLI tool (e.g. `/path/tool --flag {arg}`)
- `url` — HTTP endpoint (GET/POST, custom headers/auth)
- `python` — inline `def run(arg) -> str` script



## Requirements

- Python 3.7+ (stdlib only — no pip packages needed)
- **Linux** ✅ Full support
- **macOS** ✅ Full support
- **Windows** ✅ Full support (optional: `pip install pyreadline3` for tab-completion)
- **Android (Termux)** ✅ Full support (extra features: GPS, camera, contacts import)

## Cross-Platform Notes

All core features work identically on every OS:
- Profile CRUD, records, links, graph, encryption, backup/export/import
- **OSINT auto-enrichment** (Wikipedia, Google News, social platforms, DNS/RDAP, email/phone validation)
- **Entity expansion** (`profiler expand "Company"`)
- **Custom AI provider** (any OpenAI-compatible API)
- **Reports, case view, dedup/merge, reverse image search, recurring OSINT**

Platform-specific features gracefully degrade:
- **GPS**: falls back to IP geolocation (works everywhere) → manual input
- **Camera**: not available on PC/macOS (file upload works)
- **Phone contacts import**: Android-only via Termux API
- **Tab-completion**: native on Linux/macOS, `pip install pyreadline3` on Windows

## Data Location

All data stored in `~/.profiler/` (profiles, photos, backups, reports, config).

## License

MIT