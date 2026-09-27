# Internship demonstration

This walkthrough is designed for a short, repeatable presentation. Run it only in the included lab or on systems you are authorized to monitor.

## Preparation

```bash
cp .env.example .env
docker compose up --build -d
python3 scripts/generate_demo.py
```

Open <http://127.0.0.1:8000> and <http://127.0.0.1:8000/docs>.

## Five-minute walkthrough

1. Show the overview and explain the event, alert, and case counters.
2. Open **Events** and compare Linux, Windows, Suricata, and generic records in one schema.
3. Open **Detection Rules** and show that thresholds, windows, cooldowns, severity, and ATT&CK metadata come from YAML.
4. Open the SSH brute-force alert. Point out the source IP, event-time evidence, first and last seen timestamps, and occurrence count.
5. Assign the alert to yourself, change it to `investigating`, and add a short note.
6. Create an investigation case from the alert.
7. Export the alert queue as CSV and show the action in `/api/audit` using the administrator key when configured.

## Evidence chain

| Safe simulation | Telemetry | Detection | Analyst result |
|---|---|---|---|
| Repeated failed SSH samples | Linux authentication | `LINUX-SSH-BRUTE` / T1110 | Aggregated brute-force alert |
| Sequential destination ports | Suricata flow | `NET-PORT-SCAN` / T1046 | Scan investigation |
| `sudo` log sample | Linux process/auth | `PRIV-SUDO-ROOT` / T1548.003 | Privileged-action review |
| Encoded shell indicator | Linux process | `PROC-REVERSE-SHELL` / T1059 | Critical alert |
| Event ID 4732 sample | Windows Security | `WIN-PRIV-GROUP` / T1098 | Persistence review |
| Severity 1 IDS sample | Suricata alert | `SURICATA-HIGH` | Network evidence |
| Enumeration user-agent | HTTP event | `WEB-ENUM` / T1595.002 | Reconnaissance alert |

## Discussion points

- Normalization lets one investigation search multiple telemetry formats.
- Event-time windows work for live events and chronological log replay.
- Cooldowns reduce alert fatigue while preserving the occurrence count.
- ATT&CK is context, not proof of compromise.
- Deterministic rules are explainable and testable, but require tuning to reduce false positives.
- SQLite is suitable for this lab; PostgreSQL and a worker queue are later scaling steps.

## Expected test result

```bash
pytest -q
```

All tests should pass before the presentation.
