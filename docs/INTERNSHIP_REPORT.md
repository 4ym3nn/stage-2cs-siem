# Internship report outline

## 1. Context and objectives

Explain the SOC problem, why centralized telemetry matters, and the educational objectives of Stage 2CS SIEM.

## 2. Requirements

- Collect Linux, Windows, network IDS, syslog, and REST events.
- Normalize heterogeneous records.
- Detect and correlate suspicious activity.
- Support alert triage and investigations.
- Remain reproducible on one development machine.

## 3. Design

Use the diagrams in [ARCHITECTURE.md](ARCHITECTURE.md). Describe trust boundaries, the database model, API roles, and the reason for choosing FastAPI, SQLAlchemy, SQLite, and deterministic YAML-configured rules.

## 4. Implementation

Document the collectors, normalizers, event-time correlation, alert cooldowns, ATT&CK mapping, dashboard, cases, notes, audit trail, Docker packaging, and CI.

## 5. Validation

For each scenario in [DEMO.md](DEMO.md), record:

1. Input event or authorized lab action.
2. Relevant normalized fields.
3. Triggered rule and threshold.
4. Produced alert and ATT&CK mapping.
5. Analyst decision.
6. Automated test that prevents regression.

Include screenshots of the overview, one alert investigation, a case, API documentation, and the passing test suite.

## 6. Security and limitations

Discuss API-key handling, TLS termination, sensitive log storage, retention, false positives, SQLite concurrency, UDP syslog reliability, and the difference between an educational implementation and a production SIEM.

## 7. Results and future work

Report the number of sources, rules, automated tests, and demonstrated scenarios. Reasonable future work includes PostgreSQL, a background worker, Sigma conversion, threat-intelligence enrichment, and enterprise identity integration.

## 8. Conclusion

Summarize what was learned about telemetry pipelines, detection engineering, ATT&CK, SOC investigation, API security, testing, and deployment.
