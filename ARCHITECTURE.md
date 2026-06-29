# Project Aegis — Architecture Overview

## What Is Project Aegis
Project Aegis is a fully autonomous, self-improving AI security monitoring system
built in Python for Kali Linux. It detects attacks across three time horizons,
enriches findings with real-world threat intelligence, makes autonomous response
decisions via a large language model, and presents everything through a live
SOC-grade dashboard.

---

## Three-Layer Detection Architecture
┌─────────────────────────────────────────────────────────────────────┐

│                         PROJECT AEGIS                               │

│                                                                     │

│  /var/log/auth.log ──► Layer 1: Rule Engine                        │

│                         5+ fails in 120s → BRUTE_FORCE             │

│                                                                     │

│  psutil (CPU/RAM)  ──► Layer 2: LSTM Autoencoder                   │

│  + auth.log fails       Behavioral anomaly → ML_ANOMALY            │

│  + active users         Self-improving: retrains on clean data      │

│  + open ports                                                       │

│                                                                     │

│  auth.log (slow)   ──► Layer 3: Slow Attack Tracker                │

│                         3+ fails/1hr  → SLOW_PROBE                 │

│                         10+ fails/24hr → PERSISTENT_PROBE          │

│                         10+ IPs/10min → DISTRIBUTED_ATTACK         │

│                         New port open → NEW_PORT_DETECTED           │

│                                                                     │

│  Layer 4 (Passive) ──► Resilience                                  │

│                         UFW integrity check every 60s              │

│                         Log tamper detection every 30s             │

│                                                                     │

│  All layers feed the same pipeline:                                 │

│  forensics → AbuseIPDB → Groq LLM → severity escalation →         │

│  ufw block → tiered Discord alert → CSV/TXT report → dashboard     │

└─────────────────────────────────────────────────────────────────────┘

---

## Thread Architecture (6 threads, all daemon=True)

| Thread | Name | Tick | Role |
|---|---|---|---|
| 1 | Rule-Engine | 0.5s | Tails auth.log, Layer 1 brute force detection |
| 2 | Collector | 10s | Samples 6 system features, feeds ML + system_metrics.csv |
| 3 | ML-Inference | 10s | LSTM anomaly scoring, fires ML_ANOMALY pipeline |
| 4 | Trainer | 60min or 200 rows | Background retrainer, three-layer data guard |
| 5 | Port-Watcher | 60s | Diffs open ports against baseline, fires NEW_PORT_DETECTED |
| 6 | Resilience | 60s + 30s | UFW integrity check + log tamper detection |

---

## Intelligence Pipeline
Incident detected (any layer)

│

▼

gather_forensics()

whois lookup         (skipped for non-IP detections)
GeoIP lookup         (skipped for non-IP detections)
process snapshot
system telemetry
open ports / active users / running services

│

▼

threat_intel.lookup(ip)
AbuseIPDB API check  (cached 1hr, skipped for private IPs)
abuse_score injected into forensics

│

▼

llm_analyst.analyze_threat(forensics)
Enriched prompt: usernames, timing, AbuseIPDB, repeat offender,

detection label, threat labels, anomaly score
Groq API: openai/gpt-oss-120b
Returns: {severity, action, summary}
Fallback classifier if Groq is unreachable

│

▼

threat_intel.maybe_escalate(verdict, abuse_data)
abuse_score >= 80 → force CRITICAL
abuse_score >= 50 → force HIGH
abuse_score >= 20 → minimum MEDIUM

│

▼

mitigation.handle_verdict(ip, verdict, forensics)
Whitelist check (never block whitelisted IPs)
block_ip() with auto-expiry:

LOW=1hr, MEDIUM=6hr, HIGH/CRITICAL=permanent
Tiered Discord alert:

LOW=log only, MEDIUM=message, HIGH=@here, CRITICAL=@here+forensics
save_reports() → incidents.csv (15 cols) + incidents.txt


---

## ML Pipeline (Layer 2)
collector.py (every 10s)

Samples: cpu_percent, ram_percent, failed_logins,

active_users, open_ports, hour_of_day

→ appends to system_metrics.csv

→ calls ml_detector.add_sample()
ml_detector.py (every 10s)

Rolling window: 20 timesteps × 6 features

LSTM Autoencoder → reconstruction error (anomaly score)

score > threshold → ML_ANOMALY

Score logged to anomaly_scores.csv every inference

5-minute cooldown prevents repeat pipeline triggers
trainer.py (every 60min or 200 new rows)

Three-layer data guard:

Filter 1: exclude rows where score > threshold (anomalous)

Filter 2: exclude rows within ±5min of any incident (blackout)

Filter 3: abort if fewer than 100 clean rows survive

Atomic model save: aegis_model.tmp.keras → aegis_model.keras

Updates threshold to 95th percentile of clean data

Hot-reloads model in ml_detector without restarting daemon
ML Phases:

WARMING UP  → no model file, collecting data, rule engine defends

TRAINING    → first train running

DEFENDING   → model loaded, inference every 10s

RETRAINING  → background retrain, old model still live

---

## File Map

| File | Role |
|---|---|
| `daemon.py` | Main entrypoint, 6 threads, forensics pipeline, save_reports() |
| `log_parser.py` | Username extraction, timing analysis, threat labeling, unusual hour |
| `threat_tracker.py` | Layer 3 logic, repeat offender check, port baseline |
| `ml_detector.py` | LSTM inference, rolling window, score logging, hot-reload |
| `trainer.py` | Background retrainer, three-layer data guard |
| `collector.py` | 10s feature sampler, feeds ml_detector + system_metrics.csv |
| `llm_analyst.py` | Groq prompt builder, fallback classifier, abuse_score injection |
| `threat_intel.py` | AbuseIPDB lookup (cached), severity escalation, fallback classify |
| `mitigation.py` | block_ip(), unblock_ip(), tiered Discord, auto-expiry blocklist |
| `resilience.py` | UFW integrity check, log tamper detection |
| `system_checks.py` | open ports (ss), active users (who), running services (systemctl) |
| `dashboard.py` | 5-tab native PySide6 desktop SOC dashboard |
| `config.py` | All keys, thresholds, paths, whitelist, expiry map (gitignored) |
| `config.example.py` | Safe template for repo |

---

## Key Data Files

| File | Contents |
|---|---|
| `reports/incidents.csv` | 15-column incident log: timestamp, ip, fails, country, isp, org, severity, action, summary, detection_label, abuse_score, timing_pattern, usernames, repeat_offender, anomaly_score |
| `reports/incidents.txt` | Human-readable full incident reports |
| `reports/blocklist.txt` | Blocked IPs with severity, timestamp, expiry |
| `ml_data/system_metrics.csv` | Raw 6-feature telemetry samples (collector output) |
| `ml_data/anomaly_scores.csv` | Per-inference anomaly scores with timestamps |
| `ml_data/model/aegis_model.keras` | Trained LSTM Autoencoder |
| `ml_data/model/scaler.pkl` | MinMaxScaler for feature normalisation |
| `ml_data/model/metadata.json` | threshold, trained_at, sequence_length, features, epochs |

---

## Detection Labels

| Label | Layer | Trigger |
|---|---|---|
| BRUTE_FORCE | 1 | 5+ failed logins from same IP in 120s |
| ML_ANOMALY | 2 | LSTM reconstruction error > threshold |
| SLOW_PROBE | 3 | 3+ fails from same IP in 1 hour |
| PERSISTENT_PROBE | 3 | 10+ fails from same IP in 24 hours |
| DISTRIBUTED_ATTACK | 3 | 10+ different IPs each with 1-2 fails in 10 min |
| NEW_PORT_DETECTED | 3 | New open port vs baseline |
| PRIV_ESC_ATTEMPT | 1+parser | sudo failure in auth.log |
| BREACH_SUSPECTED | 1+parser | Successful login after failed attempts |
| UNUSUAL_HOUR | parser | Login outside configured active hours (07:00-22:00) |

---

## Security Considerations
- All API keys in config.py — gitignored, never committed
- DRY_RUN=True by default — no real blocks until explicitly enabled
- IP whitelist prevents accidental self-lockout
- Auto-expiry releases LOW/MEDIUM blocks after 1hr/6hr automatically
- Groq fallback classifier ensures verdicts even when API is unreachable
- Three-layer data guard prevents anomalous data from corrupting ML model
- Atomic model save prevents corrupt model state during retraining
- UFW integrity check re-adds missing rules if tampered with
- Log tamper detection alerts if auth.log is modified or rotated
