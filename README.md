# RECONSTR

Timeline-driven attack reconstruction from Linux authentication logs.

Parses raw logs, detects attack patterns, correlates events into stages, and visualizes the full kill chain.

---

## Features

* Log parsing (`auth.log` format)
* Attack detection (brute force, valid account abuse, privilege escalation, persistence)
* Event correlation into attack stages
* MITRE ATT&CK mapping
* Interactive attack graph (HTML)
* JSON timeline export

---

## Setup

```bash
git clone https://github.com/4thul-505/reconstr.git
cd reconstr
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

```bash
python reconstr.py --log sample_logs/auth.log --output output/graph.html
```

Options:

```bash
--no-graph
--timeline output/timeline.json
```

---

## Output

* Interactive graph: `output/graph.html`
* Timeline data: `output/timeline.json`

---

## Detections

* Brute Force — T1110
* Valid Accounts — T1078
* Privilege Escalation (sudo) — T1548
* Persistence (user + cron) — T1136, T1053

---

## Project Structure

```
reconstr/
├── reconstr.py
├── modules/
├── sample_logs/
└── output/
```

---
