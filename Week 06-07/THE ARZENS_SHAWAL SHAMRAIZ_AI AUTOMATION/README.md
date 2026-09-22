# THE ARZENS — Week 06-07 Combined Assignment Submission

**Track:** AI, Automation & Security Engineering (Beginner Track)
**Deadline:** Thursday, 12 September 2026, 11:59 PM

## Contents

| Folder | Task | Deliverables |
|---|---|---|
| `task1_ai_ml_concept_analysis/` | Task 1 — AI/ML Concept Analysis | `Task1_AI_ML_Concept_Analysis.pdf` (+ source `content.py`, `build_pdf.py`) |
| `task2_openai_analyzer/` | Task 2 — OpenAI Security Log Analyzer | `openai_analyzer.py`, `.env.example`, `sample_logs.txt`, `cost_tracker.csv`, sample outputs |
| `task3_hf_classifier/` | Task 3 — Hugging Face Text Classifier | `hf_classifier.py`, `requirements.txt`, `sample_alerts.csv`, `classified_output.csv` |
| `task4_soar_architecture/` | Task 4 — SOAR Architecture Design | `Task4_SOAR_Architecture_Design.pdf` (+ source `content.py`, `build_pdf.py`, `build_diagram.py`, `workflow_diagram.png`) |
| `task5_phishing_playbook/` | Task 5 — Phishing Response Playbook | `phishing_playbook.py`, `config.yaml`, `blacklist_domains.txt`, `sample_email.json`, `playbook.log` |
| `task6_playbook_manager/` | Task 6 — Playbook Manager & Scheduler | `playbook_manager.py`, `playbook_registry.json`, `schedule_config.yaml`, `execution_history.json`, `MANAGER_README.md` |

## How the pieces fit together

- **Tasks 1-3** (Week 06) build the AI-assisted analysis layer: an essay
  comparing AI use cases in security operations, a GPT-4-based log analyzer,
  and a local Hugging Face-based alert classifier.
- **Tasks 4-6** (Week 07) build the automation/orchestration layer: a SOAR
  architecture design (Phishing Response), a working phishing-response
  playbook implementing that design, and a manager that registers, runs,
  schedules, and health-checks all three executable tools (Tasks 2, 3, and 5)
  from one place.

## Running things yourself

Each task folder is self-contained and runnable on its own (see the comment
header at the top of each `.py` file for exact usage). The fastest way to
see everything work end-to-end without any API keys is:

```bash
cd task6_playbook_manager
python3 playbook_manager.py --health-check
python3 playbook_manager.py --list
python3 playbook_manager.py --run phishing_response
python3 playbook_manager.py --run hf_alert_classifier
python3 playbook_manager.py --run openai_log_analyzer
python3 playbook_manager.py --daily-summary
```

All three underlying playbooks default to a safe mode (`--dry-run` /
`--mock`) that requires no API keys, no internet access, and performs no
real containment actions — matching the "safe AI principles" (human
oversight, validation, cost awareness) discussed in Task 1.

### AI Assistance Note

Portions of this submission (code scaffolding, documentation, and the
Task 1/4 written analyses) were drafted with AI assistance (Claude) as part
of THE ARZENS' AI, Automation & Security Engineering curriculum, then
reviewed, tested, and adjusted. All code was executed and its output
verified as part of preparing this submission.
