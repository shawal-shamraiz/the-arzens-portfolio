# -*- coding: utf-8 -*-
"""
Content definitions for Task 1: AI/ML for Security Analysts.
Kept separate from the PDF-rendering script so the text is easy to review/edit.
"""

TITLE = "AI/ML for Security Analysts: Log Analysis, Threat Intel, and Alert Triage"
SUBTITLE = "Task 1 — AI/ML Concept Analysis | THE ARZENS Internship, AI, Automation & Security Engineering Track"

INTRO = """Security operations centers (SOCs) are drowning in data. A mid-sized organization
can generate tens of thousands of alerts a day, far more than any human team can review, and a
single investigation can take a trained analyst twenty to forty minutes when done manually.
Pre-trained AI models — large language models (LLMs) such as GPT-4 and open-source classifiers
hosted on platforms like Hugging Face — are increasingly used to close this gap. Rather than
replacing analysts, these models are best understood as force multipliers: they read, summarize,
and pre-score large volumes of text and telemetry so a human can apply judgment where it matters
most. This analysis compares three common AI use cases in security operations — log analysis,
threat intelligence summarization, and alert triage — and outlines the safety principles that
should govern how a junior analyst or engineer deploys them."""

USE_CASE_LOG_ANALYSIS = """Log analysis is the most mature use case. Raw logs (firewall, EDR,
authentication, DNS) are verbose, inconsistently formatted, and require domain knowledge to
interpret. An LLM can be given a chunk of raw log lines and asked to summarize what happened,
flag anomalies, and suggest a severity rating and next action, acting as a first-pass reader.
Open-source classifiers complement this with narrow, repeatable scoring — e.g. labeling an event
"threat" or "non-threat" with a confidence score — which is cheaper than an LLM call for
high-volume, low-complexity work. The value is speed and consistency: models apply the same
scrutiny to log line 10,000 as to log line 1. The risk is that unfamiliar log formats,
adversarial log injection, or unusual encodings can produce misleading summaries that look
confident even when wrong."""

USE_CASE_THREAT_INTEL = """Threat intelligence summarization asks a model to digest long-form
material — vendor advisories, CVE write-ups, translated chatter, incident reports — into a short
brief an analyst can act on. This suits LLMs because summarization draws on general language
ability rather than deep, current security knowledge, and the source is usually already vetted
before it reaches the model. The benefit is time saved: a ten-page advisory becomes a five-bullet
summary in seconds. The risk is compounding error — if the model misreads a detail (e.g. which
CVE affects which product version) and the summary is used without checking the source, that
error can propagate into containment decisions. Summaries should therefore always retain a link
back to the source and should not be trusted for anything with legal, regulatory, or attribution
consequences without a human re-reading the original."""

USE_CASE_ALERT_TRIAGE = """Alert triage is the highest-stakes of the three use cases because it
sits closest to automated action. An AI model — often a classifier or an agentic LLM pipeline —
ingests an alert, correlates it with other signals, and recommends (or in mature deployments,
executes) a disposition: auto-close, escalate to analyst, or immediate response. Industry
guidance increasingly favors a three-tier model — auto-close, analyst review, immediate
escalation — with auto-close reserved for patterns with a documented benign explanation and a
recent validation history. The benefit is enormous: automated triage can cut manual investigation
effort dramatically and shrink the time between detection and response. The risk is equally
large: a false "auto-close" on a genuine intrusion can leave an organization blind, and models
trained on historical patterns perform poorly against genuinely novel techniques, where
low-confidence outputs should route to a human rather than close automatically."""

SAFE_AI_HEADER = "Safe AI Principles"
SAFE_AI_INTRO = """Regardless of use case, three principles should govern any AI-assisted
security tool built during this internship, and are reflected directly in the tools submitted
alongside this analysis (openai_analyzer.py and hf_classifier.py):"""

SAFE_AI_BULLETS = [
    ("Human oversight", "AI output is a recommendation, not a verdict. Every tool here produces "
     "a suggested severity or classification and leaves the final decision — and any high-impact "
     "action such as blocking — to a human reviewer, matching the human-in-the-loop pattern "
     "current incident-response guidance (including NIST) treats as a requirement."),
    ("Validation", "Model outputs are checked before being trusted. Confidence thresholds route "
     "low-confidence classifications to a human instead of silently auto-accepting them, and "
     "every classification is logged with its confidence score for later audit."),
    ("Cost awareness", "API models like GPT-4 cost money per call and can run away if uncontrolled. "
     "The OpenAI-based tool includes a --dry-run mode, running cost tracking written to "
     "cost_tracker.csv, and basic rate limiting, so a bug or bulk log file cannot cause a "
     "surprise bill."),
]

COMPARISON_TABLE_HEADER = ["Use Case", "Benefit", "Risk", "Required Oversight"]
COMPARISON_TABLE_ROWS = [
    [
        "Log Analysis",
        "Fast, consistent first-pass reading of high-volume, inconsistently formatted "
        "log data; frees analysts from manual line-by-line review.",
        "Misleading summaries on unfamiliar log formats or adversarial/injected log "
        "content; false confidence in wrong summaries.",
        "Spot-check a sample of AI summaries against raw logs; never feed AI severity "
        "scores directly into automated blocking actions.",
    ],
    [
        "Threat Intel\nSummarization",
        "Condenses long advisories/reports into actionable briefs in seconds instead "
        "of the many minutes a full read would take.",
        "Misread technical details (e.g. affected versions) can propagate into "
        "containment decisions if the source isn't re-checked.",
        "Keep a visible link to the source document; require human re-read before any "
        "action with legal, regulatory, or attribution impact.",
    ],
    [
        "Alert Triage",
        "Can process alert volumes far beyond human capacity and cut manual "
        "investigation time significantly, reducing analyst fatigue.",
        "False auto-close on a real intrusion leaves the org blind; poor performance "
        "on genuinely novel, unseen attack techniques.",
        "Three-tier disposition (auto-close / analyst review / escalate); auto-close "
        "restricted to well-documented, low-risk patterns only.",
    ],
]

CONCLUSION = """Taken together, these three use cases show a consistent pattern: AI models are
strongest at compressing volume and surfacing candidates for review, and weakest at making final,
consequential decisions with no human in the loop. The tools built for Task 2 and Task 3 of this
assignment, and the SOAR playbooks built for Tasks 4-6, are designed around that boundary —
using AI and automation to do the reading and scoring, while keeping a human, a dry-run mode, or
a confidence threshold between the model's output and any action that cannot easily be undone."""

REFERENCES_HEADER = "References"
REFERENCES = [
    "Dropzone AI. \"AI SOC Analyst Guide 2026: From Alert Triage to Verdict.\" "
    "dropzone.ai/resource-guide/ai-soc-analysts-the-complete-guide-to-alert-management",
    "NHI Management Group. \"Alert triage automation exposes the governance gap in AI SOC "
    "workflows.\" nhimg.org/articles/alert-triage-automation-exposes-the-governance-gap-in-ai-soc-workflows",
    "National Institute of Standards and Technology. NIST Special Publication 800-61 Revision "
    "3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management. "
    "csrc.nist.gov",
]
