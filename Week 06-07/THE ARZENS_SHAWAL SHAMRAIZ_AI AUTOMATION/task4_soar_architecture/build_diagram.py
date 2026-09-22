# -*- coding: utf-8 -*-
"""Builds workflow_diagram.png depicting the Phishing Response SOAR playbook flow."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

fig, ax = plt.subplots(figsize=(11, 7.5))
ax.set_xlim(0, 11)
ax.set_ylim(0, 15)
ax.axis("off")

COLOR_TRIGGER = "#2c3e6b"
COLOR_PROCESS = "#3f6bb5"
COLOR_DECISION = "#c07a1e"
COLOR_ACTION_HIGH = "#a13333"
COLOR_ACTION_MED = "#c07a1e"
COLOR_ACTION_LOW = "#3f7d3f"
COLOR_HUMAN = "#6a3fa0"
COLOR_AUDIT = "#555555"
TEXT_WHITE = "white"


def box(x, y, w, h, text, color, fontsize=9.2, text_color=TEXT_WHITE):
    b = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08,rounding_size=0.12",
                        linewidth=0, facecolor=color)
    ax.add_patch(b)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
             fontsize=fontsize, color=text_color, wrap=True, fontweight="bold")
    return (x + w / 2, y, x + w / 2, y + h)  # bottom-center, top-center helpers


def arrow(x1, y1, x2, y2, color="#333333", style="-|>"):
    a = FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=14,
                         color=color, linewidth=1.4, shrinkA=2, shrinkB=2)
    ax.add_patch(a)


# --- Trigger ---
box(3.5, 13.7, 4, 0.9, "TRIGGER\nSuspicious email reported\n(user report / mail-gateway alert)", COLOR_TRIGGER)
arrow(5.5, 13.7, 5.5, 13.15)

# --- Extraction ---
box(3.0, 12.25, 5, 0.9, "INDICATOR EXTRACTION\nSender, domain, URLs, attachment hash", COLOR_PROCESS)
arrow(5.5, 12.25, 5.5, 11.7)

# --- Reputation check ---
box(3.0, 10.8, 5, 0.9, "REPUTATION CHECK\nLocal blacklist  +  VirusTotal API\n(--dry-run safe by default)", COLOR_PROCESS)
arrow(5.5, 10.8, 5.5, 10.25)

# --- Risk scoring ---
box(3.0, 9.35, 5, 0.9, "RISK SCORING\nWeighted 0-100 score from indicators", COLOR_PROCESS)
arrow(5.5, 9.35, 5.5, 8.8)

# --- Decision diamond (approximate with box) ---
box(2.7, 7.75, 5.6, 1.0, "DECISION GATE\nScore thresholds -> disposition", COLOR_DECISION)

# three branches
arrow(3.3, 7.75, 1.6, 6.9)
arrow(5.5, 7.75, 5.5, 6.9)
arrow(7.7, 7.75, 9.3, 6.9)

box(0.3, 6.0, 3.0, 0.9, "HIGH (>=70)\nAuto-block domain/hash\n+ quarantine email", COLOR_ACTION_HIGH)
box(4.0, 6.0, 3.0, 0.9, "MEDIUM (30-69)\nQueue for analyst review\n(no auto action)", COLOR_ACTION_MED)
box(7.7, 6.0, 3.0, 0.9, "LOW (<30)\nLog only, no action", COLOR_ACTION_LOW)

# HIGH -> human confirmation (rollback safety)
arrow(1.8, 6.0, 1.8, 5.1)
box(0.3, 4.2, 3.0, 0.9, "HUMAN-IN-THE-LOOP\nAnalyst can --rollback\nauto-block within window", COLOR_HUMAN)

# MEDIUM -> analyst queue
arrow(5.5, 6.0, 5.5, 5.1)
box(4.0, 4.2, 3.0, 0.9, "ANALYST REVIEW QUEUE\nManual disposition required", COLOR_HUMAN)

# converge to notification + audit
arrow(1.8, 4.2, 4.5, 3.2)
arrow(5.5, 4.2, 5.5, 3.2)
arrow(9.2, 6.0, 6.8, 3.2)

box(3.3, 2.3, 4.5, 0.9, "NOTIFICATION\nEmail report to security team", COLOR_PROCESS)
arrow(5.55, 2.3, 5.55, 1.75)

box(2.7, 0.85, 5.6, 0.9, "AUDIT LOG\nFull chain of custody -> playbook.log\n(input, decision, action, actor, timestamp)", COLOR_AUDIT)

ax.text(5.5, 14.85, "Phishing Response Playbook — Workflow", ha="center", fontsize=15,
        fontweight="bold", color="#1a2b4c")

legend_patches = [
    mpatches.Patch(color=COLOR_TRIGGER, label="Trigger"),
    mpatches.Patch(color=COLOR_PROCESS, label="Automated processing"),
    mpatches.Patch(color=COLOR_DECISION, label="Decision gate"),
    mpatches.Patch(color=COLOR_ACTION_HIGH, label="High-risk action"),
    mpatches.Patch(color=COLOR_HUMAN, label="Human-in-the-loop"),
    mpatches.Patch(color=COLOR_AUDIT, label="Audit / logging"),
]
ax.legend(handles=legend_patches, loc="upper left", bbox_to_anchor=(-0.02, 1.0),
          fontsize=7.5, frameon=False)

plt.tight_layout()
plt.savefig("workflow_diagram.png", dpi=200, bbox_inches="tight")
print("Diagram saved.")
