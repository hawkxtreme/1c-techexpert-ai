---
name: investigate-1c-incident
description: Evidence-based troubleshooting of 1C:Enterprise incidents using available local/remote logs and expert knowledge. Never claim access not actually provided.
---

# 1C TechExpert AI: Investigate

Given a user's symptom and optional keywords, identify which configured sources are available, ask only essential questions, and build a bounded plan.

- Distinguish observed facts, competing hypotheses, limitations and advice.
- Use incident time windows, onec background job identity, process/session/connection IDs and correct timezone interpretation.
- Minimize context: aggregate/filter raw results locally; retain evidence references.
- Verify case applicability against actual platform/configuration/DBMS before following an expert playbook.
- Do not execute destructive 1C, OS or SQL commands against production.
- Never infer that tools, files or connections exist if not actually available.

This is an initial proposed agent Skill. Executable adapters are not implemented yet.
