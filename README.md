# eyearesee: IRCv3 Client with AI Detection

eyearesee is a sophisticated, single-file terminal-based IRC client featuring an integrated seven-signal AI text detection ensemble. It combines a robust IRCv3-compliant stack with advanced linguistic analysis to identify automated messages in real-time.

## Table of Contents
- [Quick Start](#quick-start)
- [Architecture and AI Composition](#architecture-and-ai-composition)
- [Core IRC Features](#core-irc-features)
- [AI Detection System](#ai-detection-system)
- [Interactive Commands](#interactive-commands)
- [Dependencies](#dependencies)
- [Summary](#summary)

---

## Quick Start

To run the core client without installing dependencies or enabling AI detection:

```bash
python eyearesee.py --no-ai --no-install
```
*Note: All AI features will be disabled. Use `--require-virtualenv` if running within a virtual environment.*

---

## Architecture and AI Composition

Approximately 29% of the codebase (2,254 of 7,710 lines) is dedicated to AI and Large Language Model (LLM) functionality.

### Breakdown of AI Components:
- **9.6% AI Detection Ensemble:** Heuristics, Binoculars, RoBERTa classifiers, and LLM-based classification.
- **6.0% AI Integration:** Core logic for `/askai`, `/summarize`, `/model`, and `/api` provider clients.
- **5.8% AI Interface:** Slash commands and dashboard views (suspects view, AI profiles, `/topai`, `/bot`).
- **4.4% AI Logging & History:** JSONL audit trails and per-nick history management.
- **2.2% AI Linguistic Data:** Detection word lists including casual/formal words and common LLM phrases.
- **1.2% Bot Fingerprinting:** The `BotFingerprint` class for identifying recurring patterns.
- **1.0% HTTP Clients:** Support for Ollama and llama.cpp.
- **0.7% AI Configuration:** Model registry, API key management, and thread pools.
- **0.5% AI Initialization:** Dependency management and startup logic.

The remaining **71%** comprises the core IRC protocol stack (IRCv3), curses TUI, plugin system, CJK translation, and general infrastructure.

---

## Core IRC Features

- **Multi-Server Support:** SSL/TLS support and extensive SASL mechanisms (PLAIN, SCRAM-SHA-256, EXTERNAL, ECDSA-NIST256P-CHALLENGE).
- **IRCv3 Compliance:** Labeled-response, message-tags (server-time, msgid), chathistory replay, multiline, monitor, WHOX, and draft extensions (react, redact, reply, mention).
- **Protocol Handling:** Full CTCP support (VERSION, PING, TIME, CLIENTINFO, ACTION).
- **TUI Interface:** A curses-based split-pane layout featuring a main chat window, user list, input line, and a scrollable dashboard for AI profiles and information visualization.
- **Persistence:** Local logging of chat and AI scores (JSONL), input history, and JSON-based configuration with autojoin support.
- **Advanced Utilities:** Auto-translation via Google Translate, link previews, inline help, plugin system, vim-style command chaining (`/chain`), and behavioural analysis.

---

## AI Detection System (EnsembleAIDetector)

The detector computes eight distinct signals for every incoming message to determine the likelihood of AI generation.

| Signal | Method | Description |
| :--- | :--- | :--- |
| **Binoculars** | `_binoculars_score()` | Perplexity ratio between a performer model (GPT-2) and an observer model. |
| **Classifiers** | `_classifier_score()` | RoBERTa-based ChatGPT and OpenAI detectors, with optional LoRA adaptation. |
| **Heuristics** | `_heuristic_score()` | Analysis of formality, capitalization, punctuation, and IRC slang. |
| **Llama Patterns** | `llama_pattern_score()` | Detection of specific Markdown structures, bot openers, and enumeration styles. |
| **Adversarial** | `_adversarial_score()` | Detection of low char-ngram entropy and spacing anomalies used for evasion. |
| **Embedding Drift**| `_embedding_variance_score()` | Sentence-BERT embedding variance against a user's recent history. |
| **Watermark** | `watermark_score()` | Analysis of token spacing regularity and "green-red" list bias. |
| **Timing** | `timing_anomaly_score()` | Log-normal modeling of inter-message intervals to detect automation. |

*Ensemble weighting automatically adapts to message length (e.g., favoring heuristics for short messages and classifiers/binoculars for longer text).*

---

## Interactive Commands

| Command | Function |
| :--- | :--- |
| `/ai <nick>` | Displays a full AI profile with per-signal breakdown and verdict. |
| `/topai` | Ranks users in the current channel by AI likelihood. |
| `/bot <nick>` | Marks a user as a confirmed bot and trains a fingerprint. |
| `/unbot <nick>` | Removes the confirmed-bot status from a user. |
| `/learn_tell <phrase>` | Adds n-grams to the collaborative blocklist. |
| `/forget_tell <phrase>` | Removes n-grams from the blocklist. |
| `/scan_watermark` | Scans text or recent messages for watermark patterns. |
| `/aitoggle` | Enables or disables real-time AI scoring. |
| `/explain <nick>` | Performs an LLM-based behavioural analysis of a specific user. |
| `/askai <question>` | Queries a configured LLM (Claude, GPT, Ollama, llama.cpp). |
| `/model` | Lists or selects the active AI provider and model. |
| `/fingerprint` | Displays fingerprints of confirmed bots. |
| `/cluster` | Clusters users based on linguistic similarity. |

---

## Dependencies

Required dependencies are automatically installed via pip on startup unless `--no-install` is specified.

- **windows-curses:** Required for the terminal interface on Windows.
- **transformers / torch:** Powers the AI detection ensemble.
- **anthropic / openai:** Required for LLM-based features like `/askai` and `/summarize`.
- **cryptography:** (Optional) Required for SASL ECDSA-NIST256P-CHALLENGE support.

---

## Summary

eyearesee is an ambitious single-file project that bridges the gap between traditional IRC communication and modern AI analysis. It provides a polished, feature-rich IRCv3 experience alongside powerful tools for auditing and interacting with AI-generated content in real-time.
