## 🚀 Quick Start

To run the core client without installing dependencies or enabling AI (LLM) detection:

python eyearesee.py --no-ai --no-install ( all llm features will be disabled and it will install no dependencies. also use --require-virtualenv for venv)

## What do you mean by AI?
~29% of the code (2,254 of 7,710 lines) is dedicated to AI/LLM functionality. Breakdown:
- 9.6% — AI Detection ensemble (heuristics, Binoculars, RoBERTa classifiers, LLM-based classification)
- 6.0% — AI Integration (/askai, /summarize, /model, /api, provider clients)
- 5.8% — AI slash commands & dashboard (suspects view, AI profiles, /topai, /bot, etc.)
- 4.4% — AI logging & history (JSONL audit trail, per-nick history loading)
- 2.2% — AI tell phrases / word lists (IRC_CASUAL_WORDS, AI_TELL_PHRASES, LLAMA_TELL_PHRASES, FORMAL_WORDS)
- 1.2% — Bot fingerprinting (BotFingerprint class)
- 1.0% — Ollama/llama.cpp HTTP clients
- 0.7% — AI config (model registry, API keys, thread pools)
- 0.5% — AI deps & startup (--no-ai, auto-install transformers/torch)
The remaining ~71% is the IRC protocol stack (full IRCv3), curses TUI, plugin system, CJK translation, and general infrastructure.

## Explained 
eyearesee.py (~9364 lines) is a full-featured curses-based IRC client with an integrated AI-generated-text detection system. It connects to IRC servers (Libera.Chat, OFTC, etc.), renders a split-pane TUI (chat + dashboard), and silently scores every incoming message for AI-likeness using a 7-signal ensemble. Single-file, zero-dependency IRC stack (no irclib).
Core IRC Features
- Multi-server support with SSL, SASL (PLAIN, SCRAM-SHA-256, EXTERNAL, ECDSA-NIST256P-CHALLENGE)
- IRCv3: labeled-response, message-tags (server-time, msgid), chathistory replay, multiline, monitor, WHOX, draft/react, draft/redact, draft/reply, draft/mention
- Full CTCP handling (VERSION, PING, TIME, CLIENTINFO, ACTION)
- TUI: curses-based split-pane with chat window, user list, input line, and scrollable *dashboard* pane for AI profiles and infoviz
- Persistence: chat logs, AI score log (JSONL), input history, config (JSON), autojoin channels
- Auto-translation (Google Translate API), link previews, online help, plugin system, aliases, vim-style /chain commands, /explain (AI analysis of a nick via Claude/GPT/Ollama)
AI Detection System (EnsembleAIDetector)
All 8 detection signals, computed per-message:
Signal	Method	What it detects
Binoculars	_binoculars_score()	Perplexity ratio between GPT-2 (performer) and observer model (distilgpt2 or modern configurable LLM)
Classifiers	_classifier_score()	Chatgpt-detector-roberta (cls1) + openai-detector (cls2), optionally LoRA-adapted
Heuristics	_heuristic_score()	Formality, capitalisation, punctuation, IRC slang absence, tell phrases
Llama patterns	llama_pattern_score()	Markdown structure, bot openers, colon-terminated intros, enumeration
Adversarial	_adversarial_score()	Low char-ngram entropy + spacing anomalies (evasion padding)
Embedding drift	_embedding_variance_score()	Cosine similarity of sentence-BERT embeddings against user's own recent history — tight clusters → bot
Watermark	watermark_score()	Duplicate-token spacing regularity, green-red list bias, sentence-length uniformity
Timing	timing_anomaly_score()	Log-normal model of inter-message gaps — low log-variance + small z-scores → automated
Ensemble weighting adapts to message length (<8 words: 75% heuristic, ≥30 words: 38% binoculars + 37% classifier). Additional boosts from fingerprint similarity (cross-nick style matching), rolling momentum, adversarial override, and collaborative blocklist.
Interactive Commands
Command	Function
/ai <nick>	Full AI profile with per-signal breakdown, session + all-time stats, verdict
/topai	Per-channel ranking by AI likelihood
/bot <nick>	Mark as confirmed bot — builds n-gram fingerprint + trains LoRA adapter
/unbot <nick>	Remove confirmed-bot status
/learn_tell <phrase>	Add n-grams to collaborative blocklist
/forget_tell <phrase>	Remove n-grams from blocklist
/scan_watermark [text]	Scan text or last 10 messages for watermark patterns
/aitoggle	Enable/disable AI scoring
/explain <nick>	LLM-based behavioural analysis of a user
/askai <question>	Query a configured LLM (Claude, GPT, Ollama, llama.cpp)
/model	List/select AI provider models
/fingerprint	Show confirmed-bot style fingerprints
/cluster	Cluster users by linguistic similarity

# Summary: 
eyearesee is an unusually ambitious single-file project: a polished, IRCv3-compliant terminal IRC client merged with a seven-signal AI text detector and a multi-provider LLM chat interface, all in one script with minimal external dependencies.

## Dependencies Required 
(auto-installed if missing):
- windows-curses — curses for Windows (required on Windows)
- transformers — HuggingFace models (AI detection)
- torch — PyTorch (AI detection)
- anthropic — Claude API client (/askai, /summarize)
- openai — OpenAI/DeepSeek/Copilot API client
Optional:
- cryptography — only needed for SASL ECDSA-NIST256P-CHALLENG

On startup, _ensure_deps() auto-installs missing packages via pip (skipped with --no-install). The script refuses to run if windows-curses is missing and installs it automatically.
