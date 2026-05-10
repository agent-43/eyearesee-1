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

## 🚀 Quick Start

To run the core client without installing dependencies or enabling AI (llm) detection:

python eyearesee.py --no-ai --no-install ( all llm features will be disabled and it will install no dependencies. )

## Explained 
eyearesee is a 7,710-line Python curses-based IRCv3 client with integrated AI detection. It connects to IRC (default irc.libera.chat:6697), supports SASL auth (PLAIN, SCRAM-SHA-256, EXTERNAL, ECDSA-NIST256P-CHALLENGE), full IRCv3 capabilities (message-tags, server-time, echo-message, batch, chathistory, multiline, read-marker, typing indicators, account-registration), CTCP, multi-server via /server, and has a tabbed TUI with userlist, channel history persistence, and CJK auto-translation.
Its distinguishing feature is an ensemble AI detector that scores every incoming message on a 0–100 AI-likelihood scale using: heuristic formality/pattern analysis, Binoculars cross-entropy ratio (GPT-2/distilGPT-2), RoBERTa classifiers (ChatGPT-focused + general), optional LLM-based classification (via Claude/OpenAI/Ollama/llama.cpp), and bot fingerprinting with n-gram similarity. A dashboard shows ranked suspects, per-user AI profiles with sparklines and session breakdowns, and channel activity stats. It also supports /askai and /summarize using any configured provider, a Python plugin system, and persistent JSONL audit logging.


Summary: eyearesee is an unusually ambitious single-file project: a polished, IRCv3-compliant terminal IRC client merged with a four-signal AI text detector and a multi-provider LLM chat interface, all in one script with minimal external dependencies.

## Dependencies Required 
(auto-installed if missing):
- windows-curses — curses for Windows (required on Windows)
- transformers — HuggingFace models (AI detection)
- torch — PyTorch (AI detection)
- anthropic — Claude API client (/askai, /summarize)
- openai — OpenAI/DeepSeek/Copilot API client
Optional:
- cryptography — only needed for SASL ECDSA-NIST256P-CHALLENGE

