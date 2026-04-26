( Note: python eyearesee.py --no-ai --no-install will run without installing dependencies or using offline AI )
( For further usage help type: /commands )

( Thank you Amigojapan for feature list suggestions! Check his page out! https://github.com/amigojapan )

eyearesee — A Terminal IRC Client with AI Detection
eyearesee.py is a single-file, ~5,720-line Python 3 IRC (Internet Relay Chat) client that runs in the terminal as a curses-based TUI. The name is a phonetic spelling of "I-R-C." Beyond being a fully featured IRC client, it has an unusual headline feature: it scores every message it sees with an ensemble of AI/LLM-detection models, flagging users whose chat looks machine-generated.
What it is, at a glance

Type: Asynchronous (asyncio) terminal IRC client with a curses-based text UI
Default target: irc.libera.chat:6697 over SSL, channel ##anime
Platforms: Linux, macOS, and Windows (auto-installs windows-curses on Windows if missing)
Auto-bootstrap: On first run it pip-installs missing optional dependencies (anthropic, openai, transformers, torch) and restarts itself
Storage: All data files (chat logs, AI scores log, input history) live next to the script so it works even when launched from a read-only working directory

Architecture
The code is organized into ten classes plus a large block of module-level utilities:

IRCClient — the network layer: SSL socket, IRCv3 capability negotiation (including SASL PLAIN auth, server-time, multi-prefix, away-notify, etc.), reconnection with backoff, send-rate limiting, full IRC command/numeric handling
TUI — the curses interface: tab bar of windows, scrollable chat pane, user list panel, input line with readline-style key bindings
ChatWindow / UserState / ServerContext — per-window and per-user state tracking, including rolling AI-score history per nick
EnsembleAIDetector — the LLM detection engine (see below)
BotFingerprint / ScoringEngine — confirmed-bot fingerprinting using vocabulary, bigrams, and trigrams to catch users writing like a known bot
PluginAPI / PluginManager — a hot-reloadable Python plugin system

IRC client features
It implements a near-complete IRC feature set: messaging (/msg, /query, /notice, /me), channel ops (/join, /part, /topic, /kick, /invite, /names), operator commands (/op, /voice, /ban, etc.), services (/ns for NickServ, /cs for ChanServ, /ctcp), user info (/whois, /whowas, /who, /away//back, /ignore), and connection management (/server for parallel connections to multiple networks, /reconnect).
Notable refinements:

IRCv3 message-tag parsing so server-time-tagged messages aren't dropped
Five built-in color themes (Classic, Hacker, Ocean, Sunset, Neon) selectable with /theme
Wide-character (CJK) handling so Japanese/Chinese/Korean text aligns correctly in fixed-width terminal columns
Auto-translation toggle for CJK messages
Persistent input history (up to 500 lines) across sessions
Per-window persistent chat logs that reload on startup
Inline IRC formatting (bold, italic, underline, color codes) with a parse cache for performance
URL detection in messages

The AI-detection system
This is the distinguishing feature. Every incoming PRIVMSG is run through EnsembleAIDetector, which combines four signals:

Heuristic score — pattern matching against curated phrase sets:

AI_TELL_PHRASES: generic LLM tells like "it's worth noting," "delve into," "tapestry," "as an AI language model," sycophantic openers, em-dashes, etc.
LLAMA_TELL_PHRASES: open-source-LLM-specific patterns ("Sure, here's...", "Let me break this down...", etc.)
Plus formality, contraction usage, capitalization, presence of casual IRC tokens (lol, lmao, brb...)


Llama pattern score — structural detection of markdown lists, numbered enumerations, colon-introduced lists, abnormally long messages, and templated multi-sentence structure inside what should be casual chat
Binoculars score — the Hans et al. (2024) cross-entropy ratio method using two GPT-2-family models (an "observer" and a "performer"); a low ratio means both models find the text fluent, indicating likely AI generation
Classifier score — averaged probability from two HuggingFace transformer classifiers: Hello-SimpleAI/chatgpt-detector-roberta (strong on GPT/Claude output) and openai-community/roberta-base-openai-detector (generalizes to Llama/Mistral)

These are blended into a 0-100 ensemble score with an override that boosts scores for high-confidence Llama structural patterns even when the ML signals are uncertain. Models can be disabled entirely with --no-ai.
Each user gets a rolling AI-score average over their last 200 messages. Users above a threshold (default 70) are flagged "suspect" and highlighted. Detection commands include /ai <nick> (full profile with sparkline and verdict), /topai (channel ranking), /bot <nick> (mark as confirmed AI and build a vocabulary/n-gram fingerprint), and /unbot.
Every detection is logged as a JSONL record to ai_scores.log with the full sub-signal breakdown, session ID, monotone sequence number (so missing entries are detectable), and the message itself. This persistent log is loaded at startup to seed per-nick history across sessions.
LLM integration (you can talk to AI in IRC)
The same client can also send messages to LLMs via /askai and /summarize. It supports four backends through a unified model registry:

Anthropic Claude (cloud): opus, sonnet, haiku — though the model IDs hardcoded in the file (claude-opus-4-6, claude-sonnet-4-6, claude-haiku-4-5-20251001) reference Claude 4.6-family models
OpenAI (cloud): gpt-4o, gpt-4-turbo, gpt-3.5-turbo
Ollama (local): gemma3:4b, llama3.2 — for offline use
llama.cpp (local): via OpenAI-compatible server at port 8033

API keys are read from environment variables (ANTHROPIC_API_KEY, OPENAI_API_KEY, OLLAMA_URL, LLAMACPP_URL) or set at runtime with /api. The default model is qwen3 running on local llama.cpp.
Other notable bits

Plugin system: /loadplugin <path> loads any Python file with a setup(api) function and lets it register custom slash commands; supports hot-reload
Multi-server support: /server opens additional parallel connections, each with its own window stack
Defensive coding: the file is full of comments explaining edge cases (Windows console encoding, directory-traversal hardening on log filenames, broken-pipe handling, race conditions in LRU caches, IRCv3 tag escape sequences)
Performance work: O(1) frozenset lookups for IRC numerics, LRU caches for prediction results and formatting parses, chunked reverse-reading of log files instead of loading them whole

In short
It's an unusually ambitious single-file project: a polished, IRCv3-compliant terminal IRC client merged with a four-signal AI-text-detector and a multi-provider LLM chat interface, all in one ~5,700-line script with no required external dependencies beyond Python's standard library (everything else is auto-installed or optional).
