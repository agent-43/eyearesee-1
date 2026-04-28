# eyearesee — Terminal IRC Client with AI Detection

**eyearesee.py** is a single-file, ~6,205-line Python 3 IRC (Internet Relay Chat) client that runs in the terminal as a curses-based TUI. The name is a phonetic spelling of "I-R-C."

Beyond being a fully featured IRC client, it has an unusual headline feature: it scores every message it sees with an ensemble of AI/LLM-detection models, flagging users whose chat looks machine-generated.

## Quick Start

```bash
python eyearesee.py
Note: python eyearesee.py --no-ai --no-install will run without installing dependencies or using offline AI.
For further usage help type: /commands
Thank you Amigojapan for feature list suggestions! Check his page out! https://github.com/amigojapan
( If on windows you have the option of installing a llm for AI, to do so just: winget install llama.cpp
and run the command: llama-server -hf ggml-org/gemma-4-E2B-it-GGUF --jinja -c 0 --host 127.0.0.1 --port 8033
and if you like use the /model command in the irc client to use it )
What it is, at a glance

Type: Asynchronous (asyncio) terminal IRC client with a curses-based text UI
Default target: irc.libera.chat:6697 over SSL, channel ##anime
Platforms: Linux, macOS, and Windows (auto-installs windows-curses on Windows if missing)
Auto-bootstrap: On first run it pip-installs missing optional dependencies and restarts itself
Storage: All data files (chat logs, AI scores log, input history) live next to the script so it works even when launched from a read-only working directory

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
AI_TELL_PHRASES, LLAMA_TELL_PHRASES, formality, contraction usage, capitalization, presence of casual IRC tokens (lol, lmao, brb...)
Llama pattern score — structural detection of markdown lists, numbered enumerations, colon-introduced lists, abnormally long messages, and templated multi-sentence structure
Binoculars score — the Hans et al. (2024) cross-entropy ratio method using two GPT-2-family models
Classifier score — averaged probability from two HuggingFace transformer classifiers

These are blended into a 0-100 ensemble score with an override that boosts scores for high-confidence Llama structural patterns. Models can be disabled entirely with --no-ai.
Each user gets a rolling AI-score average over their last 200 messages. Users above a threshold (default 70) are flagged "suspect" and highlighted.
Detection commands:

/ai — full profile with sparkline and verdict
/topai — channel ranking
/bot — mark as confirmed AI and build a vocabulary/n-gram fingerprint
/unbot — remove bot marking

Every detection is logged as a JSONL record to ai_scores.log.
LLM integration
The same client can also send messages to LLMs via /askai and /summarize. It supports four backends:

Anthropic Claude (cloud)
OpenAI (cloud)
Ollama (local)
llama.cpp (local)

API keys are read from environment variables or set at runtime with /api. The default model is qwen3 running on local llama.cpp.
Plugin system

Hot-reloadable plugins via /loadplugin
Any Python file with a setup(api) function can register custom slash commands

Architecture
The code is organized into ten classes plus a large block of module-level utilities:

IRCClient — the network layer
TUI — the curses interface
ChatWindow / UserState / ServerContext — per-window and per-user state tracking
EnsembleAIDetector — the LLM detection engine
BotFingerprint / ScoringEngine — confirmed-bot fingerprinting
PluginAPI / PluginManager — hot-reloadable plugin system

Includes performance work (LRU caches, O(1) lookups, chunked log reading) and defensive coding practices.
Running without dependencies / AI
Bash python eyearesee.py --no-ai --no-install
This command runs the core IRC client cleanly without installing packages or enabling AI detection.
 
eyearesee is an unusually ambitious single-file project: a polished, IRCv3-compliant terminal IRC client merged with a four-signal AI-text-detector and a multi-provider LLM chat interface, all in one ~5,700-line script with no required external dependencies beyond Python's standard library.
