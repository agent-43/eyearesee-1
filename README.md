# 🤖 eyearesee — Terminal IRC Client with AI Detection

**eyearesee.py** is a single-file, ~6,205-line Python 3 IRC (Internet Relay Chat) client that runs in the terminal as a curses-based Text User Interface (TUI). The name is a phonetic spelling of "I-R-C."

Beyond being a fully featured IRC client, it features a unique headline feature: it scores every message with an ensemble of AI/LLM-detection models, flagging users whose chat appears machine-generated.

---

## 🚀 Quick Start

To run the core client without installing dependencies or enabling AI detection:

```bash
python eyearesee.py --no-ai --no-install

Installation & Setup Notes
Help: For further usage help, type /commands in the client.
Feature Suggestions: Thank you Amigojapan for feature list suggestions! Check out his page: https://github.com/amigojapan
Windows LLM Setup (Optional): If you wish to enable local AI detection on Windows, you can install an LLM (e.g., llama.cpp) and run the server:
bash

winget install llama.cpp
llama-server -hf ggml-org/gemma-4-E2B-it-GGUF --jinja -c 0 --host 127.0.0.1 --port 8033
You can then use the /model command in the IRC client to utilize the local model.
At a Glance
Feature	Description
Type	Asynchronous (asyncio) terminal IRC client with a curses-based text UI.
Default Target	irc.libera.chat:6697 over SSL, channel ##anime.
Platforms	Linux, macOS, and Windows (auto-installs windows-curses if missing).
Auto-Bootstrap	On first run, it pip-installs missing optional dependencies and restarts itself.
Storage	All data (logs, AI scores, history) lives next to the script, ensuring persistence even in read-only directories.
🛠️ Core Features
💬 IRC Client Capabilities
eyearesee implements a near-complete IRC feature set, including:

Messaging: /msg, /query, /notice, /me
Channel Operations: /join, /part, /topic, /kick, /invite, /names
Operator Commands: /op, /voice, /ban, etc.
Services: /ns (NickServ), /cs (ChanServ), /ctcp
User Info: /whois, /whowas, /who, /away//back, /ignore
Connection Management: /server (for parallel connections) and /reconnect.
Notable Refinements:

IRCv3 Parsing: Supports message-tag parsing so server-time-tagged messages are not dropped.
Theming: Five built-in color themes (Classic, Hacker, Ocean, Sunset, Neon) selectable with /theme.
CJK Handling: Wide-character support ensures Japanese, Chinese, and Korean text aligns correctly in fixed-width terminal columns.
Auto-Translation: Toggle for automatic translation of CJK messages.
Persistence: Persistent input history (up to 500 lines) across sessions and per-window persistent chat logs.
Formatting: Inline IRC formatting (bold, italic, underline, color codes) with a performance-optimized parse cache.
URL Detection: Automatic detection of URLs within messages.
🧠 The AI-Detection System (Distinguishing Feature)
Every incoming PRIVMSG is analyzed by the EnsembleAIDetector, which combines four distinct signals to generate a holistic score.

Detection Signals:
Heuristic Score: Pattern matching against curated phrase sets, formality levels, contraction usage, capitalization, and presence of casual IRC tokens (e.g., lol, lmao, brb).
Llama Pattern Score: Structural detection of machine-generated patterns, such as markdown lists, numbered enumerations, colon-introduced lists, abnormally long messages, and templated multi-sentence structures.
Binoculars Score: Uses the Hans et al. (2024) cross-entropy ratio method employing two GPT-2-family models for structural analysis.
Classifier Score: Averaged probability from two HuggingFace transformer classifiers.
These scores are blended into a 0-100 ensemble score, with an override that boosts scores for high-confidence Llama structural patterns. Models can be disabled entirely via the --no-ai flag.

Flagging: Users above a threshold (default 70) are flagged as "suspect" and highlighted.
Detection Commands:
/ai: Shows a full profile with a sparkline and verdict.
/topai: Ranks users by their AI suspicion score in the current channel.
/bot: Marks a user as confirmed AI and builds a vocabulary/n-gram fingerprint.
/unbot: Removes the bot marking.
Logging: Every detection is logged as a JSONL record to ai_scores.log.
💡 LLM Integration
The client supports sending messages to various Large Language Models via /askai and /summarize.

Supported Backends:

Anthropic Claude (Cloud)
OpenAI (Cloud)
Ollama (Local)
llama.cpp (Local)
API keys are read from environment variables or can be set at runtime using /api. The default model is qwen3 running locally via llama.cpp.

🧩 Plugin System
The architecture supports hot-reloadable plugins via the /loadplugin command. Any Python file with a setup(api) function can register custom slash commands, extending the client's functionality easily.

🏗️ Architecture
The project is organized into ten classes and a large block of module-level utilities, ensuring clear separation of concerns:

IRCClient: Handles the network layer and connection management.
TUI: Manages the curses interface and terminal display.
ChatWindow / UserState / ServerContext: Manages per-window and per-user state tracking.
EnsembleAIDetector: The core LLM detection engine.
BotFingerprint / ScoringEngine: Handles confirmed-bot fingerprinting and score aggregation.
PluginAPI / PluginManager: Implements the hot-reloadable plugin system.
The codebase includes performance optimizations (LRU caches, O(1) lookups, chunked log reading) and defensive coding practices.

Summary: eyearesee is an unusually ambitious single-file project: a polished, IRCv3-compliant terminal IRC client merged with a four-signal AI text detector and a multi-provider LLM chat interface, all in one script with minimal external dependencies.
