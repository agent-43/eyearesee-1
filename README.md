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

Eye Are See IRC Client 👁️
Eye Are See is a highly advanced, feature-rich, and intelligent IRC client built in Python, designed for serious IRC users, developers, and anyone interested in analyzing communication patterns, particularly the detection of AI-generated content.

It combines a powerful, modern Curses-based Terminal User Interface (TUI) with deep machine learning and linguistic analysis capabilities to give you unprecedented insight into your chat environment.

✨ Features at a Glance
🧠 Advanced AI & Bot Detection
Ensemble AI Scoring: Uses an ensemble of large models (Anthropic Claude, OpenAI GPT, Ollama, Llama.cpp) to generate a detailed AI probability score for every message.
Linguistic Heuristics: Combines ML predictions with classical linguistic analysis (formality, repetition, structural patterns) to create a robust, multi-layered assessment.
Bot Fingerprinting: Learns the unique vocabulary, bigrams, and trigrams of confirmed bot users to detect similar writing styles in other users.
Real-time Monitoring: Tracks user AI likelihood, message frequency, and typing regularity to flag suspicious behavior.
AI Interaction Commands:
/askai [model] <question>: Query any configured model and see the answer in the dashboard.
/summarize [n] [model]: Generate a structured summary of the last n messages in a window using an AI model.
/model [key]: Set or list available AI models (e.g., gpt4o, gemma, sonnet).
Bot Management: /bot and /unbot commands to confirm or remove confirmed AI users.
AI Toggle: /aitoggle to enable or disable all AI scoring features.
🖥️ Advanced Terminal UI (Curses)
Multi-Server Support: Connect and manage multiple IRC servers in parallel via /server.
Tabbed Interface: Organize channels, status, and dashboards in a clean, navigable tab bar.
Line Wrapping: Intelligent line wrapping that correctly handles CJK (East Asian) characters and Unicode grapheme clusters, ensuring perfect terminal display.
URL Clicking: Left-click highlighted URLs in the chat window to open them in your default browser.
Input History: Full history logging and Ctrl+Up/Down navigation.
Real-time Feedback: Instantaneous input drawing for a smooth typing experience.
⚙️ Robust IRCv3 & Network Features
SASL Support: Secure connections via PLAIN, SCRAM-SHA-256, EXTERNAL (client certs), and ECDSA-NIST256P-CHALLENGE.
CTCP Support: Send IRCv3 control messages (PING, VERSION, TIME, CLIENTINFO, FINGER) to the server.
Message Tags: Full support for IRCv3 tags like MESSAGE-REDACTION, MARKREAD, and TAGMSG.
Auto-Translation: Automatically translates CJK messages into English.
Plugin System: Dynamically load and unload custom Python plugins to extend client functionality.
🚀 Installation
Eye Are See requires Python 3.8+ and relies on pip for dependency management.

Prerequisites
Ensure you have Python installed.

Dependencies
Eye Are See automatically checks for and installs necessary packages for AI detection and Curses support.

bash

# Install all required dependencies (transformers, torch, anthropic, openai, etc.)
# If you run the script, it will automatically detect missing packages and prompt you to install them.
pip install eyearesee
Note: The AI detection components require transformers and torch. If installation fails, please check your environment and ensure you have the necessary hardware (CPU/GPU) if you intend to use the ML features.

⚙️ Configuration
Configuration is handled via environment variables, a configuration file (irc_config.json), or interactive prompts upon startup.

1. Server & Nick
These are set interactively upon launch, or via irc_config.json.

Server: DEFAULT_SERVER (e.g., irc.libera.chat or server:host:port).
Nick: DEFAULT_NICK.
Channel: DEFAULT_CHANNEL (prefixed with # if omitted).
2. SASL Credentials
If using secure authentication, configure these via the interactive prompt or irc_config.json.

IRC_SASL_MECHANISM: PLAIN, SCRAM-SHA-256, EXTERNAL, or ECDSA-NIST256P-CHALLENGE.
IRC_NICKSERV_PASSWORD: Password for PLAIN/SCRAM mechanisms.
IRC_SASL_CERT / IRC_SASL_KEY: Paths to PEM files for EXTERNAL or ECDSA-NIST256P-CHALLENGE.
3. AI API Keys (Optional)
Set these via the /api command or environment variables.

Variable	Description	Commands
ANTHROPIC_API_KEY	Anthropic API Key	/api ANTHROPIC_API_KEY <value>
OPENAI_API_KEY	OpenAI API Key	/api OPENAI_API_KEY <value>
DEEPSEEK_API_KEY	DeepSeek API Key	/api DEEPSEEK_API_KEY <value>
GITHUB_TOKEN	GitHub Copilot Token	/api GITHUB_TOKEN <value>
OLLAMA_URL	Local Ollama Server URL	/api OLLAMA_URL <url>
LLAMACPP_URL	Local llama.cpp Server URL	/api LLAMACPP_URL <url>
💬 Basic Usage
Start the client, and use the /help command for a full list of commands.

Core Commands:

Command	Usage	Description
/join	/join #channel	Join a channel.
/part	/part #channel [message]	Leave a channel.
/nick	/nick newnick	Change your nickname.
/msg	/msg <nick> <text>	Send a private message (opens DM window).
/query	/query <nick> [message]	Open a DM window with a nick; optionally send a first message.
/mode	/mode <target> [modes]	Get or set channel/user modes (+o, -o, +v, -v, +h, -h, +b, -b).
/kick	/kick <chan> <nick> [reason]	Kick a user from a channel.
/whois	/whois <nick>	Look up user information (shown in status window).
/server	/server [-ssl] <host> [port]	Connect to a new IRC server in parallel.
🤖 AI & Bot Analysis Usage
These features require the AI detection module to be enabled (/aitoggle).

AI Interaction
/askai [model] <question>: Ask a question using a specified model (e.g., /askai gpt4o "Explain quantum entanglement.").
/summarize [n] [model]: Summarize the last n messages in the current window.
/model [key]: View or set the AI model for future /askai and /summarize calls.
Bot Management
/bot <nick>: Mark a nick as a confirmed bot/AI. The client will build a linguistic fingerprint from their messages.
/unbot <nick>: Remove the confirmed bot status and fingerprint for a user.
/topai: View a ranked list of users in the current channel, sorted by their rolling AI score.
📝 Persistence and Logging
Eye Are See automatically logs detailed AI scores to ai_scores.log and maintains input history to ensure no activity is lost.

AI Score Log (ai_scores.log): Stores every message with detailed scores (AI probability, heuristic scores, Llama patterns, classifier probabilities, etc.) for auditing and analysis.
Chat History: Message history is persisted to disk and loaded efficiently, ensuring the chat window state is maintained across sessions.
🛠️ Plugins
Eye Are See supports a flexible plugin architecture.

/loadplugin <path>: Load a Python plugin file.
/unloadplugin <name>: Unload a plugin.
/reloadplugin <name>: Reload a plugin from its source file (hot-swap).
/plugins: List all currently loaded plugins and their available commands.
Summary: eyearesee is an unusually ambitious single-file project: a polished, IRCv3-compliant terminal IRC client merged with a four-signal AI text detector and a multi-provider LLM chat interface, all in one script with minimal external dependencies.
