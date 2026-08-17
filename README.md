# SentraX AI

> **Autonomous security testing, explained.**
> Autonomous multi-agent AI system that attacks, finds, proves, and fixes security vulnerabilities in web apps and APIs — explaining every step in plain language.

---

## Installation (Global CLI)

SentraX is installed globally using `pipx`, giving you a seamless CLI experience (like `claude` or `gh`) available from any terminal and folder without manually activating virtual environments.

### 1. One-Time Setup: Install `pipx` (if not already installed)

On Debian/Ubuntu:
```bash
sudo apt update && sudo apt install -y pipx
pipx ensurepath
```

*(If this is your first time setting up `pipx`, restart your terminal once to apply PATH changes).*

### 2. Install SentraX in Editable Mode

Clone and install SentraX globally:
```bash
git clone https://github.com/Tanish18906/SentraX.git
cd SentraX
pipx install -e .
```

*Note: The `-e` (editable) flag ensures that any code updates made during development are immediately live without needing to reinstall.*

---

## Usage

Simply run `sentrax` from any terminal or directory:

```bash
sentrax
```

This launches the interactive SentraX terminal session.

### Interactive Commands

As soon as you type `/`, an autocompletion dropdown menu will appear with suggestions and descriptions:

| Command | Description |
|---|---|
| `/scan <url>` | Run DAST security scan against a live web target (e.g., `http://localhost:4000`) |
| `/scan-code <folder>` | Run SAST security scan against a local source code directory |
| `/report` | Re-display the most recent scan report |
| `/status` | Show current pipeline and scan status |
| `/clear` | Clear the terminal screen and redisplay banner |
| `/help` | Display list of available commands |
| `/exit`, `/quit` | Exit SentraX session (or press `Ctrl+C` / `Ctrl+D`) |

---

## Configuration

Copy the example environment file and configure your LLM API keys:

```bash
cp .env.example .env
```

Edit `.env` to provide your `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.
