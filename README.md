# Security Skills for CLI Agents

A collection of security testing skills built from analyzing **4,000+ paid HackerOne bug bounty reports**. These skills can be used with Claude Code, Gemini CLI, or any agent that supports MCP/Skills.

## What is this?

This repo contains specialized prompts (skills) that teach AI coding agents how to find real security vulnerabilities. Instead of dumping thousands of bug reports into context, each skill distills the patterns and techniques from hundreds of real-world findings into actionable guidance.

## Available Skills

| Skill | Description |
|-------|-------------|
| `mitmfindidor` | Find Insecure Direct Object Reference vulnerabilities |
| `mitmfindauth` | Detect authentication and authorization issues |
| `mitmfindbizlogic` | Identify business logic flaws |
| `mitmfindssrf` | Find Server-Side Request Forgery vulnerabilities |
| `mitmfindsqli` | Detect SQL injection patterns |
| `mitmfindotp` | Find OTP/2FA bypass vulnerabilities |
| `mitmfindpii` | Identify PII exposure issues |
| `mitmfindsecrets` | Detect leaked secrets and API keys |
| `mitmfindcallback` | Find callback/webhook security issues |
| `mitmfindchecksum` | Identify checksum/integrity bypass opportunities |
| `mitmfindenumerable` | Find enumerable endpoints and IDs |
| `mitmfindinsecure` | Detect insecure configurations |
| `mitmfindreferer` | Find referer-based vulnerabilities |
| `mitmlistapis` | List and analyze captured API endpoints |
| `mitmsubdomains` | Analyze subdomain patterns |
| `mitmsecurityaudit` | Run comprehensive security audit |
| `mitmreport` | Generate security report |

## Setup

### For Claude Code

Copy skills to your project's `.claude/skills/` directory:

```bash
mkdir -p .claude/skills
cp *.md .claude/skills/
```

### For Gemini CLI

Copy as commands to `.gemini/commands/`:

```bash
mkdir -p .gemini/commands
cp *.md .gemini/commands/
```

## Usage

1. Start mitmproxy to capture traffic:
   ```bash
   mitmdump -w traffic.mitm --set flow_detail=3 2>&1 | tee log.txt &
   ```

2. Configure your browser/app to proxy through `localhost:8080`

3. Browse the target application to capture traffic

4. Ask your AI agent to analyze:
   ```
   Find security issues in example.com
   Check for idor and auth issues
   Run a full security audit
   ```

## How It Works

Rather than overwhelming the AI with raw bug reports, each skill contains:
- High-value patterns extracted from real bounty-winning reports
- Specific grep/regex patterns to search traffic logs
- Testing methodology with curl examples
- Severity ratings and impact assessment
- False positive guidance

## Disclaimer

**Only use these tools on systems you have explicit permission to test.** Unauthorized security testing is illegal. These skills are intended for:
- Authorized penetration testing
- Bug bounty programs where you have permission
- Security research on your own systems
- Educational purposes

## Credits

Built by analyzing 4,000+ paid bug bounty reports from [HackerOne's public disclosures](https://huggingface.co/datasets/Hacker0x01/hackerone_disclosed_reports).
