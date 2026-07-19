# Discord bot in Go

A Discord bot built with [DiscordGo](https://github.com/bwmarrin/discordgo), Subfinder, and HTTPX. It provides `/ping` plus administrator-only `/scan` and `/results` commands.

## 1. Create the Discord application

1. Open the [Discord Developer Portal](https://discord.com/developers/applications) and select **New Application**.
2. Open **Bot**, create the bot if needed, and reset/copy its token. Treat this token like a password.
3. Open **Installation** and configure a **Guild Install** with the `applications.commands` and `bot` scopes.
4. Give the bot the **Send Messages** and **Attach Files** permissions, copy the install link, and add it to a test server you control.

This starter does not require any privileged gateway intents.

## 2. Configure it

Copy `.env.example` to `.env`, then replace the placeholder values. To copy a server ID, enable **Developer Mode** in Discord under **User Settings > Advanced**, right-click the server icon, and select **Copy Server ID**.

The bot loads `.env` automatically during local development. Environment variables already supplied by your shell or deployment platform take precedence.

`DISCORD_GUILD_ID` is optional, but guild commands appear immediately and are best during development. If omitted, commands are registered globally and may take longer to appear.

The bot consolidates passive results from Subfinder, Shosubgo/Shodan, and GitHub Subdomains. Subfinder always runs with every source (`subfinder -all`). Set `SUBFINDER_PROVIDER_CONFIG` to your provider key YAML; its `github` and `shodan` entries enable the additional adapters. Without those keys, the corresponding adapters are skipped. `RESULTS_DIR` controls where `/scan` artifacts are written and defaults to `results`.

### Optional PureDNS brute forcing

PureDNS is packaged with MassDNS in a pinned Docker image. Its large wordlist and public resolver list stay in ignored local storage rather than Git. Prepare them once:

```sh
./scripts/setup-puredns.sh
```

Then set `PUREDNS_ENABLED=true` in `.env` and restart the bot. By default, PureDNS runs only when consolidated passive discovery finds `1,000` names or fewer. Adjust that cutoff with `PUREDNS_PASSIVE_THRESHOLD`; set `PUREDNS_RATE_LIMIT` to a query rate appropriate for your network and resolver list. Only one PureDNS job runs at a time, even though two scans may otherwise run concurrently.

The setup script downloads `n0kovo_subdomains_huge.txt` and the Trickest public resolver list into `data/puredns/`, then builds `discord-puredns:2.1.1`. Refresh either cached file by deleting just that file and running the setup again. PureDNS can also be used manually:

```sh
docker run --rm \
  --mount type=bind,source="$PWD/data/puredns/n0kovo_subdomains_huge.txt",target=/data/words.txt,readonly \
  --mount type=bind,source="$PWD/data/puredns/resolvers.txt",target=/data/resolvers.txt,readonly \
  discord-puredns:2.1.1 bruteforce /data/words.txt example.com \
  --resolvers /data/resolvers.txt --wildcard-batch 1000000 --rate-limit 5000 --quiet
```

Use only against domains you are authorized to test. Public resolvers change over time; curate your own resolver file when reliability matters and choose a responsible rate limit.

## 3. Run it

```sh
go mod tidy
go run .
```

In your Discord test server, enter `/ping`, `/scan domain:example.com`, or `/results domain:example.com`. Only server administrators can use the discovery commands, and you should only scan domains you own or are authorized to assess. Stop the bot with `Ctrl+C`.

`/scan` acknowledges immediately, runs in the background without an interaction timeout, and sends `httpx_results.txt` to the channel or your DMs when finished. Up to two scans run concurrently. Each scan performs consolidated passive discovery, optionally adds PureDNS brute-force results when enabled and below the passive threshold, validates the merged names through DNSX with 50 workers, and sends only names with an A or AAAA record to HTTPX. HTTPX probes ports `80`, `443`, `8443`, `8444`, `8080`, `3000`, and `5000` with 15 workers and normal HTTP/HTTPS fallback behavior. When both ports 80 and 443 respond for the same hostname, only the port 443 result is retained; results from the other configured ports remain untouched. Each run also creates:

```text
results/20260717T153628.000Z_example.com/
├── passive_subdomains.txt
├── puredns_subdomains.txt
├── raw_subdomains.txt
├── resolved_subdomains.txt
└── httpx_results.txt
```

The HTTPX file uses the familiar CLI-style format: one URL per line followed by bracketed status, redirect, content, title, server, IP, CDN, final-URL, and technology fields when present. If probing fails after enumeration, the partial artifacts are retained.

## Project layout

- `main.go` owns process signals and starts the application.
- `internal/app` assembles the bot and its dependencies.
- `internal/config` loads and validates environment configuration.
- `internal/discordbot` owns the Discord session and slash commands.
- `internal/dnsvalidate` filters consolidated results through ProjectDiscovery DNSX.
- `internal/dnsbruteforce` runs the optional Docker-backed PureDNS stage.
- `internal/subdomains` validates, runs, and consolidates all passive sources.
- `internal/subdomains/subfinder` adapts ProjectDiscovery Subfinder.
- `internal/subdomains/shosubgo` adapts Shodan's passive DNS-domain endpoint.
- `internal/subdomains/github-subs` searches GitHub code and extracts subdomains.
- `internal/httpprobe` adapts ProjectDiscovery HTTPX with the fixed probe profile.
- `internal/recon` orchestrates discovery, probing, and per-run artifact storage.
- `.env.example` documents the required configuration.
- `.gitignore` prevents your real token from being committed.

## Internal consolidated discovery capability

Code inside this module can use the consolidated capability directly like this:

```go
finder, err := subdomains.NewFinder()
if err != nil {
	return err
}

ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
defer cancel()

subs, err := finder.Enumerate(ctx, "example.com")
```

To supply a provider key file while using the internal capability directly:

```go
finder, err := subdomains.NewFinderWithOptions(subdomains.FinderOptions{
	ProviderConfig: "secrets/provider-config.yaml",
})
```

The provider file uses YAML lists. For example:

```yaml
github:
  - your_github_token
shodan:
  - your_shodan_api_key
securitytrails:
  - your_securitytrails_key
censys:
  - your_api_id:your_api_secret
```

The local `secrets/` directory is ignored by Git. Prefer mounting the file at runtime in production, and restrict it to its owner (for example, `chmod 600 secrets/provider-config.yaml`). Do not upload or commit it.

Only pass domains you own or are explicitly authorized to assess. Subfinder uses passive third-party sources; some optional sources require API keys in Subfinder's provider configuration.

Never paste or commit your Discord bot token. If it is exposed, reset it immediately in the Developer Portal.
