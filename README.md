# Discord bot in Go

A Discord bot built with [DiscordGo](https://github.com/bwmarrin/discordgo), Subfinder, HTTPX, and Caduceus. It provides `/ping` plus administrator-only `/scan`, `/queue`, `/add`, and `/get` commands.

## 1. Create the Discord application

1. Open the [Discord Developer Portal](https://discord.com/developers/applications) and select **New Application**.
2. Open **Bot**, create the bot if needed, and reset/copy its token. Treat this token like a password.
3. Open **Installation** and configure a **Guild Install** with the `applications.commands` and `bot` scopes.
4. Give the bot the **Send Messages** and **Attach Files** permissions, copy the install link, and add it to a test server you control.

This starter does not require any privileged gateway intents.

## 2. Configure it

Create the persistent configuration directory and copy the YAML template once:

```sh
mkdir -p ~/.config/recon-bot
cp config.example.yaml ~/.config/recon-bot/config.yaml
chmod 600 ~/.config/recon-bot/config.yaml
```

Edit `discord.token` in that file. `discord.guild_id` is optional, but guild commands appear immediately and are best during development. To copy a server ID, enable **Developer Mode** in Discord under **User Settings > Advanced**, right-click the server icon, and select **Copy Server ID**. If the ID is omitted, commands are registered globally and may take longer to appear.

The bot consolidates passive results from Subfinder, Shosubgo/Shodan, and GitHub Subdomains. Subfinder always runs with every source (`subfinder -all`). Set `subfinder.provider_config` to your provider key YAML; its `github` and `shodan` entries enable the additional adapters. Without those keys, the corresponding adapters are skipped. Paths beginning with `~` are expanded, and relative paths are resolved from the bot YAML's directory rather than the shell's working directory.

New `/scan subs` and `/scan ips` runs are stored as normalized rows in SQLite. Leave `database.path` empty to use `~/.config/recon-bot/recon.db`, outside the cloned repository and with owner-only permissions. Set an explicit path only when you want another location.

On the first run after upgrading, if the persistent database does not exist but the former repository-local `data/recon.db` does, the bot creates a consistent SQLite copy at the new location and leaves the original untouched. The same relocation check runs before `recon-bot migrate`. Once the startup log confirms the persistent path, back up `~/.config/recon-bot/recon.db` separately from the Git checkout.

### Optional PureDNS brute forcing

PureDNS is packaged with MassDNS in a pinned Docker image. The installed bot prepares it without a repository checkout or configuration file:

```sh
recon-bot build
```

The build command downloads and caches the n0kovo wordlist and public resolver list under the user's cache directory, builds both into `discord-puredns:2.1.1`, and verifies that the image contains them and Caduceus. The bot does not need host paths or bind mounts for either file. Set `puredns.enabled: true` in the bot YAML and restart it. By default, PureDNS runs only when consolidated passive discovery finds `1,000` names or fewer. Adjust `puredns.passive_threshold` and set `puredns.rate_limit` to a query rate appropriate for your network and resolver list. Only one PureDNS job runs at a time, even though two scans may otherwise run concurrently.

The downloaded source copies remain under `~/.cache/recon-bot/tool-image/` solely as Docker build inputs. PureDNS can also be used manually without mounts:

```sh
docker run --rm \
  discord-puredns:2.1.1 bruteforce /data/n0kovo_subdomains_huge.txt example.com \
  --resolvers /data/resolvers.txt --wildcard-batch 1000000 --rate-limit 5000 --quiet
```

The same image includes Caduceus v1.0.5, built with CGO and GCC. PureDNS remains the default entrypoint for bot compatibility, so invoke Caduceus explicitly:

```sh
docker run --rm --entrypoint caduceus discord-puredns:2.1.1 -h
docker run --rm --entrypoint caduceus discord-puredns:2.1.1 -i 192.0.2.10 -p 443
```

The `/scan ips` command runs Caduceus in the background. For a small input, pass comma- or space-separated IPv4 addresses and CIDRs directly:

```text
/scan ips targets:192.0.2.10,198.51.100.0/28 ports:443,8443
```

For large inputs, attach a text file with one IPv4 address or CIDR per line:

```text
/scan ips file:targets.txt ports:443,8443
```

Choose exactly one of `targets` and `file`. Attachments are limited to 8 MiB, validated before the job starts, and streamed to the container over stdin. Caduceus currently handles IPv4 targets; IPv6 input is rejected instead of being passed in a format the upstream tool cannot scan correctly. `/scan ips` publishes `caduceus_results.txt` when complete and saves its inputs in `ip_targets` and discoveries in `ip_domains`. Failed runs retain any rows completed before the failure. Only one Caduceus job runs at a time. IP runs remain separate from `/get scans` and `/get roots`.

Use only against domains and address ranges you are authorized to test. Public resolvers change over time; curate your own resolver file when reliability matters and choose a responsible rate limit.

## 3. Run it

Install or update the compiled binary directly from GitHub:

```sh
go install github.com/Unit-8200/recon-bot@latest
$(go env GOPATH)/bin/recon-bot run --config ~/.config/recon-bot/config.yaml
```

`go install ...@latest` replaces the installed binary but does not restart an already running process. Stop the foreground copy in `screen` with `Ctrl+C` and launch the command above again. Use `@main` instead of `@latest` when you deliberately want the newest pushed commit rather than the latest release. The YAML and SQLite database remain under `~/.config/recon-bot` during binary updates.

For a private GitHub repository, configure Go to fetch this organization directly and ensure the VPS Git credentials can read it:

```sh
go env -w 'GOPRIVATE=github.com/Unit-8200/*'
git config --global url."git@github.com:".insteadOf "https://github.com/"
go install github.com/Unit-8200/recon-bot@latest
```

During local development, use `go run . run --config /path/to/config.yaml`. The Cobra command tree also provides `recon-bot --help`, `recon-bot version`, and shell completion through `recon-bot completion <shell>`.

In your Discord test server, enter `/ping`, `/scan subs domain:example.com`, `/get scans domain:example.com`, or `/get roots`. `/get scans` defaults to `content:full format:txt`; use `/get scans domain:example.com format:xlsx` for a filterable spreadsheet containing normalized HTTP probe columns. Select `content:urls` with either format for only sorted, unique HTTP(S) URLs—for example, `/get scans domain:example.com content:urls format:xlsx` produces `urls.xlsx`. `/get scans domain:*` combines every completed scan, while a wildcard such as `/get scans domain:*example.com` combines every completed scan whose root domain matches; all of these forms support both content and attachment choices. `/get roots` publishes a unique, sorted list of all root domains represented in the saved scan history. Successful `/get` responses are visible to everyone in the channel. Only server administrators can use the data and discovery commands, and you should only scan domains and address ranges you own or are authorized to assess. Stop the bot with `Ctrl+C`.

Every accepted scan receives a process-local queue ID in its acknowledgement. `/queue list` publicly shows all currently queued and running subdomain and IP scans. `/queue delete id:<id>` cancels that scan; a waiting scan never starts, while a running scan is stopped and its `runs` row plus related `subdomains`, `http_probes`, `ip_targets`, and `ip_domains` rows are deleted. Completed scans no longer appear in the queue and are not deleted by this command. Queue IDs reset when the bot restarts.

Use `/add data:<value>` to place a single-line value in the bot's standalone shared storage. The optional `description` field adds context, and adding the same value again updates its description without creating a duplicate. `/get storage` publishes every manually stored value in `data.txt` without descriptions. Use `/get storage descriptions:true` to append descriptions as `value — description`. This storage is intentionally isolated from `/scan subs`, `/scan ips`, `/get scans`, and `/get roots`.

`/scan subs` acknowledges immediately with its queue ID, runs in the background without an interaction timeout, and sends `httpx_results.txt` to the channel or your DMs when finished. Up to two scans run concurrently. Each scan performs consolidated passive discovery, optionally adds PureDNS brute-force results when enabled and below the passive threshold, validates the merged names through DNSX with 50 workers, and sends only names with an A or AAAA record to HTTPX. HTTPX probes ports `80`, `443`, `8443`, `8444`, `8080`, `3000`, and `5000` with 20 workers and normal HTTP/HTTPS fallback behavior. When both ports 80 and 443 respond for the same hostname, only the port 443 result is retained; results from the other configured ports remain untouched. Each run also creates:

```text
passive_subdomains.txt
puredns_subdomains.txt
raw_subdomains.txt
resolved_subdomains.txt
httpx_results.txt
```

These filenames describe the Discord attachments generated from normalized database rows; new filesystem files are not created. The HTTPX attachment uses the familiar CLI-style format: one URL per line followed by bracketed status, redirect, content, title, server, IP, CDN, final-URL, and technology fields when present. If probing fails after enumeration, rows completed before the failure remain associated with the failed database run.

### SQLite tables

- `runs` stores scan type, root domain, timestamp, status, error, and legacy source path.
- `subdomains` stores one hostname per `/scan subs` run with passive, bruteforced, and resolved flags.
- `http_probes` stores one HTTPX endpoint per row with its URL, status, title, server, IPs, technologies, redirect, content metadata, and display output.
- `ip_targets` stores each IP address or CIDR passed to `/scan ips`.
- `ip_domains` stores each unique domain returned by Caduceus for an IP scan.
- `stored_items` stores values submitted manually through `/add` and is the only table read by `/get storage`.

### Merge previous results

Import an existing legacy results directory with:

```sh
recon-bot migrate --config ~/.config/recon-bot/config.yaml --folder /path/to/results
```

Or merge a previous database into the database selected by the YAML configuration:

```sh
recon-bot migrate --config ~/.config/recon-bot/config.yaml --db /path/to/previous-recon.db
```

Choose exactly one of `--folder` and `--db`. Folder imports recognize both `timestamp_domain/` and `timestamp_ips/` directories. Database imports include subdomain runs, HTTP probes, IP runs, and manually added storage items. Both modes are additive: they never clear or replace rows already in the configured destination database, and the source files are opened without modification. You can therefore import a folder first and a database afterward; the destination keeps the union of both. Repeating an import from the same folder or database path skips runs already imported, while duplicate stored items are merged by their unique data value.

## Project layout

- `main.go` owns process signals and starts the application.
- `internal/app` assembles the bot and its dependencies.
- `internal/config` strictly loads and validates the YAML configuration.
- `internal/database` owns the SQLite schema and transactional persistence.
- `internal/discordbot` owns the Discord session and slash commands.
- `internal/modules` groups the independent scanning and discovery capabilities.
- `internal/modules/dnsvalidate` filters consolidated results through ProjectDiscovery DNSX.
- `internal/modules/dnsbruteforce` runs the optional Docker-backed PureDNS stage.
- `internal/modules/subdomains` validates, runs, and consolidates all passive sources.
- `internal/modules/subdomains/subfinder` adapts ProjectDiscovery Subfinder.
- `internal/modules/subdomains/shosubgo` adapts Shodan's passive DNS-domain endpoint.
- `internal/modules/subdomains/github-subs` searches GitHub code and extracts subdomains.
- `internal/modules/httpprobe` adapts ProjectDiscovery HTTPX with the fixed probe profile.
- `internal/modules/ipscan` runs Docker-backed Caduceus scans for IPv4 addresses and CIDRs.
- `internal/migration` additively imports legacy result directories and previous SQLite databases.
- `internal/recon` orchestrates discovery, probing, and per-run artifact storage.
- `internal/scanqueue` coordinates current jobs and scan cancellation.
- `config.example.yaml` documents every runtime setting.
- `.gitignore` prevents a repository-local `config.yaml` and old `.env` secrets from being committed.

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
