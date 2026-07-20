#!/bin/sh
set -eu

command -v curl >/dev/null 2>&1 || {
	printf 'curl is required to download PureDNS data.\n' >&2
	exit 1
}
command -v docker >/dev/null 2>&1 || {
	printf 'Docker is required to build the PureDNS image.\n' >&2
	exit 1
}

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
data_dir=${PUREDNS_DATA_DIR:-"$project_dir/data/puredns"}
image=${PUREDNS_IMAGE:-discord-puredns:2.1.1}
wordlist="$data_dir/n0kovo_subdomains_huge.txt"
resolvers="$data_dir/resolvers.txt"

mkdir -p "$data_dir"

if [ ! -s "$wordlist" ]; then
	wordlist_tmp="$wordlist.tmp"
	curl --fail --location --retry 3 \
		--output "$wordlist_tmp" \
		https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/refs/heads/main/n0kovo_subdomains_huge.txt
	mv "$wordlist_tmp" "$wordlist"
fi

if [ ! -s "$resolvers" ]; then
	resolvers_tmp="$resolvers.tmp"
	curl --fail --location --retry 3 \
		--output "$resolvers_tmp" \
		https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
	mv "$resolvers_tmp" "$resolvers"
fi

docker build --tag "$image" --file "$project_dir/docker/puredns/Dockerfile" "$project_dir"
docker run --rm --entrypoint caduceus "$image" -h >/dev/null 2>&1

printf 'PureDNS and Caduceus are ready. Add PUREDNS_ENABLED=true to .env and restart the bot.\n'
printf 'Image: %s\nWordlist: %s\nResolvers: %s\n' "$image" "$wordlist" "$resolvers"
