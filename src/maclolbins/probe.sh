#!/bin/bash
# Guest-side collector, run as /bin/bash -s on the target. Read-only: it never writes outside
# its own temp directory. It inventories the top-level executables of the target's default PATH,
# built the way path_helper builds it. Inputs are newline-separated variables set by the host
# preamble:
#   LOLBINS_PATH_SOURCES  files listing PATH directories, or directories of such files read in
#                         name order (normally /etc/paths and /etc/paths.d)
#   LOLBINS_SYMBOLS       imported symbol names the capability rules look for
# Output is one tab-separated record per line; maclolbins/probe.py documents and parses it.
set -euo pipefail

: "${LOLBINS_PATH_SOURCES?set LOLBINS_PATH_SOURCES to newline-separated files or directories}"
: "${LOLBINS_SYMBOLS?set LOLBINS_SYMBOLS to newline-separated symbol names}"

oneline() { tr '\t\n' '  '; }
b64() { base64 | tr -d '\n'; }
emit_fact() { printf 'H\t%s\t%s\n' "$1" "$(printf '%s' "$2" | oneline)"; }

collect_facts() {
	emit_fact collected_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	emit_fact product_version "$(sw_vers -productVersion)"
	emit_fact build_version "$(sw_vers -buildVersion)"
	emit_fact kernel "$(uname -r)"
	emit_fact arch "$(uname -m)"
	emit_fact hostname "$(hostname)"
	emit_fact user "$(id -un)"
	emit_fact groups "$(id -Gn)"
	emit_fact sip "$(csrutil status 2>&1 || true)"
	emit_fact gatekeeper "$(spctl --status 2>&1 || true)"
	emit_fact developer_dir "$(xcode-select -p 2>/dev/null || echo none)"
}

# The default PATH: each source file's lines in order, each source directory's files in name
# order, first occurrence of a directory wins; this is what path_helper does with /etc/paths.d.
list_path_dirs() {
	local source file
	while IFS= read -r source; do
		if [ -d "$source" ]; then
			for file in "$source"/*; do
				if [ -f "$file" ]; then grep -vE '^[[:space:]]*(#|$)' "$file" || true; fi
			done
		elif [ -f "$source" ]; then
			grep -vE '^[[:space:]]*(#|$)' "$source" || true
		fi
	done <<<"$LOLBINS_PATH_SOURCES" | awk '!seen[$0]++'
}

list_candidates() {
	local dir
	while IFS= read -r dir; do
		[ -d "$dir" ] || continue
		find "$dir" -maxdepth 1 \( -type f -o -type l \) -perm +111 -print 2>/dev/null || true
	done <"$WORK/path_dirs"
}

# Capability evidence for a compiled binary: the imported symbols the catalog asks about, plus the
# library paths it links. Mach-O string tables keep both as NUL-separated tokens.
emit_evidence() {
	local path=$1 tokens
	tokens=$(LC_ALL=C grep -aoE '[A-Za-z0-9_$./+-]{4,}' "$path" 2>/dev/null |
		awk 'NR == FNR { want[$0] = 1; next }
			($0 in want) || /^\/(usr\/lib|System\/Library)\/.*(\.dylib$|\.framework\/)/' \
			"$WORK/symbols" - | sort -u || true)
	printf 'C\t%s\t%s\n' "$path" "$(printf '%s' "$tokens" | b64)"
}

emit_stats() {
	tr '\n' '\0' <"$1" | xargs -0 stat -L -f 'P%t%Sp%t%Su%t%Sg%t%z%t%Sf%t%N' 2>/dev/null || true
}

# Text columns are stripped of tabs and newlines so every grant stays one record.
TCC_QUERY="SELECT replace(replace(service, char(9), ' '), char(10), ' '),
	replace(replace(client, char(9), ' '), char(10), ' '), client_type, auth_value,
	replace(replace(indirect_object_identifier, char(9), ' '), char(10), ' ') FROM access;"

# Read-only: sqlite3 opens each TCC database with -readonly. Reading needs Full Disk Access, so
# a database the probe cannot open is reported as unreadable rather than failing the scan.
collect_tcc() {
	local scope db rows
	for scope in system user; do
		if [ "$scope" = system ]; then
			db="/Library/Application Support/com.apple.TCC/TCC.db"
		else
			db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
		fi
		if [ ! -e "$db" ]; then
			printf 'D\t%s\tmissing\t%s\n' "$scope" "$db"
			continue
		fi
		if rows=$(/usr/bin/sqlite3 -readonly -separator $'\t' "$db" "$TCC_QUERY" 2>"$WORK/tcc.err"); then
			printf 'D\t%s\tok\t%s\n' "$scope" "$db"
			if [ -n "$rows" ]; then printf '%s\n' "$rows" | sed "s/^/T\t$scope\t/"; fi
		else
			printf 'D\t%s\tunreadable\t%s\n' "$scope" "$(oneline <"$WORK/tcc.err")"
		fi
	done
}

emit_hashes() {
	tr '\n' '\0' <"$1" | xargs -0 shasum -a 256 2>/dev/null |
		awk '{ hash = $1; sub(/^[0-9a-f]+  /, ""); printf "S\t%s\t%s\n", hash, $0 }' || true
}

emit_summaries() {
	sed 's|.*/||' "$1" | sort -u | tr '\n' '\0' | { xargs -0 whatis 2>/dev/null || true; } |
		awk '/ - / { gsub(/\t/, " "); print "W\t" $0 }'
}

# Emit launchd Mach-service registrations only for executables already in the inventory. This is
# candidate identification: it reads plist metadata and static listener strings, but never looks
# up a Mach service or opens an XPC connection.
emit_xpc_registrations() {
	local paths_file=$1 plist services program label context markers
	for plist in \
		/System/Library/LaunchAgents/*.plist \
		/System/Library/LaunchDaemons/*.plist \
		/Library/LaunchAgents/*.plist \
		/Library/LaunchDaemons/*.plist; do
		[ -f "$plist" ] || continue
		services=$(/usr/bin/plutil -extract MachServices json -o - "$plist" 2>/dev/null) || continue
		[ "$services" != "{}" ] || continue
		program=$(/usr/bin/plutil -extract Program raw -o - "$plist" 2>/dev/null ||
			/usr/bin/plutil -extract ProgramArguments.0 raw -o - "$plist" 2>/dev/null) || continue
		/usr/bin/grep -Fqx "$program" "$paths_file" || continue
		label=$(/usr/bin/plutil -extract Label raw -o - "$plist" 2>/dev/null) || continue
		case "$plist" in
		*LaunchDaemons*) context=system ;;
		*) context=user ;;
		esac
		markers=$(LC_ALL=C /usr/bin/grep -aoE \
			'NSXPCListener|shouldAcceptNewConnection|xpc_main|xpc_connection_create_mach_service|xpc_connection_set_event_handler' \
			"$program" 2>/dev/null | /usr/bin/sort -u || true)
		printf 'X\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$program" "$label" "$context" "$plist" \
			"$(printf '%s' "$services" | b64)" "$(printf '%s' "$markers" | b64)"
	done
}

probe_file() {
	local path=$1 link="" magic="" is_script=0 info ent
	# find listed it a moment ago; skip it if it has since gone.
	if [ ! -e "$path" ] && [ ! -L "$path" ]; then return; fi
	if [ -L "$path" ]; then link=$(readlink "$path"); fi
	if [ -r "$path" ]; then
		IFS= read -r -n 2 magic 2>/dev/null <"$path" || true
	fi
	if [ "$magic" = "#!" ]; then is_script=1; fi
	ent=$(codesign -dv --verbose=2 --entitlements - --xml "$path" 2>"$WORK/codesign.err" | b64) || true
	info=$(b64 <"$WORK/codesign.err")
	printf 'F\t%s\t%s\t%s\t%s\t%s\n' "$path" "$link" "$is_script" "$info" "$ent"
	if [ "$is_script" = 0 ] && [ -r "$path" ]; then emit_evidence "$path"; fi
}

main() {
	WORK=$(mktemp -d)
	trap 'rm -f "$WORK/paths" "$WORK/path_dirs" "$WORK/symbols" "$WORK/codesign.err" "$WORK/whatis" "$WORK/tcc.err"; rmdir "$WORK"' EXIT
	# A sentinel keeps the symbols file non-empty, so awk's NR == FNR test always means "first file".
	{
		echo __lolbins_none__
		printf '%s\n' "$LOLBINS_SYMBOLS"
	} >"$WORK/symbols"
	list_path_dirs >"$WORK/path_dirs"

	collect_facts
	emit_fact path_dirs "$(paste -sd : "$WORK/path_dirs")"
	collect_tcc
	list_candidates | sort -u >"$WORK/paths"
	# whatis is the slowest step, so it runs while the per-file loop below does.
	emit_summaries "$WORK/paths" >"$WORK/whatis" &
	local summaries_pid=$!
	emit_stats "$WORK/paths"
	emit_hashes "$WORK/paths"
	local path
	while IFS= read -r path; do
		probe_file "$path"
	done <"$WORK/paths"
	emit_xpc_registrations "$WORK/paths"
	wait "$summaries_pid"
	cat "$WORK/whatis"
	printf 'E\tok\n'
}

main
