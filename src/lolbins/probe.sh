#!/bin/bash
# Guest-side collector, run as /bin/bash -s on the target. Read-only: it never writes outside
# its own temp directory. Inputs are newline-separated variables set by the host preamble:
#   LOLBINS_SCAN_DIRS    directories whose top-level executables are inventoried
#   LOLBINS_EXTRA_PATHS  extra paths to probe (catalog entries outside the scan dirs)
# Output is one tab-separated record per line; lolbins/probe.py documents and parses it.
set -euo pipefail

: "${LOLBINS_SCAN_DIRS?set LOLBINS_SCAN_DIRS to newline-separated directories}"
: "${LOLBINS_EXTRA_PATHS:=}"

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

list_candidates() {
	local dir
	while IFS= read -r dir; do
		[ -n "$dir" ] && [ -d "$dir" ] || continue
		find "$dir" -maxdepth 1 \( -type f -o -type l \) -perm +111 -print 2>/dev/null || true
	done <<<"$LOLBINS_SCAN_DIRS"
	printf '%s\n' "$LOLBINS_EXTRA_PATHS"
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
	if [ ! -e "$path" ] && [ ! -L "$path" ]; then
		printf 'M\t%s\n' "$path"
		return
	fi
	if [ -L "$path" ]; then link=$(readlink "$path"); fi
	if [ -r "$path" ]; then
		IFS= read -r -n 2 magic 2>/dev/null <"$path" || true
	fi
	if [ "$magic" = "#!" ]; then is_script=1; fi
	ent=$(codesign -dv --verbose=2 --entitlements - --xml "$path" 2>"$WORK/codesign.err" | b64) || true
	info=$(b64 <"$WORK/codesign.err")
	printf 'F\t%s\t%s\t%s\t%s\t%s\n' "$path" "$link" "$is_script" "$info" "$ent"
}

main() {
	WORK=$(mktemp -d)
	trap 'rm -f "$WORK/paths" "$WORK/codesign.err" "$WORK/whatis" "$WORK/tcc.err"; rmdir "$WORK"' EXIT

	collect_facts
	collect_tcc
	list_candidates | { grep -v '^$' || true; } | sort -u >"$WORK/paths"
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
