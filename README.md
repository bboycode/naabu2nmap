# naabu2nmap

Convert `naabu` JSONL output into ready-to-run `nmap` commands.

This tool reads line-delimited JSON (`jsonl`) from Naabu, groups ports by target and protocol, and prints one or more optimized `nmap` commands.

## Features

- Reads Naabu JSONL from a file or `stdin`
- Groups and deduplicates ports per host/IP
- Generates separate commands for TCP and UDP ports
- Adds `-oA` automatically for each command
- Creates safe `-oA` output names:
  - Use hostname when available
  - Else use IP with `.` replaced by `_`
  - Hostnames also replace `.` with `_`
  - Unsafe filename characters are normalized to `_`
- Writes output to `stdout` or a file
- Filters targets by one or more selected ports and writes matching hosts to a file
- Optionally prints a summary of discovered ports and hosts after generating commands

## Build

```bash
go build -o naabu2nmap .
```

## Usage

```bash
./naabu2nmap -input <naabu.jsonl> [flags]
```

Or with `go run`:

```bash
go run . -input <naabu.jsonl> [flags]
```

## Flags

- `-input` (default: `-`)
  - Input Naabu JSONL path
  - Use `-` to read from `stdin`
- `-output` (default: `-`)
  - Output path for generated commands
  - Use `-` to write to `stdout`
- `-ports` (default: empty)
  - Comma-separated port numbers to filter by, such as `80,443`
  - Only matching hosts and selected ports appear in the results
- `-hosts-output` (default: `filtered_hosts.txt`)
  - Path for matching hosts when `-ports` is set
  - Each host appears once, and filtered `nmap` commands read this file with `-iL`
- `-use-host` (default: `true`)
  - Use JSON `host` value as scan target when available
  - If `false`, scans by IP instead
- `-base-args` (default: `-sV -sC -Pn`)
  - Base args prepended to each generated command
- `-summary` (default: `false`)
  - Print only the Naabu port and host summary to `stdout`

## Examples

Generate commands to terminal:

```bash
go run . -input test.jsonl
```

Save commands to file:

```bash
go run . -input test_two.jsonl -output outputs/commands.txt
```

Filter for ports 80 and 443, save matching hosts and their commands:

```bash
go run . -input test_two.jsonl -ports 80,443 -hosts-output outputs/web_hosts.txt -output outputs/web_commands.txt
```

The host file contains one hostname (or IP for IP-only records) per line. The command file uses `-iL outputs/web_hosts.txt` and scans only the selected ports found in the input. Nmap scans each listed host for every port in its command. TCP and UDP get separate commands and `-oA` names. If no hosts match, both files are empty.

Read from stdin:

```bash
cat test_two.jsonl | go run . -output outputs/from_stdin.txt
```

Scan by IP instead of hostname:

```bash
go run . -input test_two.jsonl -use-host=false
```

Custom base args:

```bash
go run . -input test_two.jsonl -base-args "-sC -sV -Pn --reason"
```

## Input format

Expected Naabu JSONL fields (per line):

```json
{"host":"example.com","ip":"93.184.216.34","timestamp":"2026-10-23T13:00:52Z","port":443,"protocol":"tcp","tls":true}
```

Only valid lines with a positive `port` and a non-empty `host` or `ip` are used.

## Output behavior

- TCP ports: no explicit scan type flag is added
- UDP ports: `-sU` is added
- Every generated command includes `-oA <name>`
- With a port filter, commands use `-iL <hosts-output>` instead of individual targets

Example output:

```bash
nmap -sV -sC -Pn -p 80,443,8080 -oA api_alpha_local api.alpha.local
nmap -sV -sC -Pn -sU -p 53,123 -oA api_alpha_local api.alpha.local
```

Filtered output example:

```bash
nmap -sV -sC -Pn -p 80,443 -oA web_hosts_tcp -iL outputs/web_hosts.txt
```

## Summary

Pass `-summary` to print only a summary of the Naabu findings to `stdout`. No Nmap commands or hosts files are generated in this mode; `-output` and `-hosts-output` are ignored. Add `-ports` to summarize only matching hosts and selected ports.

```bash
go run . -input test.jsonl -summary
```

```text
Summary:
  Hosts with open ports: 3
  Distinct open ports: 2
  Open host-port pairs: 4
  Hosts by port:
    80 : 3 hosts
    161 : 1 host
```

Each port number is counted once per host, even if it appears in both TCP and UDP findings or in repeated JSONL rows.

