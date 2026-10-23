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
- `-use-host` (default: `true`)
  - Use JSON `host` value as scan target when available
  - If `false`, scans by IP instead
- `-base-args` (default: `-sV -sC -Pn`)
  - Base args prepended to each generated command

## Examples

Generate commands to terminal:

```bash
go run . -input test.jsonl
```

Save commands to file:

```bash
go run . -input test_two.jsonl -output outputs/commands.txt
```

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

Example output:

```bash
nmap -sV -sC -Pn -p 80,443,8080 -oA api_alpha_local api.alpha.local
nmap -sV -sC -Pn -sU -p 53,123 -oA api_alpha_local api.alpha.local
```

