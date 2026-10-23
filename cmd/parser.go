package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

func ParseNaabuJSONL(reader io.Reader) (map[string]*target, error) {
	scanner := bufio.NewScanner(reader)
	targets := make(map[string]*target)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var row NaabuResult
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("invalid json on line %d: %w", lineNumber, err)
		}

		if row.Port <= 0 {
			continue
		}

		row.Protocol = strings.ToLower(strings.TrimSpace(row.Protocol))
		if row.Protocol == "" {
			row.Protocol = "tcp"
		}

		key := buildTargetKey(row.Host, row.IP)
		if key == "" {
			continue
		}

		t, exists := targets[key]
		if !exists {
			t = &target{
				host:  row.Host,
				ip:    row.IP,
				ports: make(map[string]map[int]struct{}),
			}
			targets[key] = t
		}

		if _, ok := t.ports[row.Protocol]; !ok {
			t.ports[row.Protocol] = make(map[int]struct{})
		}
		t.ports[row.Protocol][row.Port] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading input: %w", err)
	}

	return targets, nil
}

func BuildNmapCommands(targets map[string]*target, useHost bool, baseArgs string) []string {
	keys := sortedKeys(targets)
	commands := make([]string, 0, len(keys))

	for _, key := range keys {
		t := targets[key]
		targetName := t.ip
		if useHost && strings.TrimSpace(t.host) != "" {
			targetName = t.host
		}

		outputName := buildOutputName(t)
		if outputName == "" {
			continue
		}

		if targetName == "" {
			continue
		}

		for _, protocol := range sortedKeysFromPortMap(t.ports) {
			ports := sortedPorts(t.ports[protocol])
			if len(ports) == 0 {
				continue
			}

			joinedPorts := strings.Join(ports, ",")
			args := strings.TrimSpace(baseArgs)
			scanFlag := protocolScanFlag(protocol)
			commandParts := []string{"nmap"}
			if args != "" {
				commandParts = append(commandParts, args)
			}
			if scanFlag != "" {
				commandParts = append(commandParts, scanFlag)
			}
			commandParts = append(commandParts, "-p", joinedPorts, "-oA", outputName, targetName)

			command := strings.Join(commandParts, " ")
			commands = append(commands, command)
		}
	}

	return commands
}

func buildOutputName(t *target) string {
	host := strings.TrimSpace(t.host)
	if host != "" {
		host = strings.ReplaceAll(host, ".", "_")
		host = sanitizeOutputName(host)
		if host != "" {
			return host
		}
	}

	ip := strings.TrimSpace(t.ip)
	ip = strings.ReplaceAll(ip, ".", "_")
	ip = sanitizeOutputName(ip)
	if ip != "" {
		return ip
	}

	return "scan_target"
}

func sanitizeOutputName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			return r
		}
		return '_'
	}, value)

	clean = strings.Trim(clean, "._-")
	for strings.Contains(clean, "__") {
		clean = strings.ReplaceAll(clean, "__", "_")
	}

	return clean
}

func protocolScanFlag(protocol string) string {
	switch protocol {
	case "udp":
		return "-sU"
	default:
		return ""
	}
}

func buildTargetKey(host string, ip string) string {
	host = strings.TrimSpace(host)
	ip = strings.TrimSpace(ip)

	if host != "" {
		return "host:" + host
	}
	if ip != "" {
		return "ip:" + ip
	}
	return ""
}

func sortedKeys(targets map[string]*target) []string {
	keys := make([]string, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysFromPortMap(ports map[string]map[int]struct{}) []string {
	keys := make([]string, 0, len(ports))
	for key := range ports {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedPorts(portSet map[int]struct{}) []string {
	ports := make([]int, 0, len(portSet))
	for port := range portSet {
		ports = append(ports, port)
	}
	sort.Ints(ports)

	out := make([]string, 0, len(ports))
	for _, port := range ports {
		out = append(out, strconv.Itoa(port))
	}
	return out
}
