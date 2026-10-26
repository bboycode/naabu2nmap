package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
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

func FilterTargetsByPorts(targets map[string]*target, selectedPorts map[int]struct{}) map[string]*target {
	filtered := make(map[string]*target)
	for key, original := range targets {
		matchedPorts := make(map[string]map[int]struct{})
		for protocol, ports := range original.ports {
			for port := range ports {
				if _, selected := selectedPorts[port]; !selected {
					continue
				}
				if matchedPorts[protocol] == nil {
					matchedPorts[protocol] = make(map[int]struct{})
				}
				matchedPorts[protocol][port] = struct{}{}
			}
		}
		if len(matchedPorts) > 0 {
			filtered[key] = &target{host: original.host, ip: original.ip, ports: matchedPorts}
		}
	}
	return filtered
}

func TargetNames(targets map[string]*target, useHost bool) []string {
	names := make(map[string]struct{})
	for _, t := range targets {
		if name := scanTargetName(t, useHost); name != "" {
			names[name] = struct{}{}
		}
	}

	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func BuildNmapCommands(targets map[string]*target, useHost bool, baseArgs string) []string {
	keys := sortedKeys(targets)
	commands := make([]string, 0, len(keys))

	for _, key := range keys {
		t := targets[key]
		targetName := scanTargetName(t, useHost)

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

			commands = append(commands, formatNmapCommand(baseArgs, protocol, ports, outputName, targetName))
		}
	}

	return commands
}

func BuildFilteredNmapCommands(targets map[string]*target, useHost bool, baseArgs string, hostsPath string) []string {
	portsByProtocol := make(map[string]map[int]struct{})
	for _, t := range targets {
		if scanTargetName(t, useHost) == "" {
			continue
		}
		for protocol, ports := range t.ports {
			if portsByProtocol[protocol] == nil {
				portsByProtocol[protocol] = make(map[int]struct{})
			}
			for port := range ports {
				portsByProtocol[protocol][port] = struct{}{}
			}
		}
	}

	outputName := sanitizeOutputName(strings.TrimSuffix(filepath.Base(hostsPath), filepath.Ext(hostsPath)))
	if outputName == "" {
		outputName = "filtered_hosts"
	}

	commands := make([]string, 0, len(portsByProtocol))
	for _, protocol := range sortedKeysFromPortMap(portsByProtocol) {
		ports := sortedPorts(portsByProtocol[protocol])
		if len(ports) == 0 {
			continue
		}
		commands = append(commands, formatNmapCommand(baseArgs, protocol, ports, outputName+"_"+protocol, "-iL", shellQuote(hostsPath)))
	}
	return commands
}

func formatNmapCommand(baseArgs string, protocol string, ports []string, outputName string, targetArgs ...string) string {
	commandParts := []string{"nmap"}
	if args := strings.TrimSpace(baseArgs); args != "" {
		commandParts = append(commandParts, args)
	}
	if scanFlag := protocolScanFlag(protocol); scanFlag != "" {
		commandParts = append(commandParts, scanFlag)
	}
	commandParts = append(commandParts, "-p", strings.Join(ports, ","), "-oA", outputName)
	commandParts = append(commandParts, targetArgs...)
	return strings.Join(commandParts, " ")
}

func shellQuote(value string) string {
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("/._-", character) {
			continue
		}
		return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
	}
	return value
}

func scanTargetName(t *target, useHost bool) string {
	if useHost && strings.TrimSpace(t.host) != "" {
		return t.host
	}
	return t.ip
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
