package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/bboycode/naabu2nmap/cmd"
)

func main() {
	inputPath := flag.String("input", "-", "Path to naabu jsonl file ('-' for stdin)")
	outputPath := flag.String("output", "-", "Path for generated nmap commands ('-' for stdout)")
	portsFlag := flag.String("ports", "", "Only include hosts with these comma-separated ports (e.g. 80,443)")
	hostsOutputPath := flag.String("hosts-output", "filtered_hosts.txt", "Path for matching hosts when -ports is set")
	useHost := flag.Bool("use-host", true, "Use host value as nmap target when available")
	baseArgs := flag.String("base-args", "-sV -sC -Pn", "Common nmap args prepended to each command")
	flag.Parse()

	selectedPorts, err := parsePorts(*portsFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(selectedPorts) > 0 && *hostsOutputPath == *outputPath {
		fmt.Fprintln(os.Stderr, "-hosts-output and -output must be different paths")
		os.Exit(1)
	}

	reader, closeReader, err := openInput(*inputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if closeReader != nil {
		defer closeReader()
	}

	targets, err := cmd.ParseNaabuJSONL(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
		os.Exit(1)
	}

	var commands []string
	if len(selectedPorts) > 0 {
		targets = cmd.FilterTargetsByPorts(targets, selectedPorts)
		if err := writeLines(*hostsOutputPath, cmd.TargetNames(targets, *useHost)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		commands = cmd.BuildFilteredNmapCommands(targets, *useHost, *baseArgs, *hostsOutputPath)
	} else {
		commands = cmd.BuildNmapCommands(targets, *useHost, *baseArgs)
	}

	if err := writeLines(*outputPath, commands); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if len(commands) == 0 && len(selectedPorts) == 0 {
		fmt.Fprintln(os.Stderr, "no valid hosts/ports found in input")
		os.Exit(1)
	}
}

func parsePorts(value string) (map[int]struct{}, error) {
	selected := make(map[int]struct{})
	if strings.TrimSpace(value) == "" {
		return selected, nil
	}
	for _, part := range strings.Split(value, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q: expected a number from 1 to 65535", part)
		}
		selected[port] = struct{}{}
	}
	return selected, nil
}

func writeLines(path string, lines []string) error {
	writer, closeWriter, err := openOutput(path)
	if err != nil {
		return err
	}
	bufferedWriter := bufio.NewWriter(writer)
	for _, line := range lines {
		if _, err := fmt.Fprintln(bufferedWriter, line); err != nil {
			if closeWriter != nil {
				closeWriter()
			}
			return fmt.Errorf("failed to write %q: %w", path, err)
		}
	}
	if err := bufferedWriter.Flush(); err != nil {
		if closeWriter != nil {
			closeWriter()
		}
		return fmt.Errorf("failed to flush %q: %w", path, err)
	}
	if closeWriter != nil {
		if err := closeWriter(); err != nil {
			return fmt.Errorf("failed to close %q: %w", path, err)
		}
	}
	return nil
}

func openInput(path string) (io.Reader, func() error, error) {
	if path == "-" {
		return os.Stdin, nil, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open input file %q: %w", path, err)
	}

	return file, file.Close, nil
}

func openOutput(path string) (io.Writer, func() error, error) {
	if path == "-" {
		return os.Stdout, nil, nil
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create output file %q: %w", path, err)
	}

	return file, file.Close, nil
}
