package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bboycode/naabu2nmap/cmd"
)

func main() {
	inputPath := flag.String("input", "-", "Path to naabu jsonl file ('-' for stdin)")
	outputPath := flag.String("output", "-", "Path for generated nmap commands ('-' for stdout)")
	useHost := flag.Bool("use-host", true, "Use host value as nmap target when available")
	baseArgs := flag.String("base-args", "-sV -sC -Pn", "Common nmap args prepended to each command")
	flag.Parse()

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

	commands := cmd.BuildNmapCommands(targets, *useHost, *baseArgs)

	writer, closeWriter, err := openOutput(*outputPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if closeWriter != nil {
		defer closeWriter()
	}

	bufferedWriter := bufio.NewWriter(writer)
	for _, command := range commands {
		if _, err := fmt.Fprintln(bufferedWriter, command); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write output: %v\n", err)
			os.Exit(1)
		}
	}

	if err := bufferedWriter.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to flush output: %v\n", err)
		os.Exit(1)
	}

	if len(commands) == 0 {
		fmt.Fprintln(os.Stderr, "no valid hosts/ports found in input")
		os.Exit(1)
	}

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
