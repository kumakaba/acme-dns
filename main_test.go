package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestMainVersionFlag(t *testing.T) {
	args := []string{"acme-dns", "-version"}
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	exitCode := run(args, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}

	expected := "acme-dns"
	if !strings.Contains(stdout.String(), expected) {
		t.Errorf("Output %q does not contain %q", stdout.String(), expected)
	}
}

func TestMainConfigtestFlag(t *testing.T) {
	args := []string{"acme-dns", "-t", "-c", "config.cfg"}
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	exitCode := run(args, stdout, stderr)

	if exitCode != 0 {
		t.Error("Expected non-zero exit code for invalid flag")
	}

	if !strings.Contains(stdout.String(), "succeeded") {
		t.Errorf("Expected stdout succeeded message, got: %s", stdout.String())
	}
}

func TestMainNonexistConfigtestFlag(t *testing.T) {
	args := []string{"acme-dns", "-t", "-c", "nainai-nonexist-config.cfg"}
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	exitCode := run(args, stdout, stderr)

	if exitCode == 0 {
		t.Error("Expected non-zero exit code for invalid flag")
	}

	if !strings.Contains(stderr.String(), "configuration file not found") {
		t.Errorf("Expected configration error in stderr, got: %s", stderr.String())
	}
}

func TestMainInvalidFlag(t *testing.T) {
	args := []string{"acme-dns", "-unknown"}
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	exitCode := run(args, stdout, stderr)

	if exitCode == 0 {
		t.Error("Expected non-zero exit code for invalid flag")
	}

	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Errorf("Expected flag error in stderr, got: %s", stderr.String())
	}
}
