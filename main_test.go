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

	exitCode := run(args, stdout, stderr, true)

	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}

	expected := "acme-dns"
	if !strings.Contains(stdout.String(), expected) {
		t.Errorf("Output %q does not contain %q", stdout.String(), expected)
	}
}

func TestMainDefaultConfigtestFlag(t *testing.T) {
	args := []string{"acme-dns", "-t"}
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	exitCode := run(args, stdout, stderr, true)

	if exitCode != 0 {
		t.Error("Expected non-zero exit code for invalid flag")
	}

	if !strings.Contains(stdout.String(), "succeeded") {
		t.Errorf("Expected stdout succeeded message, got: %s", stdout.String())
	}

	if !strings.Contains(stdout.String(), "file: ./config.cfg") {
		t.Errorf("Expected stdout 'file: ./config.cfg', got: %s", stdout.String())
	}
}

func TestMainExistConfigtestFlag(t *testing.T) {
	args := []string{"acme-dns", "-t", "-c", "config.cfg"}
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	exitCode := run(args, stdout, stderr, true)

	if exitCode != 0 {
		t.Error("Expected non-zero exit code for invalid flag")
	}

	if !strings.Contains(stdout.String(), "succeeded") {
		t.Errorf("Expected stdout succeeded message, got: %s", stdout.String())
	}

	if !strings.Contains(stdout.String(), "file: config.cfg") {
		t.Errorf("Expected stdout 'file: config.cfg', got: %s", stdout.String())
	}
}

func TestMainEmptyConfigtestFlag(t *testing.T) {
	args := []string{"acme-dns", "-t", "-c", ""}
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	_ = run(args, stdout, stderr, true)

	if !strings.Contains(stdout.String(), "file:  failed") {
		t.Errorf("Expected stdout 'file:  failed', got: %s", stdout.String())
	}
}

func TestMainNonexistConfigtestFlag(t *testing.T) {
	args := []string{"acme-dns", "-t", "-c", "nainai-nonexist-config.cfg"}
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	exitCode := run(args, stdout, stderr, true)

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

	exitCode := run(args, stdout, stderr, true)

	if exitCode == 0 {
		t.Error("Expected non-zero exit code for invalid flag")
	}

	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Errorf("Expected flag error in stderr, got: %s", stderr.String())
	}
}

func TestMainDummyConfigtestFlag(t *testing.T) {
	args := []string{"acme-dns", "-c", "./pkg/acmedns/testdata/test_main_dummy_config.toml"}
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	exitCode := run(args, stdout, stderr, true)

	if exitCode != 0 {
		t.Errorf("Expected TestRun finish exitCode 0, but %d", exitCode)
	}

	if stdout.String() != "" {
		t.Errorf("Expected TestRun stdout is empty, but not")
	}

	if stderr.String() != "" {
		t.Errorf("Expected TestRun stderr is empty, but not")
	}
}
