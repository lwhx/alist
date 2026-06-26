package local_test

import (
	"bytes"
	"os"
	"testing"

	"yourmodule/drivers/local"
)

func TestResizeImageToBufferWithFFmpegGo_ShellInjection(t *testing.T) {
	// Create a temporary valid image file for testing
	tmpfile, err := os.CreateTemp("", "test-*.png")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	// Write minimal PNG header to make it a valid image file
	tmpfile.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})

	payloads := []string{
		// Valid input (baseline)
		tmpfile.Name(),
		// Shell metacharacters that should be rejected by sanitizeFilePath
		"; rm -rf /",
		"$(whoami)",
		"`id`",
		// Path traversal attempt
		"/tmp/../etc/passwd",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			// This will call the actual production function
			buffer, err := local.ResizeImageToBufferWithFFmpegGo(payload, 100, "png_pipe")
			
			// The security property: either the input is rejected by sanitizeFilePath
			// (returns error) or if it passes sanitization, it should not cause
			// command injection (ffmpeg execution should succeed with valid input)
			
			if payload == tmpfile.Name() {
				// Valid input should succeed
				if err != nil {
					t.Errorf("Valid input failed: %v", err)
				}
				if buffer == nil || buffer.Len() == 0 {
					t.Error("Valid input should produce non-empty buffer")
				}
			} else {
				// Malicious inputs should be rejected by sanitizeFilePath
				if err == nil {
					t.Error("Shell metacharacters should be rejected by sanitizeFilePath")
				}
				// Check error message indicates path validation failed
				if err != nil && err.Error()[:20] != "invalid input file path" {
					t.Errorf("Expected path validation error, got: %v", err)
				}
			}
		})
	}
}