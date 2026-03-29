//go:build ignore

// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	serviceDir, err := schemaDir()
	if err != nil {
		fail(err)
	}

	capnpPath, err := exec.LookPath("capnp")
	if err != nil {
		fail(errors.New("capnp compiler was not found on PATH"))
	}

	capnpcGoPath, err := findCapnpcGo()
	if err != nil {
		fail(err)
	}

	schemaPath := filepath.Join(serviceDir, "service.capnp")
	cmd := exec.Command(
		capnpPath,
		"compile",
		"--src-prefix="+serviceDir,
		"-I"+serviceDir,
		"-o",
		capnpcGoPath,
		schemaPath,
	)
	cmd.Dir = serviceDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fail(fmt.Errorf("failed to generate %s: %w", schemaPath, err))
	}
}

func schemaDir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("failed to locate generator source file")
	}
	return filepath.Dir(file), nil
}

func findCapnpcGo() (string, error) {
	if path, err := exec.LookPath("capnpc-go"); err == nil {
		return path, nil
	}

	exeName := "capnpc-go"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}

	for _, dir := range candidateBinDirs() {
		path := filepath.Join(dir, exeName)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}

	return "", errors.New("capnpc-go was not found on PATH, GOBIN, or GOPATH/bin")
}

func candidateBinDirs() []string {
	seen := map[string]struct{}{}
	dirs := []string{}
	add := func(dir string) {
		if dir == "" {
			return
		}
		if _, ok := seen[dir]; ok {
			return
		}
		seen[dir] = struct{}{}
		dirs = append(dirs, dir)
	}

	add(os.Getenv("GOBIN"))

	if gopath := os.Getenv("GOPATH"); gopath != "" {
		for _, root := range filepath.SplitList(gopath) {
			add(filepath.Join(root, "bin"))
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, "go", "bin"))
	}

	if out, err := exec.Command("go", "env", "GOBIN").Output(); err == nil {
		add(strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("go", "env", "GOPATH").Output(); err == nil {
		for _, root := range filepath.SplitList(strings.TrimSpace(string(out))) {
			add(filepath.Join(root, "bin"))
		}
	}

	return dirs
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "servicecapnp generator:", err)
	os.Exit(1)
}
