package main

import (
	"os"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--version"}, out, os.Stderr); code != 0 {
		t.Fatalf("--version 退出码 %d", code)
	}
	data, _ := os.ReadFile(out.Name())
	if !strings.Contains(string(data), "0.0.0-dev") {
		t.Fatalf("输出应当含默认版本，得到 %q", data)
	}
	if code := run([]string{"--help"}, out, out); code != 0 {
		t.Fatalf("--help 应当退出码 0，得到 %d", code)
	}
	if code := run([]string{"--bogus"}, out, out); code != 2 {
		t.Fatalf("未知 flag 应当退出码 2，得到 %d", code)
	}
	if code := run(nil, out, out); code != 1 {
		t.Fatalf("没有参数应当退出码 1，得到 %d", code)
	}
}
