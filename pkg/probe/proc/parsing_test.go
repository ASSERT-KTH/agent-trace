package proc

import "testing"

// makeArgSlots encodes values into the fixed-width slot layout the BPF
// program writes (argSlot bytes per entry, NUL-terminated), matching what
// commandLine expects to parse. Unused slots stay zeroed.
func makeArgSlots(values ...string) []int8 {
	buf := make([]int8, argSlot*MaxArgsForTest)
	for i, v := range values {
		if i >= MaxArgsForTest {
			break
		}
		for j := 0; j < len(v) && j < argSlot-1; j++ {
			buf[i*argSlot+j] = int8(v[j])
		}
	}
	return buf
}

// MaxArgsForTest mirrors MAX_ARGS in proc.bpf.c. Kept separate (rather than
// exported from the BPF-generated code) since the slot count is a C-side
// constant with no corresponding Go symbol.
const MaxArgsForTest = 12

func TestCommandLine_UsesResolvedFilenameNotArgv0(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		argv     []string
		nargs    uint32
		want     string
	}{
		{
			name:     "spoofed argv0 is dropped in favor of the resolved path",
			filename: "/bin/echo",
			argv:     []string{"totally-not-echo", "hello", "world"},
			nargs:    3,
			want:     "/bin/echo hello world",
		},
		{
			name:     "matching argv0 and filename (the common, honest case)",
			filename: "/usr/bin/wc",
			argv:     []string{"wc", "-l", "/tmp/x/file2.txt"},
			nargs:    3,
			want:     "/usr/bin/wc -l /tmp/x/file2.txt",
		},
		{
			name:     "no arguments beyond argv0",
			filename: "/usr/bin/ls",
			argv:     []string{"ls"},
			nargs:    1,
			want:     "/usr/bin/ls",
		},
		{
			name:     "filename capture failed, falls back to argv0",
			filename: "",
			argv:     []string{"ls", "-la"},
			nargs:    2,
			want:     "ls -la",
		},
		{
			name:     "filename capture failed and no argv at all",
			filename: "",
			argv:     nil,
			nargs:    0,
			want:     "",
		},
		{
			name:     "nargs truncates trailing garbage slots",
			filename: "/usr/bin/git",
			argv:     []string{"git", "commit", "-m", "leftover-from-a-previous-event"},
			nargs:    3,
			want:     "/usr/bin/git commit -m",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := commandLine(tc.filename, makeArgSlots(tc.argv...), tc.nargs)
			if got != tc.want {
				t.Errorf("commandLine(%q, %v, %d) = %q, want %q",
					tc.filename, tc.argv, tc.nargs, got, tc.want)
			}
		})
	}
}
