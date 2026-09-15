package tlsoffset

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"sort"
)

// Target represents a resolved candidate for SSL_write.
type Target struct {
	Path     string `json:"path"`
	BuildID  string `json:"build_id"`
	SSLWrite uint64 `json:"ssl_write_file_offset"`
}

// Candidate represents a potential SSL_write location.
type Candidate struct {
	VA      uint64
	FileOff uint64
	Score   int
}

// ScanELF analyzes a stripped executable to find SSL_write candidates.
func ScanELF(path string) ([]Candidate, string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open elf: %w", err)
	}
	defer func() { _ = f.Close() }()

	buildID := getBuildID(f)

	// 1. Try symbols first
	for _, get := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		syms, err := get()
		if err == nil {
			for _, s := range syms {
				if s.Name == "SSL_write" {
					return []Candidate{{VA: s.Value, FileOff: vaToFileOff(f, s.Value), Score: 100}}, buildID, nil
				}
			}
		}
	}

	// 2. Locate ssl_lib.cc string
	strVA, err := findString(f, "ssl_lib.cc")
	if err != nil {
		return nil, buildID, fmt.Errorf("find string: %w", err)
	}

	text := f.Section(".text")
	if text == nil {
		return nil, buildID, fmt.Errorf("no .text section")
	}
	code, err := text.Data()
	if err != nil {
		return nil, buildID, fmt.Errorf("read .text: %w", err)
	}

	// 3. Scan .text for xrefs to strVA
	var sites []uint64
	sites = append(sites, scanLEA(code, text.Addr, strVA)...)
	sites = append(sites, scanAbsolute(code, text.Addr, strVA)...)

	// 4. Find function starts
	funcStarts := make(map[uint64]int)
	for _, site := range sites {
		funcVA := findFunctionStart(code, text.Addr, site, 4096)
		if funcVA != 0 {
			funcStarts[funcVA]++
		}
	}

	var candidates []Candidate
	for va, score := range funcStarts {
		candidates = append(candidates, Candidate{
			VA:      va,
			FileOff: vaToFileOff(f, va),
			Score:   score,
		})
	}
	
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Score > candidates[j].Score
	})

	return candidates, buildID, nil
}

func scanLEA(code []byte, base, target uint64) []uint64 {
	var out []uint64
	for i := 0; i+7 <= len(code); i++ {
		rex := code[i]
		if rex != 0x48 && rex != 0x4c {
			continue
		}
		if code[i+1] != 0x8d {
			continue
		}
		modrm := code[i+2]
		if modrm&0xC7 != 0x05 {
			continue
		}
		disp := int32(binary.LittleEndian.Uint32(code[i+3 : i+7]))
		next := base + uint64(i) + 7
		if uint64(int64(next)+int64(disp)) == target {
			out = append(out, base+uint64(i))
		}
	}
	return out
}

func scanAbsolute(code []byte, base, target uint64) []uint64 {
	if target > 0xffffffff {
		return nil
	}
	var want [4]byte
	binary.LittleEndian.PutUint32(want[:], uint32(target))

	var out []uint64
	for i := 0; i+4 <= len(code); i++ {
		if code[i] != want[0] || code[i+1] != want[1] || code[i+2] != want[2] || code[i+3] != want[3] {
			continue
		}
		if classifyImmediate(code, i) {
			out = append(out, base+uint64(i))
		}
	}
	return out
}

func classifyImmediate(code []byte, i int) bool {
	if i >= 2 && i+8 <= len(code) && code[i+4] == 0 && code[i+5] == 0 && code[i+6] == 0 && code[i+7] == 0 {
		if rex := code[i-2]; (rex == 0x48 || rex == 0x49) && code[i-1] >= 0xb8 && code[i-1] <= 0xbf {
			return true
		}
	}
	if i >= 3 && (code[i-3] == 0x48 || code[i-3] == 0x49) && code[i-2] == 0xc7 && code[i-1]&0xf8 == 0xc0 {
		return true
	}
	if i >= 2 && code[i-2] == 0x41 && code[i-1] >= 0xb8 && code[i-1] <= 0xbf {
		return true
	}
	if i >= 1 && code[i-1] >= 0xb8 && code[i-1] <= 0xbf {
		return true
	}
	if i >= 1 && code[i-1] == 0x68 {
		return true
	}
	return false
}

func findFunctionStart(code []byte, base, site uint64, maxBack int) uint64 {
	off := int(site - base)
	limit := off - maxBack
	if limit < 0 { limit = 0 }
	for i := off; i >= limit+4; i-- {
		if code[i] == 0xf3 && code[i+1] == 0x0f && code[i+2] == 0x1e && code[i+3] == 0xfa {
			if i == 0 || code[i-1] == 0xcc || code[i-1] == 0x90 {
				return base + uint64(i)
			}
		}
	}
	for i := off; i > limit; i-- {
		if code[i] == 0xcc && code[i+1] != 0xcc && code[i+1] != 0x90 {
			return base + uint64(i+1)
		}
	}
	return 0
}

func findString(f *elf.File, needle string) (uint64, error) {
	for _, s := range f.Sections {
		if s.Type != elf.SHT_PROGBITS || s.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		idx := bytes.Index(data, []byte(needle))
		if idx < 0 {
			continue
		}
		start := idx
		for start > 0 && data[start-1] != 0 {
			start--
		}
		return s.Addr + uint64(start), nil
	}
	return 0, fmt.Errorf("string %q not found", needle)
}

func getBuildID(f *elf.File) string {
	sect := f.Section(".note.gnu.build-id")
	if sect == nil { return "" }
	data, _ := sect.Data()
	if len(data) < 16 { return "" }
	return fmt.Sprintf("%x", data[16:])
}

func vaToFileOff(f *elf.File, va uint64) uint64 {
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD && va >= prog.Vaddr && va < prog.Vaddr+prog.Filesz {
			return va - prog.Vaddr + prog.Off
		}
	}
	for _, sec := range f.Sections {
		if sec.Flags&elf.SHF_ALLOC != 0 && va >= sec.Addr && va < sec.Addr+sec.Size {
			return va - sec.Addr + sec.Offset
		}
	}
	return va
}
