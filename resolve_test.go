package main

import (
	"context"
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"
)

type stubMLClient struct {
	info    MLInfo
	resolve MLResolveResponse
	share   MLShareResponse
}

func (s stubMLClient) Info(context.Context) (MLInfo, error) {
	return s.info, nil
}

func (s stubMLClient) Resolve(context.Context, ProgramBundle, int) (MLResolveResponse, error) {
	return s.resolve, nil
}

func (s stubMLClient) Share(context.Context, ProgramBundle) (MLShareResponse, error) {
	return s.share, nil
}

func newTestDB(t *testing.T, name string) *bbolt.DB {
	t.Helper()
	db, err := OpenDatabase(filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
	})
	return db
}

func TestResolveProgramUsesCandidateFilteredExactMatchAndApproxFallback(t *testing.T) {
	dbOther := newTestDB(t, "other.db")
	dbMatch := newTestDB(t, "match.db")

	section := &SectionHash{Size: 0x30, Paddr: 0x4000, Digest: []byte{0xaa, 0xbb}}
	sectionKey := SectionHashToKey(section, "elf", "linux")
	if err := DbSetHintsMeta(dbOther, sectionKey, "psk", ".text", "bin-other", []*Hint{{Bits: 64, Offset: 0x10}}); err != nil {
		t.Fatal(err)
	}
	if err := DbSetHintsMeta(dbMatch, sectionKey, "psk", ".text", "bin-match", []*Hint{{Bits: 64, Offset: 0x20}}); err != nil {
		t.Fatal(err)
	}

	sig := &Signature{Arch: "x86", Bits: 64, Length: 16, Digest: []byte{0x01, 0x02}}
	sigKey := SignatureToKey(sig)
	if err := DbSetSymbolMeta(dbOther, sigKey, "psk", "bin-other", &Symbol{Name: "sym.bad"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := DbSetSymbolMeta(dbMatch, sigKey, "psk", "bin-match", &Symbol{Name: "sym.good", Signature: "int good()", Callconv: "sysv", Bits: 64}, 0); err != nil {
		t.Fatal(err)
	}

	server := &Server{
		auths: map[string]bool{"psk": true},
		search: map[string][]*bbolt.DB{
			GENERIC_DB: {dbOther, dbMatch},
		},
		shared: map[string]*bbolt.DB{},
		ml: stubMLClient{
			resolve: MLResolveResponse{
				CandidateBinaryIDs: []string{"bin-match"},
				ModelVersion:       "hash-embed-v1",
				IndexVersion:       "flat-v1",
				Symbols: []SymbolMatchRecord{
					{
						Addr:            0x5000,
						Symbol:          SymbolRecord{Name: "sym.approx", Signature: "void approx()", Bits: 64},
						Confidence:      0.77,
						Exact:           false,
						MatchedBinaryID: "bin-match",
						MatchedBy:       "keenhash_sem",
					},
				},
			},
		},
		mlTopK: 5,
	}

	result := server.ResolveProgram("psk", ProgramBundle{
		BinaryType: "elf",
		OS:         "linux",
		Arch:       "x86",
		Bits:       64,
		Sections: []SectionRecord{
			{Name: ".text", Size: 0x30, Paddr: 0x4000, Digest: []byte{0xaa, 0xbb}},
		},
		Functions: []FunctionRecord{
			{Addr: 0x4020, Bits: 64, Arch: "x86", Length: 16, Digest: []byte{0x01, 0x02}},
			{Addr: 0x5000, Bits: 64, Arch: "x86"},
		},
	})

	if len(result.CandidateBinaryIDs) != 1 || result.CandidateBinaryIDs[0] != "bin-match" {
		t.Fatalf("unexpected candidates: %#v", result.CandidateBinaryIDs)
	}
	if len(result.Hints) != 1 || result.Hints[0].Offset != 0x4020 || result.Hints[0].MatchedBinaryID != "bin-match" {
		t.Fatalf("unexpected hints: %#v", result.Hints)
	}
	if len(result.Symbols) != 2 {
		t.Fatalf("unexpected symbol count: %#v", result.Symbols)
	}
	if !result.Symbols[0].Exact || result.Symbols[0].Symbol.Name != "sym.good" {
		t.Fatalf("exact symbol mismatch: %#v", result.Symbols[0])
	}
	if result.Symbols[1].Exact || result.Symbols[1].MatchedBy != "keenhash_sem" {
		t.Fatalf("approx symbol mismatch: %#v", result.Symbols[1])
	}
}

func TestShareProgramStoresExactDataWithBinaryID(t *testing.T) {
	shareDB := newTestDB(t, "share.db")
	server := &Server{
		auths:  map[string]bool{"psk": true},
		search: map[string][]*bbolt.DB{GENERIC_DB: {shareDB}},
		shared: map[string]*bbolt.DB{"psk": shareDB},
		ml: stubMLClient{
			share: MLShareResponse{
				CandidateCount: 3,
				ModelVersion:   "hash-embed-v1",
				IndexVersion:   "flat-v1",
			},
		},
	}

	bundle := ProgramBundle{
		BinaryType: "elf",
		OS:         "linux",
		Arch:       "x86",
		Bits:       64,
		Sections: []SectionRecord{
			{Name: ".text", Size: 0x40, Paddr: 0x1000, Digest: []byte{0xde, 0xad}},
		},
		Functions: []FunctionRecord{
			{
				Addr:          0x1010,
				Size:          16,
				Bits:          64,
				Arch:          "x86",
				Length:        16,
				Digest:        []byte{0xca, 0xfe},
				SectionName:   ".text",
				SectionPaddr:  0x1000,
				SectionOffset: 0x10,
				Name:          "sym.main",
				Signature:     "int main()",
				Callconv:      "sysv",
			},
		},
	}

	result := server.ShareProgram("psk", bundle)
	if result.BinaryID == "" {
		t.Fatal("share result binary id is empty")
	}
	if result.CandidateCount != 3 {
		t.Fatalf("unexpected candidate count: %d", result.CandidateCount)
	}

	normalized := normalizeProgramBundle(bundle)
	sectionMeta, err := DbGetHintsMeta(shareDB, SectionHashToKey(&SectionHash{
		Size:   normalized.Sections[0].Size,
		Paddr:  normalized.Sections[0].Paddr,
		Digest: normalized.Sections[0].Digest,
	}, normalized.BinaryType, normalized.OS))
	if err != nil {
		t.Fatal(err)
	}
	if sectionMeta == nil || sectionMeta.BinaryID != result.BinaryID || len(sectionMeta.Hints) != 1 || sectionMeta.Hints[0].Offset != 0x10 {
		t.Fatalf("unexpected section meta: %#v", sectionMeta)
	}

	sig := functionSignature(normalized, normalized.Functions[0])
	symbolMeta, err := DbGetSymbolMeta(shareDB, SignatureToKey(sig))
	if err != nil {
		t.Fatal(err)
	}
	if symbolMeta == nil || symbolMeta.BinaryID != result.BinaryID || symbolMeta.Symbol == nil || symbolMeta.Symbol.Name != "sym.main" {
		t.Fatalf("unexpected symbol meta: %#v", symbolMeta)
	}

	locationMeta, err := DbGetLocationSymbolMeta(shareDB, FunctionLocationToKey(result.BinaryID, normalized.Functions[0].SectionName, normalized.Functions[0].SectionPaddr, normalized.Functions[0].SectionOffset))
	if err != nil {
		t.Fatal(err)
	}
	if locationMeta == nil || locationMeta.Symbol == nil || locationMeta.Symbol.Name != "sym.main" {
		t.Fatalf("unexpected location symbol meta: %#v", locationMeta)
	}
	if locationMeta.Size != 16 {
		t.Fatalf("unexpected location symbol size: %#v", locationMeta)
	}
}

func TestShareProgramPreservesVASectionOffsets(t *testing.T) {
	shareDB := newTestDB(t, "share-va.db")
	server := &Server{
		auths:  map[string]bool{"psk": true},
		search: map[string][]*bbolt.DB{GENERIC_DB: {shareDB}},
		shared: map[string]*bbolt.DB{"psk": shareDB},
		ml:     stubMLClient{},
	}

	bundle := ProgramBundle{
		BinaryType: "elf",
		OS:         "linux",
		Arch:       "x86",
		Bits:       64,
		Sections: []SectionRecord{
			{Name: ".text", Size: 0x40, Paddr: 0x1000, Digest: []byte{0xde, 0xad}},
		},
		Functions: []FunctionRecord{
			{
				Addr:          0x401010,
				Size:          16,
				Bits:          64,
				Arch:          "x86",
				Length:        16,
				Digest:        []byte{0xca, 0xfe},
				SectionName:   ".text",
				SectionPaddr:  0x1000,
				SectionOffset: 0x10,
				Name:          "sym.main",
			},
		},
	}

	server.ShareProgram("psk", bundle)
	normalized := normalizeProgramBundle(bundle)
	sectionMeta, err := DbGetHintsMeta(shareDB, SectionHashToKey(&SectionHash{
		Size:   normalized.Sections[0].Size,
		Paddr:  normalized.Sections[0].Paddr,
		Digest: normalized.Sections[0].Digest,
	}, normalized.BinaryType, normalized.OS))
	if err != nil {
		t.Fatal(err)
	}
	if sectionMeta == nil || len(sectionMeta.Hints) != 1 || sectionMeta.Hints[0].Offset != 0x10 {
		t.Fatalf("unexpected section meta: %#v", sectionMeta)
	}
}

func TestResolveProgramPrefersExactLocationOverAmbiguousSignature(t *testing.T) {
	db := newTestDB(t, "location.db")
	server := &Server{
		auths:  map[string]bool{"psk": true},
		search: map[string][]*bbolt.DB{GENERIC_DB: {db}},
		shared: map[string]*bbolt.DB{"psk": db},
		ml:     stubMLClient{},
	}

	bundle := normalizeProgramBundle(ProgramBundle{
		BinaryType: "elf",
		OS:         "linux",
		Arch:       "x86",
		Bits:       64,
		Sections: []SectionRecord{
			{Name: ".text", Size: 0x80, Paddr: 0x1000, Digest: []byte{0xaa, 0xbb}},
		},
		Functions: []FunctionRecord{
			{
				Addr:          0x1010,
				Size:          16,
				Bits:          64,
				Arch:          "x86",
				Length:        16,
				Digest:        []byte{0xca, 0xfe},
				SectionName:   ".text",
				SectionPaddr:  0x1000,
				SectionOffset: 0x10,
				Name:          "sym.real_name",
			},
		},
	})
	share := server.ShareProgram("psk", bundle)
	if share.BinaryID == "" {
		t.Fatal("expected binary id")
	}

	sig := functionSignature(bundle, bundle.Functions[0])
	if err := DbSetSymbolMeta(db, SignatureToKey(sig), "psk", share.BinaryID, &Symbol{Name: "sym.wrong_name"}, 0); err != nil {
		t.Fatal(err)
	}

	result := server.ResolveProgram("psk", ProgramBundle{
		BinaryType: "elf",
		OS:         "linux",
		Arch:       "x86",
		Bits:       64,
		Sections: []SectionRecord{
			{Name: ".text", Size: 0x80, Paddr: 0x1000, Digest: []byte{0xaa, 0xbb}},
		},
		Functions: []FunctionRecord{
			{
				Addr:          0x401010,
				Bits:          64,
				Arch:          "x86",
				Length:        16,
				Digest:        []byte{0xca, 0xfe},
				SectionName:   ".text",
				SectionPaddr:  0x1000,
				SectionOffset: 0x10,
			},
		},
	})

	if len(result.Symbols) != 1 {
		t.Fatalf("unexpected symbols: %#v", result.Symbols)
	}
	if got := result.Symbols[0].Symbol.Name; got != "sym.real_name" {
		t.Fatalf("expected location symbol, got %q", got)
	}
	if got := result.Symbols[0].MatchedBy; got != "exact_location" {
		t.Fatalf("expected exact_location match, got %q", got)
	}
	if got := result.Symbols[0].Offset; got != 0x1010 {
		t.Fatalf("expected exact offset, got %#x", got)
	}
	if got := result.Symbols[0].Size; got != 16 {
		t.Fatalf("expected exact size, got %d", got)
	}
}

func TestResolveProgramReturnsExtraExactLocationSymbolsForHintedOffsets(t *testing.T) {
	db := newTestDB(t, "hinted-location.db")
	server := &Server{
		auths:  map[string]bool{"psk": true},
		search: map[string][]*bbolt.DB{GENERIC_DB: {db}},
		shared: map[string]*bbolt.DB{"psk": db},
		ml:     stubMLClient{},
	}

	bundle := normalizeProgramBundle(ProgramBundle{
		BinaryType: "elf",
		OS:         "linux",
		Arch:       "x86",
		Bits:       64,
		Sections: []SectionRecord{
			{Name: ".text", Size: 0x80, Paddr: 0x1000, Digest: []byte{0xaa, 0xbb}},
		},
		Functions: []FunctionRecord{
			{
				Addr:          0x1010,
				Size:          16,
				Bits:          64,
				Arch:          "x86",
				Length:        16,
				Digest:        []byte{0xca, 0xfe},
				SectionName:   ".text",
				SectionPaddr:  0x1000,
				SectionOffset: 0x10,
				Name:          "sym.main",
			},
			{
				Addr:          0x1020,
				Size:          8,
				Bits:          64,
				Arch:          "x86",
				Length:        8,
				Digest:        []byte{0xca, 0xff},
				SectionName:   ".text",
				SectionPaddr:  0x1000,
				SectionOffset: 0x20,
				Name:          "sym.cold",
			},
		},
	})
	share := server.ShareProgram("psk", bundle)
	if share.BinaryID == "" {
		t.Fatal("expected binary id")
	}

	result := server.ResolveProgram("psk", ProgramBundle{
		BinaryType: "elf",
		OS:         "linux",
		Arch:       "x86",
		Bits:       64,
		Sections: []SectionRecord{
			{Name: ".text", Size: 0x80, Paddr: 0x1000, Digest: []byte{0xaa, 0xbb}},
		},
		Functions: []FunctionRecord{
			{
				Addr:          0x401010,
				Bits:          64,
				Arch:          "x86",
				Length:        16,
				Digest:        []byte{0xca, 0xfe},
				SectionName:   ".text",
				SectionPaddr:  0x1000,
				SectionOffset: 0x10,
			},
		},
	})

	if len(result.Symbols) != 2 {
		t.Fatalf("unexpected symbols: %#v", result.Symbols)
	}
	if got := result.Symbols[1].Symbol.Name; got != "sym.cold" {
		t.Fatalf("expected hinted exact location symbol, got %q", got)
	}
	if got := result.Symbols[1].MatchedBy; got != "exact_hint_location" {
		t.Fatalf("expected exact_hint_location match, got %q", got)
	}
	if got := result.Symbols[1].Offset; got != 0x1020 {
		t.Fatalf("expected hinted offset, got %#x", got)
	}
	if got := result.Symbols[1].Size; got != 8 {
		t.Fatalf("expected hinted size, got %d", got)
	}
}
