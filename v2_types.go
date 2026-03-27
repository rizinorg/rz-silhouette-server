// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

const (
	PROTOBUF_VERSION = uint32(1)
	CAPNP_VERSION    = uint32(2)
	MAX_VERSION      = CAPNP_VERSION
)

type SymbolRecord struct {
	Name      string `json:"name,omitempty"`
	Signature string `json:"signature,omitempty"`
	Callconv  string `json:"callconv,omitempty"`
	Bits      uint32 `json:"bits,omitempty"`
}

type SectionRecord struct {
	Name   string `json:"name,omitempty"`
	Size   uint32 `json:"size"`
	Paddr  uint64 `json:"paddr"`
	Digest []byte `json:"digest,omitempty"`
}

type FunctionRecord struct {
	Addr             uint64   `json:"addr"`
	Size             uint32   `json:"size"`
	Bits             uint32   `json:"bits,omitempty"`
	Arch             string   `json:"arch,omitempty"`
	Length           uint32   `json:"length,omitempty"`
	Digest           []byte   `json:"digest,omitempty"`
	SectionName      string   `json:"section_name,omitempty"`
	SectionPaddr     uint64   `json:"section_paddr"`
	SectionOffset    uint64   `json:"section_offset"`
	Loc              uint32   `json:"loc,omitempty"`
	Nos              uint32   `json:"nos,omitempty"`
	Pseudocode       string   `json:"pseudocode,omitempty"`
	PseudocodeSource string   `json:"pseudocode_source,omitempty"`
	Calls            []uint64 `json:"calls,omitempty"`
	Name             string   `json:"name,omitempty"`
	Signature        string   `json:"signature,omitempty"`
	Callconv         string   `json:"callconv,omitempty"`
}

type ProgramBundle struct {
	BinaryType string           `json:"binary_type,omitempty"`
	OS         string           `json:"os,omitempty"`
	Arch       string           `json:"arch,omitempty"`
	Bits       uint32           `json:"bits,omitempty"`
	BinaryID   string           `json:"binary_id,omitempty"`
	Sections   []SectionRecord  `json:"sections,omitempty"`
	Functions  []FunctionRecord `json:"functions,omitempty"`
	TopK       uint32           `json:"topk,omitempty"`
}

type HintMatch struct {
	Bits            uint32  `json:"bits"`
	Offset          uint64  `json:"offset"`
	Confidence      float32 `json:"confidence"`
	MatchedBinaryID string  `json:"matched_binary_id,omitempty"`
}

type SymbolMatchRecord struct {
	Addr            uint64       `json:"addr"`
	Symbol          SymbolRecord `json:"symbol"`
	Confidence      float32      `json:"confidence"`
	Exact           bool         `json:"exact"`
	MatchedBinaryID string       `json:"matched_binary_id,omitempty"`
	MatchedBy       string       `json:"matched_by,omitempty"`
	Offset          uint64       `json:"offset,omitempty"`
	Size            uint32       `json:"size,omitempty"`
}

type ResolveProgramResult struct {
	Hints              []HintMatch         `json:"hints,omitempty"`
	Symbols            []SymbolMatchRecord `json:"symbols,omitempty"`
	CandidateBinaryIDs []string            `json:"candidate_binary_ids,omitempty"`
	ModelVersion       string              `json:"model_version,omitempty"`
	IndexVersion       string              `json:"index_version,omitempty"`
}

type ShareProgramResult struct {
	BinaryID          string `json:"binary_id,omitempty"`
	IngestedFunctions uint32 `json:"ingested_functions"`
	CandidateCount    uint32 `json:"candidate_count"`
	ModelVersion      string `json:"model_version,omitempty"`
	IndexVersion      string `json:"index_version,omitempty"`
}

func symbolRecordFromProto(sym *Symbol) SymbolRecord {
	if sym == nil {
		return SymbolRecord{}
	}
	return SymbolRecord{
		Name:      sym.Name,
		Signature: sym.Signature,
		Callconv:  sym.Callconv,
		Bits:      sym.Bits,
	}
}

func (s SymbolRecord) Proto() *Symbol {
	if s == (SymbolRecord{}) {
		return nil
	}
	return &Symbol{
		Name:      s.Name,
		Signature: s.Signature,
		Callconv:  s.Callconv,
		Bits:      s.Bits,
	}
}

func normalizeSymbolRecord(sym SymbolRecord) SymbolRecord {
	sym.Name = sanitizeSymbol(sym.Name)
	sym.Signature = strings.TrimSpace(sym.Signature)
	sym.Callconv = sanitizeWord(sym.Callconv, "")
	if sym.Bits > 1024 {
		sym.Bits = 0
	}
	return sym
}

func normalizeProgramBundle(bundle ProgramBundle) ProgramBundle {
	bundle.BinaryType = sanitizeWord(bundle.BinaryType, GENERIC_DB)
	bundle.OS = sanitizeWord(bundle.OS, GENERIC_DB)
	bundle.Arch = sanitizeWord(bundle.Arch, GENERIC_DB)
	if bundle.TopK < 1 {
		bundle.TopK = 0
	}
	for i := range bundle.Sections {
		bundle.Sections[i].Name = strings.TrimSpace(bundle.Sections[i].Name)
		bundle.Sections[i].Digest = append([]byte(nil), bundle.Sections[i].Digest...)
	}
	for i := range bundle.Functions {
		fn := &bundle.Functions[i]
		fn.Arch = sanitizeWord(fn.Arch, bundle.Arch)
		fn.SectionName = strings.TrimSpace(fn.SectionName)
		fn.Pseudocode = strings.TrimSpace(fn.Pseudocode)
		fn.PseudocodeSource = sanitizeWord(fn.PseudocodeSource, "none")
		if fn.PseudocodeSource != "ghidra" && fn.PseudocodeSource != "pseudo" && fn.PseudocodeSource != "none" {
			fn.PseudocodeSource = "none"
		}
		fn.Name = strings.TrimSpace(fn.Name)
		fn.Signature = strings.TrimSpace(fn.Signature)
		fn.Callconv = sanitizeWord(fn.Callconv, "")
		fn.Digest = append([]byte(nil), fn.Digest...)
		fn.Calls = append([]uint64(nil), fn.Calls...)
		if fn.Length < 1 {
			fn.Length = fn.Size
		}
		if fn.Bits < 1 {
			fn.Bits = bundle.Bits
		}
	}
	if bundle.BinaryID == "" {
		bundle.BinaryID = computeBinaryID(bundle)
	}
	return bundle
}

func computeBinaryID(bundle ProgramBundle) string {
	type manifestSection struct {
		Name   string `json:"name,omitempty"`
		Size   uint32 `json:"size"`
		Paddr  uint64 `json:"paddr"`
		Digest string `json:"digest,omitempty"`
	}
	type manifestFunction struct {
		Addr             uint64   `json:"addr"`
		Size             uint32   `json:"size"`
		Bits             uint32   `json:"bits,omitempty"`
		Arch             string   `json:"arch,omitempty"`
		Length           uint32   `json:"length,omitempty"`
		Digest           string   `json:"digest,omitempty"`
		SectionName      string   `json:"section_name,omitempty"`
		SectionPaddr     uint64   `json:"section_paddr"`
		SectionOffset    uint64   `json:"section_offset"`
		Loc              uint32   `json:"loc,omitempty"`
		Nos              uint32   `json:"nos,omitempty"`
		Pseudocode       string   `json:"pseudocode,omitempty"`
		PseudocodeSource string   `json:"pseudocode_source,omitempty"`
		Calls            []uint64 `json:"calls,omitempty"`
		Name             string   `json:"name,omitempty"`
		Signature        string   `json:"signature,omitempty"`
		Callconv         string   `json:"callconv,omitempty"`
	}
	type manifest struct {
		BinaryType string             `json:"binary_type,omitempty"`
		OS         string             `json:"os,omitempty"`
		Arch       string             `json:"arch,omitempty"`
		Bits       uint32             `json:"bits,omitempty"`
		Sections   []manifestSection  `json:"sections,omitempty"`
		Functions  []manifestFunction `json:"functions,omitempty"`
	}

	out := manifest{
		BinaryType: bundle.BinaryType,
		OS:         bundle.OS,
		Arch:       bundle.Arch,
		Bits:       bundle.Bits,
		Sections:   make([]manifestSection, 0, len(bundle.Sections)),
		Functions:  make([]manifestFunction, 0, len(bundle.Functions)),
	}

	for _, sec := range bundle.Sections {
		out.Sections = append(out.Sections, manifestSection{
			Name:   sec.Name,
			Size:   sec.Size,
			Paddr:  sec.Paddr,
			Digest: hex.EncodeToString(sec.Digest),
		})
	}
	for _, fn := range bundle.Functions {
		out.Functions = append(out.Functions, manifestFunction{
			Addr:             fn.Addr,
			Size:             fn.Size,
			Bits:             fn.Bits,
			Arch:             fn.Arch,
			Length:           fn.Length,
			Digest:           hex.EncodeToString(fn.Digest),
			SectionName:      fn.SectionName,
			SectionPaddr:     fn.SectionPaddr,
			SectionOffset:    fn.SectionOffset,
			Loc:              fn.Loc,
			Nos:              fn.Nos,
			Pseudocode:       fn.Pseudocode,
			PseudocodeSource: fn.PseudocodeSource,
			Calls:            append([]uint64(nil), fn.Calls...),
			Name:             fn.Name,
			Signature:        fn.Signature,
			Callconv:         fn.Callconv,
		})
	}

	body, _ := json.Marshal(out)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
