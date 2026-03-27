// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
)

func makeStringSet(values []string) map[string]struct{} {
	if len(values) < 1 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		out[value] = struct{}{}
	}
	return out
}

func appendUniqueString(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}

func functionSignature(bundle ProgramBundle, fn FunctionRecord) *Signature {
	if len(fn.Digest) < 1 {
		return nil
	}
	arch := fn.Arch
	if arch == "" {
		arch = bundle.Arch
	}
	length := fn.Length
	if length < 1 {
		length = fn.Size
	}
	bits := fn.Bits
	if bits < 1 {
		bits = bundle.Bits
	}
	return &Signature{
		Arch:   arch,
		Bits:   bits,
		Length: length,
		Digest: append([]byte(nil), fn.Digest...),
	}
}

func functionSymbol(fn FunctionRecord, bundleBits uint32) *Symbol {
	if fn.Name == "" {
		return nil
	}
	bits := fn.Bits
	if bits < 1 {
		bits = bundleBits
	}
	return &Symbol{
		Name:      fn.Name,
		Signature: fn.Signature,
		Callconv:  fn.Callconv,
		Bits:      bits,
	}
}

func sectionLookupKey(name string, paddr uint64) string {
	return fmt.Sprintf("%s|%016x", name, paddr)
}

func sectionOffsetKey(name string, paddr, offset uint64) string {
	return fmt.Sprintf("%s|%016x|%016x", name, paddr, offset)
}

func hintedSymbolSize(hints []*Hint, currentOffset uint64, fallback uint32) uint32 {
	const maxMaterialize = 256
	best := uint64(0)
	for _, hint := range hints {
		if hint == nil || hint.Offset <= currentOffset {
			continue
		}
		span := hint.Offset - currentOffset
		if span == 0 {
			continue
		}
		if best == 0 || span < best {
			best = span
		}
	}

	if fallback > 0 {
		if best == 0 || uint64(fallback) < best {
			best = uint64(fallback)
		}
	}
	if best == 0 {
		best = 16
	}
	if best > maxMaterialize {
		best = maxMaterialize
	}
	return uint32(best)
}

func buildShareSections(bundle ProgramBundle) []*ShareSection {
	sectionsByKey := make(map[string]SectionRecord, len(bundle.Sections))
	sectionsByAddr := make(map[uint64]SectionRecord, len(bundle.Sections))
	for _, section := range bundle.Sections {
		sectionsByKey[sectionLookupKey(section.Name, section.Paddr)] = section
		sectionsByAddr[section.Paddr] = section
	}

	shared := map[string]*ShareSection{}
	for _, fn := range bundle.Functions {
		section, ok := sectionsByKey[sectionLookupKey(fn.SectionName, fn.SectionPaddr)]
		if !ok {
			section, ok = sectionsByAddr[fn.SectionPaddr]
		}
		if !ok || len(section.Digest) < 1 {
			continue
		}

		key := sectionLookupKey(section.Name, section.Paddr)
		entry, ok := shared[key]
		if !ok {
			entry = &ShareSection{
				Name: section.Name,
				Section: &SectionHash{
					Size:   section.Size,
					Paddr:  section.Paddr,
					Digest: append([]byte(nil), section.Digest...),
				},
			}
			shared[key] = entry
		}

		bits := fn.Bits
		if bits < 1 {
			bits = bundle.Bits
		}
		entry.Hints = append(entry.Hints, &Hint{
			Bits:   bits,
			Offset: fn.SectionOffset,
		})
	}

	out := make([]*ShareSection, 0, len(shared))
	for _, section := range shared {
		out = append(out, section)
	}
	return out
}

func (s *Server) ResolveProgram(psk string, bundle ProgramBundle) ResolveProgramResult {
	bundle = normalizeProgramBundle(bundle)
	result := ResolveProgramResult{}

	topK := int(bundle.TopK)
	if topK < 1 {
		topK = s.mlTopK
	}

	mlResp, err := s.ml.Resolve(context.Background(), bundle, topK)
	if err != nil {
		log.Warn().Str("psk", psk).Err(err).Msg("ml resolve failed")
	} else {
		result.CandidateBinaryIDs = append([]string(nil), mlResp.CandidateBinaryIDs...)
		result.ModelVersion = mlResp.ModelVersion
		result.IndexVersion = mlResp.IndexVersion
	}

	candidates := makeStringSet(result.CandidateBinaryIDs)
	sectionCandidates := make(map[string][]string, len(bundle.Sections))
	sectionMetas := make(map[string]*MetaHints, len(bundle.Sections))
	approxByAddr := make(map[uint64]SymbolMatchRecord, len(mlResp.Symbols))
	for _, symbol := range mlResp.Symbols {
		current, ok := approxByAddr[symbol.Addr]
		if !ok || symbol.Confidence > current.Confidence {
			approxByAddr[symbol.Addr] = symbol
		}
	}

	for _, section := range bundle.Sections {
		meta := s.GetHintsMeta(psk, bundle.BinaryType, bundle.OS, &SectionHash{
			Size:   section.Size,
			Paddr:  section.Paddr,
			Digest: section.Digest,
		}, candidates)
		if meta == nil {
			continue
		}
		sectionMetas[sectionLookupKey(section.Name, section.Paddr)] = meta
		if meta.BinaryID != "" {
			result.CandidateBinaryIDs = appendUniqueString(result.CandidateBinaryIDs, meta.BinaryID)
			sectionCandidates[sectionLookupKey(section.Name, section.Paddr)] = appendUniqueString(
				sectionCandidates[sectionLookupKey(section.Name, section.Paddr)],
				meta.BinaryID,
			)
		}
		for _, hint := range meta.Hints {
			if hint == nil {
				continue
			}
			result.Hints = append(result.Hints, HintMatch{
				Bits:            hint.Bits,
				Offset:          hint.Offset + section.Paddr,
				Confidence:      1.0,
				MatchedBinaryID: meta.BinaryID,
			})
		}
	}
	candidates = makeStringSet(result.CandidateBinaryIDs)
	queryOffsets := make(map[string]struct{}, len(bundle.Functions))

	for _, fn := range bundle.Functions {
		sectionKey := sectionLookupKey(fn.SectionName, fn.SectionPaddr)
		sectionMeta := sectionMetas[sectionKey]
		queryOffsets[sectionOffsetKey(fn.SectionName, fn.SectionPaddr, fn.SectionOffset)] = struct{}{}
		matched := false
		locationBinaryIDs := sectionCandidates[sectionKey]
		for _, binaryID := range locationBinaryIDs {
			meta := s.GetLocationSymbolMeta(psk, binaryID, fn)
			if meta == nil || meta.Symbol == nil {
				continue
			}
			result.Symbols = append(result.Symbols, SymbolMatchRecord{
				Addr:            fn.Addr,
				Symbol:          normalizeSymbolRecord(symbolRecordFromProto(meta.Symbol)),
				Confidence:      1.0,
				Exact:           true,
				MatchedBinaryID: meta.BinaryID,
				MatchedBy:       "exact_location",
				Offset:          fn.SectionPaddr + fn.SectionOffset,
				Size:            hintedSymbolSize(sectionMeta.Hints, fn.SectionOffset, meta.Size),
			})
			matched = true
			break
		}
		if matched {
			continue
		}

		sig := functionSignature(bundle, fn)
		if sig == nil {
			if approx, ok := approxByAddr[fn.Addr]; ok {
				result.Symbols = append(result.Symbols, approx)
			}
			continue
		}

		meta := s.GetSymbolMeta(psk, sig, candidates)
		if meta != nil && meta.Symbol != nil {
			result.Symbols = append(result.Symbols, SymbolMatchRecord{
				Addr:            fn.Addr,
				Symbol:          normalizeSymbolRecord(symbolRecordFromProto(meta.Symbol)),
				Confidence:      1.0,
				Exact:           true,
				MatchedBinaryID: meta.BinaryID,
				MatchedBy:       "exact_signature",
			})
			continue
		}

		if approx, ok := approxByAddr[fn.Addr]; ok {
			result.Symbols = append(result.Symbols, approx)
		}
	}

	for _, section := range bundle.Sections {
		sectionKey := sectionLookupKey(section.Name, section.Paddr)
		meta := sectionMetas[sectionKey]
		if meta == nil {
			continue
		}
		for _, hint := range meta.Hints {
			if hint == nil {
				continue
			}
			offsetKey := sectionOffsetKey(section.Name, section.Paddr, hint.Offset)
			if _, exists := queryOffsets[offsetKey]; exists {
				continue
			}
			locationFn := FunctionRecord{
				SectionName:   section.Name,
				SectionPaddr:  section.Paddr,
				SectionOffset: hint.Offset,
			}
			for _, binaryID := range sectionCandidates[sectionKey] {
				locationMeta := s.GetLocationSymbolMeta(psk, binaryID, locationFn)
				if locationMeta == nil || locationMeta.Symbol == nil {
					continue
				}
				result.Symbols = append(result.Symbols, SymbolMatchRecord{
					Symbol:          normalizeSymbolRecord(symbolRecordFromProto(locationMeta.Symbol)),
					Confidence:      1.0,
					Exact:           true,
					MatchedBinaryID: locationMeta.BinaryID,
					MatchedBy:       "exact_hint_location",
					Offset:          section.Paddr + hint.Offset,
					Size:            hintedSymbolSize(meta.Hints, hint.Offset, locationMeta.Size),
				})
				break
			}
		}
	}

	return result
}

func (s *Server) ShareProgram(psk string, bundle ProgramBundle) ShareProgramResult {
	bundle = normalizeProgramBundle(bundle)
	result := ShareProgramResult{
		BinaryID:          bundle.BinaryID,
		IngestedFunctions: uint32(len(bundle.Functions)),
	}

	shareBin := &ShareBin{
		Type: bundle.BinaryType,
		Os:   bundle.OS,
	}
	for _, section := range buildShareSections(bundle) {
		s.SetHintsWithBinaryID(psk, shareBin, section, bundle.BinaryID)
	}

	for _, fn := range bundle.Functions {
		sig := functionSignature(bundle, fn)
		sym := functionSymbol(fn, bundle.Bits)
		if sig == nil || sym == nil {
			continue
		}
		s.SetSymbolWithBinaryID(psk, sig, sym, bundle.BinaryID)
		s.SetLocationSymbolWithBinaryID(psk, fn, sym, bundle.BinaryID)
	}

	mlResp, err := s.ml.Share(context.Background(), bundle)
	if err != nil {
		log.Warn().Str("psk", psk).Err(err).Msg("ml share failed")
		return result
	}

	if mlResp.BinaryID != "" {
		result.BinaryID = mlResp.BinaryID
	}
	result.CandidateCount = mlResp.CandidateCount
	result.ModelVersion = mlResp.ModelVersion
	result.IndexVersion = mlResp.IndexVersion
	return result
}
