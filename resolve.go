// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import "fmt"

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

	if fallback > 0 && (best == 0 || uint64(fallback) < best) {
		best = uint64(fallback)
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

	sectionMetas := make(map[string]*MetaHints, len(bundle.Sections))
	for _, section := range bundle.Sections {
		meta := s.GetHintsMeta(psk, bundle.BinaryType, bundle.OS, &SectionHash{
			Size:   section.Size,
			Paddr:  section.Paddr,
			Digest: section.Digest,
		}, nil)
		if meta == nil {
			continue
		}
		sectionMetas[sectionLookupKey(section.Name, section.Paddr)] = meta
		for _, hint := range meta.Hints {
			if hint == nil {
				continue
			}
			result.Hints = append(result.Hints, HintMatch{
				Bits:   hint.Bits,
				Offset: hint.Offset + section.Paddr,
			})
		}
	}

	queryOffsets := make(map[string]struct{}, len(bundle.Functions))
	for _, fn := range bundle.Functions {
		queryOffsets[sectionOffsetKey(fn.SectionName, fn.SectionPaddr, fn.SectionOffset)] = struct{}{}
		sectionKey := sectionLookupKey(fn.SectionName, fn.SectionPaddr)
		sectionMeta := sectionMetas[sectionKey]

		if sectionMeta != nil && sectionMeta.BinaryID != "" {
			meta := s.GetLocationSymbolMeta(psk, sectionMeta.BinaryID, fn)
			if meta != nil && meta.Symbol != nil {
				result.Symbols = append(result.Symbols, SymbolMatchRecord{
					Addr:            fn.Addr,
					Symbol:          normalizeSymbolRecord(symbolRecordFromProto(meta.Symbol)),
					Exact:           true,
					MatchedBinaryID: meta.BinaryID,
					MatchedBy:       "exact_location",
					Offset:          fn.SectionPaddr + fn.SectionOffset,
					Size:            hintedSymbolSize(sectionMeta.Hints, fn.SectionOffset, meta.Size),
				})
				continue
			}
		}

		sig := functionSignature(bundle, fn)
		if sig == nil {
			continue
		}
		meta := s.GetSymbolMeta(psk, sig, nil)
		if meta != nil && meta.Symbol != nil {
			result.Symbols = append(result.Symbols, SymbolMatchRecord{
				Addr:            fn.Addr,
				Symbol:          normalizeSymbolRecord(symbolRecordFromProto(meta.Symbol)),
				Exact:           true,
				MatchedBinaryID: meta.BinaryID,
				MatchedBy:       "exact_signature",
			})
		}
	}

	for _, section := range bundle.Sections {
		sectionKey := sectionLookupKey(section.Name, section.Paddr)
		meta := sectionMetas[sectionKey]
		if meta == nil || meta.BinaryID == "" {
			continue
		}

		for _, hint := range meta.Hints {
			if hint == nil {
				continue
			}
			key := sectionOffsetKey(section.Name, section.Paddr, hint.Offset)
			if _, exists := queryOffsets[key]; exists {
				continue
			}

			locationMeta := DbGetLocationSymbolMetaSafe(s, psk, meta.BinaryID, section.Name, section.Paddr, hint.Offset)
			if locationMeta == nil || locationMeta.Symbol == nil {
				continue
			}
			result.Symbols = append(result.Symbols, SymbolMatchRecord{
				Addr:            0,
				Symbol:          normalizeSymbolRecord(symbolRecordFromProto(locationMeta.Symbol)),
				Exact:           true,
				MatchedBinaryID: meta.BinaryID,
				MatchedBy:       "exact_hint_location",
				Offset:          section.Paddr + hint.Offset,
				Size:            hintedSymbolSize(meta.Hints, hint.Offset, locationMeta.Size),
			})
		}
	}

	return result
}

func DbGetLocationSymbolMetaSafe(s *Server, psk, binaryID, sectionName string, sectionPaddr, sectionOffset uint64) *MetaSymbol {
	key := FunctionLocationToKey(binaryID, sectionName, sectionPaddr, sectionOffset)
	for _, db := range s.GetHintsDbs() {
		meta, err := DbGetLocationSymbolMeta(db, key)
		if err != nil {
			continue
		}
		if meta != nil {
			return meta
		}
	}
	return nil
}

func (s *Server) ShareProgram(psk string, bundle ProgramBundle) ShareProgramResult {
	bundle = normalizeProgramBundle(bundle)
	shareBin := &ShareBin{
		Type:     bundle.BinaryType,
		Os:       bundle.OS,
		Sections: buildShareSections(bundle),
	}

	for _, fn := range bundle.Functions {
		sig := functionSignature(bundle, fn)
		sym := functionSymbol(fn, bundle.Bits)
		if sig != nil && sym != nil {
			shareBin.Symbols = append(shareBin.Symbols, &ShareSymbol{
				Symbol:    sym,
				Signature: sig,
			})
		}
	}

	if shareBin.Sections != nil {
		for _, section := range shareBin.Sections {
			s.SetHintsWithBinaryID(psk, shareBin, section, bundle.BinaryID)
		}
	}
	if shareBin.Symbols != nil {
		symbolIndex := 0
		for _, fn := range bundle.Functions {
			if functionSignature(bundle, fn) == nil || functionSymbol(fn, bundle.Bits) == nil {
				continue
			}
			share := shareBin.Symbols[symbolIndex]
			s.SetSymbolWithBinaryID(psk, share.Signature, share.Symbol, bundle.BinaryID)
			s.SetLocationSymbolWithBinaryID(psk, fn, share.Symbol, bundle.BinaryID)
			symbolIndex++
		}
	}

	return ShareProgramResult{BinaryID: bundle.BinaryID}
}
