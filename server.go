// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.etcd.io/bbolt"
)

const (
	TIMEOUT_CONN = 30 * time.Second
)

var (
	MAX_BODY_LEN = int64(1024 * 1024)
)

type Server struct {
	motd            string
	auths           map[string]bool
	search          map[string][]*bbolt.DB
	shared          map[string]*bbolt.DB
	mutex           sync.Mutex
	queue           chan net.Conn
	capnpRequireTLS bool
}

func maxThreads() int {
	maxProcs := runtime.GOMAXPROCS(0)
	if maxProcs < 1 {
		maxProcs = 1
	}
	numCPU := runtime.NumCPU()
	if numCPU < 1 {
		numCPU = 1
	}
	if maxProcs < numCPU {
		return maxProcs
	}
	return numCPU
}

func (s *Server) GetSymbolsDbs(arch string, bits uint32) []*bbolt.DB {
	anys := s.search[GENERIC_DB]
	arch = sanitizeWord(arch, GENERIC_DB)
	if arch != GENERIC_DB {
		key := fmt.Sprintf("%s|%02d", arch, bits)
		if dbs, ok := s.search[key]; ok {
			return append(dbs, anys...)
		}
	}
	return anys
}

func (s *Server) GetHintsDbs() []*bbolt.DB {
	return s.search[GENERIC_DB]
}

func (s *Server) GetShareDB(key string) *bbolt.DB {
	return s.shared[key]
}

func binaryIDAllowed(binaryID string, candidates map[string]struct{}) bool {
	if len(candidates) < 1 {
		return true
	}
	if binaryID == "" {
		return true
	}
	_, ok := candidates[binaryID]
	return ok
}

func (s *Server) GetSymbolMeta(psk string, sig *Signature, candidates map[string]struct{}) *MetaSymbol {
	if sig == nil || sig.Digest == nil {
		return nil
	}

	dbs := s.GetSymbolsDbs(sig.Arch, sig.Bits)

	key := SignatureToKey(sig)
	for _, db := range dbs {
		meta, err := DbGetSymbolMeta(db, key)
		if err != nil {
			log.Error().Str("psk", psk).Err(err).Send()
			continue
		} else if meta != nil && binaryIDAllowed(meta.BinaryID, candidates) {
			return meta
		}
	}
	return nil
}

func (s *Server) GetLocationSymbolMeta(psk, binaryID string, fn FunctionRecord) *MetaSymbol {
	if binaryID == "" || fn.SectionName == "" {
		return nil
	}

	key := FunctionLocationToKey(binaryID, fn.SectionName, fn.SectionPaddr, fn.SectionOffset)
	for _, db := range s.GetHintsDbs() {
		meta, err := DbGetLocationSymbolMeta(db, key)
		if err != nil {
			log.Error().Str("psk", psk).Err(err).Send()
			continue
		}
		if meta != nil {
			return meta
		}
	}
	return nil
}

func (s *Server) SetSymbolWithBinaryID(psk string, sig *Signature, sym *Symbol, binaryID string) {
	if sig == nil || sym == nil || sig.Digest == nil || len(sym.Name) < 1 {
		return
	}

	dbs := s.GetSymbolsDbs(sig.Arch, sig.Bits)

	key := SignatureToKey(sig)
	for _, db := range dbs {
		found, err := DbHasSymbol(db, key)
		if err != nil {
			log.Error().Str("psk", psk).Err(err).Send()
			continue
		} else if found {
			// don't do anything if the hints are known.
			return
		}
	}

	db := s.GetShareDB(psk)
	if db == nil {
		log.Error().Str("psk", psk).Msg("tried to upload hints but db was not found")
		return
	}

	sym.Name = sanitizeSymbol(sym.Name)
	sym.Signature = strings.TrimSpace(sym.Signature)
	sym.Callconv = sanitizeWord(sym.Callconv, "")
	if sym.Bits > uint32(1024) {
		sym.Bits = 0
	}

	if sym.Name == "" {
		// let's not write stuff that has no valid name.
		return
	}

	s.mutex.Lock()
	err := DbSetSymbolMeta(db, key, psk, binaryID, sym, 0)
	s.mutex.Unlock()
	if err != nil {
		log.Error().Str("psk", psk).Err(err).Send()
	} else {
		log.Warn().
			Str("psk", psk).
			Str("arch", sig.Arch).
			Uint32("bits", sig.Bits).
			Str("name", sym.Name).
			Str("binary_id", binaryID).
			Send()
	}
}

func (s *Server) SetLocationSymbolWithBinaryID(psk string, fn FunctionRecord, sym *Symbol, binaryID string) {
	if binaryID == "" || sym == nil || len(sym.Name) < 1 || fn.SectionName == "" {
		return
	}

	db := s.GetShareDB(psk)
	if db == nil {
		log.Error().Str("psk", psk).Msg("tried to upload location symbols but db was not found")
		return
	}

	key := FunctionLocationToKey(binaryID, fn.SectionName, fn.SectionPaddr, fn.SectionOffset)
	found, err := DbHasLocationSymbol(db, key)
	if err != nil {
		log.Error().Str("psk", psk).Err(err).Send()
		return
	}
	if found {
		return
	}

	sym.Name = sanitizeSymbol(sym.Name)
	sym.Signature = strings.TrimSpace(sym.Signature)
	sym.Callconv = sanitizeWord(sym.Callconv, "")
	if sym.Bits > uint32(1024) {
		sym.Bits = 0
	}
	if sym.Name == "" {
		return
	}

	s.mutex.Lock()
	err = DbSetLocationSymbolMeta(db, key, psk, binaryID, sym, fn.Size)
	s.mutex.Unlock()
	if err != nil {
		log.Error().Str("psk", psk).Err(err).Send()
	}
}

func (s *Server) SetSymbol(psk string, sig *Signature, sym *Symbol) {
	s.SetSymbolWithBinaryID(psk, sig, sym, "")
}

func (s *Server) GetHintsMeta(psk string, binType, binOS string, sec *SectionHash, candidates map[string]struct{}) *MetaHints {
	if sec == nil || sec.Digest == nil {
		return nil
	}

	dbs := s.GetHintsDbs()
	key := SectionHashToKey(sec, binType, binOS)
	for _, db := range dbs {
		meta, err := DbGetHintsMeta(db, key)
		if err != nil {
			log.Error().Str("psk", psk).Err(err).Send()
			continue
		} else if meta != nil && binaryIDAllowed(meta.BinaryID, candidates) {
			return meta
		}
	}
	return nil
}

func (s *Server) SetHintsWithBinaryID(psk string, bin *ShareBin, sec *ShareSection, binaryID string) {
	if sec == nil || sec.Hints == nil || len(sec.Hints) < 1 {
		return
	}
	dbs := s.GetHintsDbs()
	key := SectionHashToKey(sec.Section, bin.Type, bin.Os)
	for _, db := range dbs {
		found, err := DbHasHints(db, key)
		if err != nil {
			log.Error().Str("psk", psk).Err(err).Send()
			continue
		} else if found {
			// don't do anything if the hints are known.
			return
		}
	}

	db := s.GetShareDB(psk)
	if db == nil {
		log.Error().Str("psk", psk).Msg("tried to upload hints but db was not found")
		return
	}

	s.mutex.Lock()
	err := DbSetHintsMeta(db, key, psk, sec.Name, binaryID, sec.Hints)
	s.mutex.Unlock()
	if err != nil {
		log.Error().Str("psk", psk).Err(err).Send()
	} else {
		log.Warn().
			Str("psk", psk).
			Str("section", sec.Name).
			Int("hints", len(sec.Hints)).
			Str("binary_id", binaryID).
			Send()
	}
}

func (s *Server) SetHints(psk string, bin *ShareBin, sec *ShareSection) {
	s.SetHintsWithBinaryID(psk, bin, sec, "")
}

func (s *Server) Worker() {
	for {
		conn := <-s.queue
		handleConnection(s, conn)
	}
}

func (s *Server) Listen(listener net.Listener) {
	log.Warn().Msgf("listening at %s", listener.Addr())

	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Error().Err(err).Send()
			continue
		}
		select {
		case s.queue <- conn:
		default:
			log.Error().Stringer("ip", conn.RemoteAddr()).Msg("client connected but channel was full")
			conn.Close()
		}
	}
}

func NewServer(config *Config) *Server {
	search, shared := config.LoadResources()
	auths := config.GetAuthorized()

	maxQueue := config.MaxQueue
	if maxQueue < 128 {
		maxQueue = 128
	}

	server := &Server{
		motd:            config.Message,
		auths:           auths,
		search:          search,
		shared:          shared,
		queue:           make(chan net.Conn, maxQueue),
		capnpRequireTLS: config.CapnpRequireTLS,
	}

	nThreads := maxThreads()
	for i := 0; i < nThreads; i++ {
		go server.Worker()
	}

	return server
}
