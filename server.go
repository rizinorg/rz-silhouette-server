// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

const (
	TIMEOUT_CONN = 30 * time.Second
)

var (
	MAX_BODY_LEN = int64(1024 * 1024)
)

type Server struct {
	motd   string
	auths  map[string]bool
	search map[string][]*bbolt.DB
	shared map[string]*bbolt.DB
	mutex  sync.Mutex
	queue  chan net.Conn
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

func (s *Server) GetSymbol(psk string, sig *Signature) *Symbol {
	if sig == nil || sig.Digest == nil {
		return nil
	}

	dbs := s.GetSymbolsDbs(sig.Arch, sig.Bits)

	key := SignatureToKey(sig)
	for _, db := range dbs {
		sym, err := DbGetSymbol(db, key)
		if err != nil {
			log.Println(psk, err)
			continue
		} else if sym != nil {
			return sym
		}
	}
	return nil
}

func (s *Server) SetSymbol(psk string, sig *Signature, sym *Symbol) {
	if sig == nil || sym == nil || sig.Digest == nil || len(sym.Name) < 1 {
		return
	}

	dbs := s.GetSymbolsDbs(sig.Arch, sig.Bits)

	key := SignatureToKey(sig)
	for _, db := range dbs {
		found, err := DbHasSymbol(db, key)
		if err != nil {
			log.Println(psk, err)
			continue
		} else if found {
			// don't do anything if the hints are known.
			return
		}
	}

	db := s.GetShareDB(psk)
	if db == nil {
		log.Println(psk, "tried to upload hints but db was not found.")
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
	err := DbSetSymbol(db, key, psk, sym)
	s.mutex.Unlock()
	if err != nil {
		log.Println(psk, err)
	} else {
		log.Printf("'%s' added '%s|%d|%s' symbol\n", psk, sig.Arch, sig.Bits, sym.Name)
	}
}

func (s *Server) GetHints(psk string, bin *Binary, sec *SectionHash) []*Hint {
	dbs := s.GetHintsDbs()
	key := SectionHashToKey(sec, bin.Type, bin.Os)
	for _, db := range dbs {
		hints, err := DbGetHints(db, key)
		if err != nil {
			log.Println(psk, err)
			continue
		} else if hints != nil {
			return hints
		}
	}
	return nil
}

func (s *Server) SetHints(psk string, bin *ShareBin, sec *ShareSection) {
	if sec == nil || sec.Hints == nil || len(sec.Hints) < 1 {
		return
	}
	dbs := s.GetHintsDbs()
	key := SectionHashToKey(sec.Section, bin.Type, bin.Os)
	for _, db := range dbs {
		found, err := DbHasHints(db, key)
		if err != nil {
			log.Println(psk, err)
			continue
		} else if found {
			// don't do anything if the hints are known.
			return
		}
	}

	db := s.GetShareDB(psk)
	if db == nil {
		log.Println(psk, "tried to upload hints but db was not found.")
		return
	}

	s.mutex.Lock()
	err := DbSetHints(db, key, psk, sec.Name, sec.Hints)
	s.mutex.Unlock()
	if err != nil {
		log.Println(psk, err)
	} else {
		log.Printf("'%s' added '%s' and %d hints\n", psk, sec.Name, len(sec.Hints))
	}
}

func (s *Server) IsAuthorized(req *Request) bool {
	if req.Psk == "" {
		return false
	}
	_, exists := s.auths[req.Psk]
	return exists
}

func (s *Server) CanShare(req *Request) bool {
	if req.Psk == "" {
		return false
	}
	canShare, exists := s.auths[req.Psk]
	return exists && canShare
}

func (s *Server) Worker() {
	for {
		conn := <-s.queue
		handleConnection(s, conn)
	}
}

func (s *Server) Listen(listener net.Listener) {
	log.Printf("listening at %s\n", listener.Addr())

	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		select {
		case s.queue <- conn:
		default:
			log.Printf("%s connected but channel was full.\n", conn.RemoteAddr())
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
		motd:   config.Message,
		auths:  auths,
		search: search,
		shared: shared,
		queue:  make(chan net.Conn, maxQueue),
	}

	nThreads := maxThreads()
	for i := 0; i < nThreads; i++ {
		go server.Worker()
	}

	return server
}
