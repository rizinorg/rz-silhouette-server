// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"context"
	"fmt"
	"net"

	capnp "capnproto.org/go/capnp/v3"
	"github.com/rs/zerolog/log"

	"rz-silhouette-server/servicecapnp"
)

type capnpRequest struct {
	Psk     string
	Version uint32
	Route   servicecapnp.RouteV2
	Program ProgramBundle
}

func decodeCapnpRequest(packet []byte) (capnpRequest, error) {
	msg, err := capnp.UnmarshalPacked(packet)
	if err != nil {
		return capnpRequest{}, err
	}

	root, err := servicecapnp.ReadRootRequestV2(msg)
	if err != nil {
		return capnpRequest{}, err
	}

	psk, err := root.Psk()
	if err != nil {
		return capnpRequest{}, err
	}

	req := capnpRequest{
		Psk:     psk,
		Version: root.Version(),
		Route:   root.Route(),
	}

	switch root.Which() {
	case servicecapnp.RequestV2_Which_ping:
		if req.Route != servicecapnp.RouteV2_ping {
			return capnpRequest{}, fmt.Errorf("capnp route mismatch: %s/%s", req.Route, root.Which())
		}
	case servicecapnp.RequestV2_Which_resolveProgram:
		if req.Route != servicecapnp.RouteV2_resolveProgram {
			return capnpRequest{}, fmt.Errorf("capnp route mismatch: %s/%s", req.Route, root.Which())
		}
		resolveReq, err := root.ResolveProgram()
		if err != nil {
			return capnpRequest{}, err
		}
		req.Program, err = decodeProgramBundle(resolveReq.Program)
		if err != nil {
			return capnpRequest{}, err
		}
	case servicecapnp.RequestV2_Which_shareProgram:
		if req.Route != servicecapnp.RouteV2_shareProgram {
			return capnpRequest{}, fmt.Errorf("capnp route mismatch: %s/%s", req.Route, root.Which())
		}
		shareReq, err := root.ShareProgram()
		if err != nil {
			return capnpRequest{}, err
		}
		req.Program, err = decodeProgramBundle(shareReq.Program)
		if err != nil {
			return capnpRequest{}, err
		}
	default:
		return capnpRequest{}, fmt.Errorf("unsupported capnp union %s", root.Which())
	}

	return req, nil
}

func decodeProgramBundle(get func() (servicecapnp.ProgramBundleV2, error)) (ProgramBundle, error) {
	program, err := get()
	if err != nil {
		return ProgramBundle{}, err
	}

	binaryType, err := program.BinaryType()
	if err != nil {
		return ProgramBundle{}, err
	}
	binaryOS, err := program.Os()
	if err != nil {
		return ProgramBundle{}, err
	}
	arch, err := program.Arch()
	if err != nil {
		return ProgramBundle{}, err
	}
	binaryID, err := program.BinaryId()
	if err != nil {
		return ProgramBundle{}, err
	}

	out := ProgramBundle{
		BinaryType: binaryType,
		OS:         binaryOS,
		Arch:       arch,
		Bits:       program.Bits(),
		BinaryID:   binaryID,
		TopK:       program.Topk(),
	}

	sections, err := program.Sections()
	if err != nil {
		return ProgramBundle{}, err
	}
	for i := 0; i < sections.Len(); i++ {
		section := sections.At(i)
		digest, err := section.Digest()
		if err != nil {
			return ProgramBundle{}, err
		}
		name, err := section.Name()
		if err != nil {
			return ProgramBundle{}, err
		}
		out.Sections = append(out.Sections, SectionRecord{
			Name:   name,
			Size:   section.Size(),
			Paddr:  section.Paddr(),
			Digest: append([]byte(nil), digest...),
		})
	}

	functions, err := program.Functions()
	if err != nil {
		return ProgramBundle{}, err
	}
	for i := 0; i < functions.Len(); i++ {
		function := functions.At(i)
		digest, err := function.Digest()
		if err != nil {
			return ProgramBundle{}, err
		}
		arch, err := function.Arch()
		if err != nil {
			return ProgramBundle{}, err
		}
		sectionName, err := function.SectionName()
		if err != nil {
			return ProgramBundle{}, err
		}
		pseudocode, err := function.Pseudocode()
		if err != nil {
			return ProgramBundle{}, err
		}
		pseudocodeSource, err := function.PseudocodeSource()
		if err != nil {
			return ProgramBundle{}, err
		}
		name, err := function.Name()
		if err != nil {
			return ProgramBundle{}, err
		}
		signature, err := function.Signature()
		if err != nil {
			return ProgramBundle{}, err
		}
		callconv, err := function.Callconv()
		if err != nil {
			return ProgramBundle{}, err
		}
		callsList, err := function.Calls()
		if err != nil {
			return ProgramBundle{}, err
		}
		calls := make([]uint64, 0, callsList.Len())
		for j := 0; j < callsList.Len(); j++ {
			calls = append(calls, callsList.At(j))
		}
		out.Functions = append(out.Functions, FunctionRecord{
			Addr:             function.Addr(),
			Size:             function.Size(),
			Bits:             function.Bits(),
			Arch:             arch,
			Length:           function.Length(),
			Digest:           append([]byte(nil), digest...),
			SectionName:      sectionName,
			SectionPaddr:     function.SectionPaddr(),
			SectionOffset:    function.SectionOffset(),
			Loc:              function.Loc(),
			Nos:              function.Nos(),
			Pseudocode:       pseudocode,
			PseudocodeSource: pseudocodeSource,
			Calls:            calls,
			Name:             name,
			Signature:        signature,
			Callconv:         callconv,
		})
	}

	return normalizeProgramBundle(out), nil
}

func writeCapnpMessageResponse(conn net.Conn, status servicecapnp.StatusV2, text string) bool {
	msg, seg := capnp.NewSingleSegmentMessage(nil)
	root, err := servicecapnp.NewRootResponseV2(seg)
	if err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Msg("Failed to allocate capnp response")
		return false
	}
	root.SetStatus(status)
	message, err := root.NewMessage_()
	if err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Msg("Failed to allocate capnp message body")
		return false
	}
	if err := message.SetText(text); err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Msg("Failed to set capnp response text")
		return false
	}
	packet, err := msg.MarshalPacked()
	if err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Msg("Failed to encode capnp response")
		return false
	}
	return writePacket(conn, wireCodecCapnp, packet)
}

func writeCapnpServerInfo(conn net.Conn, info MLInfo, tlsRequired bool) bool {
	msg, seg := capnp.NewSingleSegmentMessage(nil)
	root, err := servicecapnp.NewRootResponseV2(seg)
	if err != nil {
		return false
	}
	root.SetStatus(servicecapnp.StatusV2_serverInfo)
	serverInfo, err := root.NewServerInfo()
	if err != nil {
		return false
	}
	codecs, err := serverInfo.NewSupportedCodecs(2)
	if err != nil {
		return false
	}
	codecs.Set(0, servicecapnp.CodecV2_protobuf)
	codecs.Set(1, servicecapnp.CodecV2_capnp)
	serverInfo.SetMinVersion(MIN_VERSION)
	serverInfo.SetMaxVersion(MAX_VERSION)
	serverInfo.SetKeenhashEnabled(info.Available)
	serverInfo.SetDecompilerRequired(true)
	serverInfo.SetTlsRequired(tlsRequired)
	if err := serverInfo.SetModelVersion(info.ModelVersion); err != nil {
		return false
	}
	if err := serverInfo.SetIndexVersion(info.IndexVersion); err != nil {
		return false
	}
	packet, err := msg.MarshalPacked()
	if err != nil {
		return false
	}
	return writePacket(conn, wireCodecCapnp, packet)
}

func writeCapnpResolveResult(conn net.Conn, result ResolveProgramResult) bool {
	msg, seg := capnp.NewSingleSegmentMessage(nil)
	root, err := servicecapnp.NewRootResponseV2(seg)
	if err != nil {
		return false
	}
	root.SetStatus(servicecapnp.StatusV2_resolveResult)
	resolveResult, err := root.NewResolveResult()
	if err != nil {
		return false
	}
	if err := populateCapnpResolveResult(resolveResult, result); err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Msg("Failed to encode resolve result")
		return false
	}
	packet, err := msg.MarshalPacked()
	if err != nil {
		return false
	}
	return writePacket(conn, wireCodecCapnp, packet)
}

func populateCapnpResolveResult(dst servicecapnp.ResolveResultV2, result ResolveProgramResult) error {
	hints, err := dst.NewHints(int32(len(result.Hints)))
	if err != nil {
		return err
	}
	for i, hint := range result.Hints {
		entry := hints.At(i)
		entry.SetBits(hint.Bits)
		entry.SetOffset(hint.Offset)
		entry.SetConfidence(hint.Confidence)
		if err := entry.SetMatchedBinaryId(hint.MatchedBinaryID); err != nil {
			return err
		}
	}

	symbols, err := dst.NewSymbols(int32(len(result.Symbols)))
	if err != nil {
		return err
	}
	for i, symbol := range result.Symbols {
		entry := symbols.At(i)
		entry.SetAddr(symbol.Addr)
		entry.SetConfidence(symbol.Confidence)
		entry.SetExact(symbol.Exact)
		entry.SetOffset(symbol.Offset)
		entry.SetSize(symbol.Size)
		if err := entry.SetMatchedBinaryId(symbol.MatchedBinaryID); err != nil {
			return err
		}
		if err := entry.SetMatchedBy(symbol.MatchedBy); err != nil {
			return err
		}
		sym, err := entry.NewSymbol()
		if err != nil {
			return err
		}
		if err := sym.SetName(symbol.Symbol.Name); err != nil {
			return err
		}
		if err := sym.SetSignature(symbol.Symbol.Signature); err != nil {
			return err
		}
		if err := sym.SetCallconv(symbol.Symbol.Callconv); err != nil {
			return err
		}
		sym.SetBits(symbol.Symbol.Bits)
	}

	candidates, err := dst.NewCandidateBinaryIds(int32(len(result.CandidateBinaryIDs)))
	if err != nil {
		return err
	}
	for i, candidate := range result.CandidateBinaryIDs {
		if err := candidates.Set(i, candidate); err != nil {
			return err
		}
	}
	if err := dst.SetModelVersion(result.ModelVersion); err != nil {
		return err
	}
	return dst.SetIndexVersion(result.IndexVersion)
}

func writeCapnpShareResult(conn net.Conn, result ShareProgramResult) bool {
	msg, seg := capnp.NewSingleSegmentMessage(nil)
	root, err := servicecapnp.NewRootResponseV2(seg)
	if err != nil {
		return false
	}
	root.SetStatus(servicecapnp.StatusV2_shareResult)
	shareResult, err := root.NewShareResult()
	if err != nil {
		return false
	}
	if err := shareResult.SetBinaryId(result.BinaryID); err != nil {
		return false
	}
	shareResult.SetIngestedFunctions(result.IngestedFunctions)
	shareResult.SetCandidateCount(result.CandidateCount)
	if err := shareResult.SetModelVersion(result.ModelVersion); err != nil {
		return false
	}
	if err := shareResult.SetIndexVersion(result.IndexVersion); err != nil {
		return false
	}
	packet, err := msg.MarshalPacked()
	if err != nil {
		return false
	}
	return writePacket(conn, wireCodecCapnp, packet)
}

func handleCapnpConnection(server *Server, conn net.Conn, packet []byte) (requestLogInfo, bool) {
	request, err := decodeCapnpRequest(packet)
	if err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Msg("Failed to decode capnp request")
		return requestLogInfo{}, false
	}

	info := requestLogInfo{
		codec:   wireCodecCapnp,
		psk:     request.Psk,
		route:   request.Route.String(),
		version: request.Version,
	}

	_, exists := server.auths[request.Psk]
	if request.Psk == "" || !exists {
		writeCapnpMessageResponse(conn, servicecapnp.StatusV2_clientBadPreSharedKey, "client pre-shared key was rejected")
		return info, true
	}
	if request.Version != CAPNP_VERSION {
		writeCapnpMessageResponse(conn, servicecapnp.StatusV2_versionMismatch, fmt.Sprintf("client/server capnp protocol mismatch: got %d want %d", request.Version, CAPNP_VERSION))
		return info, true
	}
	if server.capnpRequireTLS && !isTLSConn(conn) {
		writeCapnpMessageResponse(conn, servicecapnp.StatusV2_clientNotAuthorized, "capnp v2 requires TLS")
		return info, true
	}

	ctx := context.Background()
	switch request.Route {
	case servicecapnp.RouteV2_ping:
		mlInfo := server.MLInfo(ctx)
		writeCapnpServerInfo(conn, mlInfo, server.capnpRequireTLS)
	case servicecapnp.RouteV2_resolveProgram:
		result := server.ResolveProgram(request.Psk, request.Program)
		writeCapnpResolveResult(conn, result)
	case servicecapnp.RouteV2_shareProgram:
		if !server.auths[request.Psk] {
			writeCapnpMessageResponse(conn, servicecapnp.StatusV2_clientNotAuthorized, "client is not allowed to share")
			return info, true
		}
		result := server.ShareProgram(request.Psk, request.Program)
		writeCapnpShareResult(conn, result)
	default:
		writeCapnpMessageResponse(conn, servicecapnp.StatusV2_internalError, "unsupported capnp route")
	}
	return info, true
}
