// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"fmt"
	"net"

	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/proto"
)

func decodeLegacyRequest(packet []byte) (*Request, error) {
	req := &Request{}
	if err := proto.Unmarshal(packet, req); err != nil {
		return nil, err
	}
	return req, nil
}

func writeLegacyResponse(conn net.Conn, body proto.Message, status Status) bool {
	var message []byte
	var err error

	if body != nil {
		message, err = proto.Marshal(body)
		if err != nil {
			log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Msg("Failed to encode body")
			return false
		}
	}

	resp := Response{
		Status:  status,
		Message: message,
	}

	packet, err := proto.Marshal(&resp)
	if err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Msg("Failed to encode response")
		return false
	}

	return writePacket(conn, wireCodecProtobuf, packet)
}

func handlePingRequest(server *Server, conn net.Conn, request *Request) {
	message := Message{
		Text: server.motd,
	}
	writeLegacyResponse(conn, &message, Status_MESSAGE)
}

func handleBinaryRequest(server *Server, conn net.Conn, request *Request) {
	var binaryReq Binary
	if err := proto.Unmarshal(request.Message, &binaryReq); err != nil {
		log.Info().
			Stringer("ip", conn.RemoteAddr()).
			Str("psk", request.Psk).
			Stringer("route", request.Route).
			Err(err).
			Send()
		return
	}

	var matches MatchHints
	for _, section := range binaryReq.Sections {
		hints := server.GetHints(request.Psk, &binaryReq, section)
		if hints == nil {
			continue
		}
		for _, hint := range hints {
			if hint == nil {
				continue
			}
			hint = &Hint{
				Bits:   hint.Bits,
				Offset: hint.Offset + section.Paddr,
			}
			matches.Hints = append(matches.Hints, hint)
		}
	}

	writeLegacyResponse(conn, &matches, Status_HINTS)
}

func handleSignatureRequest(server *Server, conn net.Conn, request *Request) {
	var signature Signature
	if err := proto.Unmarshal(request.Message, &signature); err != nil {
		log.Info().
			Stringer("ip", conn.RemoteAddr()).
			Str("psk", request.Psk).
			Stringer("route", request.Route).
			Err(err).
			Send()
		return
	}

	message := server.GetSymbol(request.Psk, &signature)
	writeLegacyResponse(conn, message, Status_SYMBOL)
}

func handleShareBinRequest(server *Server, conn net.Conn, request *Request) {
	if !server.CanShare(request) {
		writeLegacyResponse(conn, nil, Status_CLIENT_NOT_AUTHORIZED)
		return
	}

	var bin ShareBin
	if err := proto.Unmarshal(request.Message, &bin); err != nil {
		log.Info().
			Stringer("ip", conn.RemoteAddr()).
			Str("psk", request.Psk).
			Stringer("route", request.Route).
			Err(err).
			Send()
		return
	}

	if bin.Sections != nil {
		for _, section := range bin.Sections {
			server.SetHints(request.Psk, &bin, section)
		}
	}

	if bin.Symbols != nil {
		for _, share := range bin.Symbols {
			server.SetSymbol(request.Psk, share.Signature, share.Symbol)
		}
	}

	writeLegacyResponse(conn, nil, Status_SHARE_WAS_SUCCESSFUL)
}

func handleLegacyConnection(server *Server, conn net.Conn, packet []byte) (requestLogInfo, bool) {
	request, err := decodeLegacyRequest(packet)
	if err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Msg("Failed to decode request")
		return requestLogInfo{}, false
	}

	info := requestLogInfo{
		codec:   wireCodecProtobuf,
		psk:     request.Psk,
		route:   request.Route.String(),
		version: request.Version,
	}

	if !server.IsAuthorized(request) {
		writeLegacyResponse(conn, nil, Status_CLIENT_BAD_PRE_SHARED_KEY)
		return info, true
	}
	if request.Version != PROTOBUF_VERSION {
		writeLegacyResponse(conn, &Message{
			Text: fmt.Sprintf("client/server protobuf protocol mismatch: got %d want %d", request.Version, PROTOBUF_VERSION),
		}, Status_VERSION_MISMATCH)
		return info, true
	}

	switch request.Route {
	case Route_PING:
		handlePingRequest(server, conn, request)
	case Route_BINARY:
		handleBinaryRequest(server, conn, request)
	case Route_SIGNATURE:
		handleSignatureRequest(server, conn, request)
	case Route_SHARE_BIN:
		handleShareBinRequest(server, conn, request)
	default:
		writeLegacyResponse(conn, &Message{Text: "unsupported protobuf route"}, Status_INTERNAL_ERROR)
	}
	return info, true
}
