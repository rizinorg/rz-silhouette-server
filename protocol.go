// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/proto"
)

const (
	HEADER_SIZE = int64(4)
)

func readFromConn(conn net.Conn, expected int64) ([]byte, bool) {
	conn.SetReadDeadline(time.Now().Add(TIMEOUT_CONN))
	var buffer bytes.Buffer
	writer := io.Writer(&buffer)

	_, err := io.CopyN(writer, conn, expected)
	if err == io.EOF {
		return nil, false
	} else if err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Send()
		return nil, false
	}

	b := buffer.Bytes()
	if len(b) != int(expected) {
		log.Info().Stringer("ip", conn.RemoteAddr()).Msgf("Expected %d but received only %d", expected, len(b))
		return nil, false
	}
	return b, true
}

func readIncomingRequest(conn net.Conn) *Request {
	header, ok := readFromConn(conn, HEADER_SIZE)
	if !ok {
		log.Info().Stringer("ip", conn.RemoteAddr()).Msg("Failed to receive packet size.")
		return nil
	}

	packetSize := int64(binary.BigEndian.Uint32(header))
	if packetSize > MAX_BODY_LEN {
		log.Info().Stringer("ip", conn.RemoteAddr()).Msgf("Expected small body size (%d) but received %d", MAX_BODY_LEN, packetSize)
		return nil
	}

	packet, ok := readFromConn(conn, packetSize)
	if !ok {
		log.Info().Stringer("ip", conn.RemoteAddr()).Msg("Failed to receive packet")
		return nil
	}

	req := &Request{}
	if err := proto.Unmarshal(packet, req); err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Msg("Failed to decode request")
		return nil
	}

	return req
}

func writeToConn(conn net.Conn, buffer []byte) bool {
	var b = bytes.NewBuffer(buffer)
	reader := io.Reader(b)

	written, err := io.Copy(conn, reader)
	if err == io.EOF {
		return false
	} else if err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Send()
		return false
	} else if int(written) != len(buffer) {
		log.Info().Stringer("ip", conn.RemoteAddr()).Msg("Failed to send all the bytes")
		return false
	}
	return true
}

func writeOutgoingResponse(conn net.Conn, body proto.Message, status Status) bool {
	var message []byte = nil
	var err error = nil

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

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header[:], uint32(len(packet)))
	if writeToConn(conn, header) && writeToConn(conn, packet) {
		return true
	}
	log.Info().Stringer("ip", conn.RemoteAddr()).Msg("Failed to send response packet")
	return false
}

func handlePingRequest(server *Server, conn net.Conn, request *Request) {
	message := Message{
		Text: server.motd,
	}
	writeOutgoingResponse(conn, &message, Status_MESSAGE)
}

func handleBinaryRequest(server *Server, conn net.Conn, request *Request) {
	var binary = Binary{}
	if err := proto.Unmarshal(request.Message, &binary); err != nil {
		log.Info().
			Stringer("ip", conn.RemoteAddr()).
			Str("psk", request.Psk).
			Stringer("route", request.Route).
			Err(err).
			Send()
		return
	}

	var matches = MatchHints{}
	for _, section := range binary.Sections {
		hints := server.GetHints(request.Psk, &binary, section)
		if hints == nil {
			continue
		}
		for _, hint := range hints {
			hint.Offset += section.Paddr
		}
		if matches.Hints == nil {
			matches.Hints = hints
		} else {
			matches.Hints = append(matches.Hints, hints...)
		}
	}

	writeOutgoingResponse(conn, &matches, Status_HINTS)
}

func handleSignatureRequest(server *Server, conn net.Conn, request *Request) {
	var signature = Signature{}
	if err := proto.Unmarshal(request.Message, &signature); err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).
			Str("psk", request.Psk).
			Stringer("route", request.Route).
			Err(err).
			Send()
		return
	}

	message := server.GetSymbol(request.Psk, &signature)
	writeOutgoingResponse(conn, message, Status_SYMBOL)
}

func handleShareBinRequest(server *Server, conn net.Conn, request *Request) {
	if !server.CanShare(request) {
		writeOutgoingResponse(conn, nil, Status_CLIENT_NOT_AUTHORIZED)
		return
	}

	var bin = ShareBin{}
	if err := proto.Unmarshal(request.Message, &bin); err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).
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

	writeOutgoingResponse(conn, nil, Status_SHARE_WAS_SUCCESSFUL)
}

func logRequest(conn net.Conn, request *Request, start time.Time) {
	end := time.Now()
	log.Warn().
		Stringer("ip", conn.RemoteAddr()).
		Str("psk", request.Psk).
		Stringer("route", request.Route).
		TimeDiff("duration", end, start).
		Send()
}

func handleConnection(server *Server, conn net.Conn) {
	var start = time.Now()
	var request *Request = nil

	defer conn.Close()

	request = readIncomingRequest(conn)
	if request == nil {
		return
	}

	if !server.IsAuthorized(request) {
		writeOutgoingResponse(conn, nil, Status_CLIENT_BAD_PRE_SHARED_KEY)
		logRequest(conn, request, start)

		return
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
	}
	logRequest(conn, request, start)
}
