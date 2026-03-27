// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	HEADER_SIZE = int64(4)
	CAPNP_MAGIC = "SIL2"
)

type wireCodec int

const (
	wireCodecProtobuf wireCodec = iota
	wireCodecCapnp
)

type requestLogInfo struct {
	codec   wireCodec
	psk     string
	route   string
	version uint32
}

func readFromConn(conn net.Conn, expected int64) ([]byte, bool) {
	conn.SetReadDeadline(time.Now().Add(TIMEOUT_CONN))
	if expected < 0 || expected > MAX_BODY_LEN {
		log.Info().Stringer("ip", conn.RemoteAddr()).Msgf("Invalid requested read size %d", expected)
		return nil, false
	}

	buffer := make([]byte, expected)
	_, err := io.ReadFull(conn, buffer)
	if err == io.EOF {
		return nil, false
	} else if err != nil {
		log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Send()
		return nil, false
	}
	return buffer, true
}

func readIncomingPacket(conn net.Conn) (wireCodec, []byte, bool) {
	header, ok := readFromConn(conn, HEADER_SIZE)
	if !ok {
		log.Info().Stringer("ip", conn.RemoteAddr()).Msg("Failed to receive packet size.")
		return wireCodecProtobuf, nil, false
	}

	packetSize := int64(binary.BigEndian.Uint32(header))
	if packetSize > MAX_BODY_LEN {
		log.Info().Stringer("ip", conn.RemoteAddr()).Msgf("Expected small body size (%d) but received %d", MAX_BODY_LEN, packetSize)
		return wireCodecProtobuf, nil, false
	}

	packet, ok := readFromConn(conn, packetSize)
	if !ok {
		log.Info().Stringer("ip", conn.RemoteAddr()).Msg("Failed to receive packet")
		return wireCodecProtobuf, nil, false
	}

	if len(packet) >= len(CAPNP_MAGIC) && string(packet[:len(CAPNP_MAGIC)]) == CAPNP_MAGIC {
		return wireCodecCapnp, packet[len(CAPNP_MAGIC):], true
	}

	return wireCodecProtobuf, packet, true
}

func writeToConn(conn net.Conn, buffer []byte) bool {
	offset := 0
	for offset < len(buffer) {
		written, err := conn.Write(buffer[offset:])
		if err == io.EOF {
			return false
		} else if err != nil {
			log.Info().Stringer("ip", conn.RemoteAddr()).Err(err).Send()
			return false
		}
		offset += written
	}
	return true
}

func writePacket(conn net.Conn, codec wireCodec, body []byte) bool {
	if codec == wireCodecCapnp {
		body = append([]byte(CAPNP_MAGIC), body...)
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if writeToConn(conn, header) && writeToConn(conn, body) {
		return true
	}
	log.Info().Stringer("ip", conn.RemoteAddr()).Msg("Failed to send response packet")
	return false
}

func isTLSConn(conn net.Conn) bool {
	_, ok := conn.(*tls.Conn)
	return ok
}

func logRequest(conn net.Conn, info requestLogInfo, start time.Time) {
	end := time.Now()
	log.Warn().
		Stringer("ip", conn.RemoteAddr()).
		Str("codec", map[wireCodec]string{
			wireCodecProtobuf: "protobuf",
			wireCodecCapnp:    "capnp",
		}[info.codec]).
		Str("psk", info.psk).
		Str("route", info.route).
		Uint32("version", info.version).
		TimeDiff("duration", end, start).
		Send()
}

func handleConnection(server *Server, conn net.Conn) {
	start := time.Now()
	defer conn.Close()

	codec, packet, ok := readIncomingPacket(conn)
	if !ok {
		return
	}

	switch codec {
	case wireCodecCapnp:
		info, handled := handleCapnpConnection(server, conn, packet)
		if handled {
			logRequest(conn, info, start)
		}
	default:
		info, handled := handleLegacyConnection(server, conn, packet)
		if handled {
			logRequest(conn, info, start)
		}
	}
}
