// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"errors"
	"os"
	"regexp"
	"strings"
)

var (
	SYMBOLFILTER    = regexp.MustCompile(`[^a-zA-Z0-9:.]+`)
	NONALPHANUMERIC = regexp.MustCompile(`[^a-z0-9]+`)
	AUTH_FAIL       = errors.New("auth: failed to authenticate")
	TCP_PKT_TOO_BIG = errors.New("tcp: packet size is too big")
	TCP_SEND_FAIL   = errors.New("tcp: failed to send packet")
	TCP_RECV_FAIL   = errors.New("tcp: failed to receive packet")
	DECODE_FAIL     = errors.New("proto: failed to decode packet")
	BUCKET_SEC_FAIL = errors.New("db: failed to fetch the sections bucket")
	BUCKET_SYM_FAIL = errors.New("db: failed to fetch the symbols bucket")
)

func exists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func sanitizeSymbol(orig string) string {
	ret := strings.TrimSpace(orig)
	return SYMBOLFILTER.ReplaceAllString(ret, ".")
}

func sanitizeWord(orig, def string) string {
	ret := strings.TrimSpace(orig)
	res := strings.ToLower(ret)
	res = NONALPHANUMERIC.ReplaceAllString(res, "")
	if res == "" {
		return def
	}
	return res
}
