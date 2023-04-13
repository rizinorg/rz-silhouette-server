// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"flag"
)

func main() {
	var config Config
	var configPath string
	flag.StringVar(&configPath, "config", "config.yaml", "YAML configuration file")
	flag.Parse()

	if err := readConfig(configPath, &config); err != nil {
		panic(err)
	}

	server := NewServer(&config)
	raw, tls := config.GetListeners()

	if raw != nil {
		if tls != nil {
			go server.Listen(tls)
		}
		server.Listen(raw)
	} else {
		server.Listen(tls)
	}
}
