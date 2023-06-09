// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.etcd.io/bbolt"
	"gopkg.in/yaml.v3"
)

const (
	MIN_VERSION = uint32(1)
	GENERIC_DB  = "any"
)

type Resource struct {
	Arch  string   `yaml:"arch"`
	Bits  int      `yaml:"bits`
	Files []string `yaml:"files"`
}

type Config struct {
	MaxQueue   int             `yaml:"max_queue"`
	MaxPacket  int64           `yaml:"max_packet"`
	LogLevel   string          `yaml:"log_level"`
	RawBind    string          `yaml:"raw-bind"`
	TlsBind    string          `yaml:"tls-bind"`
	TlsKey     string          `yaml:"tls-key"`
	TlsCert    string          `yaml:"tls-cert"`
	Message    string          `yaml:"message"`
	UploadDir  string          `yaml:"upload_dir"`
	Resources  []Resource      `yaml:"resources"`
	Authorized map[string]bool `yaml:"authorized"`
}

func readConfig(filename string, config *Config) error {
	body, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal([]byte(body), config)
	if err != nil {
		return err
	}

	if len(config.Authorized) < 1 {
		log.Fatal().Msg("`authorized` is not defined or is empty.")
	} else if config.MaxPacket < MAX_BODY_LEN {
		log.Fatal().Msg("`max_packet` is not defined or is less than 1Mb.")
	} else if len(config.LogLevel) < 1 {
		log.Fatal().Msg("`log_level` is not defined or is empty.")
	}

	MAX_BODY_LEN = config.MaxPacket

	// setup logger.
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	switch {
	case config.LogLevel == "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case config.LogLevel == "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case config.LogLevel == "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case config.LogLevel == "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	return nil
}

func (c *Config) GetAuthorized() map[string]bool {
	if c.UploadDir != "" {
		return c.Authorized
	}

	// disable all the users from uploading..
	auths := map[string]bool{}
	for key, _ := range c.Authorized {
		auths[key] = false
	}
	return auths
}

func (c *Config) GetListeners() (net.Listener, net.Listener) {
	var lraw, ltls net.Listener
	var err error

	if c.RawBind == "" && c.TlsBind == "" {
		log.Fatal().Msg("`bind` and `tls-bind` are not defined or empty.")
	}

	if c.RawBind != "" {
		lraw, err = net.Listen("tcp", c.RawBind)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
	}

	if exists(c.TlsCert) && exists(c.TlsKey) && c.TlsBind != "" {
		cert, err := tls.LoadX509KeyPair(c.TlsCert, c.TlsKey)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
		ltls, err = tls.Listen("tcp", c.TlsBind, tlsConfig)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
	}

	return lraw, ltls
}

func (c *Config) LoadResources() (map[string][]*bbolt.DB, map[string]*bbolt.DB) {
	var resources = map[string][]*bbolt.DB{}
	var shared = map[string]*bbolt.DB{}
	var err error = nil

	if len(c.Resources) < 1 && c.UploadDir == "" {
		log.Fatal().Msg("`resources` is empty or not defined in the config file")
	}

	resources[GENERIC_DB] = []*bbolt.DB{}

	for _, res := range c.Resources {
		key := GENERIC_DB
		res.Arch = sanitizeWord(res.Arch, GENERIC_DB)
		if res.Arch != GENERIC_DB {
			key = fmt.Sprintf("%s|%02d", res.Arch, res.Bits)
		}
		search, ok := resources[key]
		if !ok {
			search = []*bbolt.DB{}
		}

		for _, file := range res.Files {
			dbFile, err := filepath.Abs(file)
			if err != nil {
				log.Fatal().Err(err).Send()
			}

			db, err := OpenDatabase(dbFile)
			if err != nil {
				log.Fatal().Err(err).Send()
			}
			search = append(search, db)
			log.Debug().Msgf("%s : %s", key, dbFile)
		}

		resources[key] = search
	}

	if c.UploadDir != "" {
		c.UploadDir, err = filepath.Abs(c.UploadDir)
		if err != nil {
			log.Fatal().Err(err).Send()
		} else if !exists(c.UploadDir) {
			log.Fatal().Msgf("'%s' does not exists!", c.UploadDir)
		}

		search := resources[GENERIC_DB]
		for key, canUpload := range c.Authorized {
			if !canUpload {
				continue
			}
			dbFile := fmt.Sprintf("%x.db", md5.Sum([]byte(key)))
			dbFile = filepath.Join(c.UploadDir, dbFile)

			db, err := OpenDatabase(dbFile)
			if err != nil {
				log.Fatal().Err(err).Send()
			}

			search = append(search, db)
			shared[key] = db
			log.Info().Msgf("%s : %s", key, dbFile)
		}
		resources[GENERIC_DB] = search
	}

	return resources, shared
}
