// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type MLInfo struct {
	Available    bool   `json:"available"`
	ModelVersion string `json:"model_version,omitempty"`
	IndexVersion string `json:"index_version,omitempty"`
}

type MLResolveRequest struct {
	Program ProgramBundle `json:"program"`
	TopK    int           `json:"topk"`
}

type MLResolveResponse struct {
	CandidateBinaryIDs []string            `json:"candidate_binary_ids,omitempty"`
	Symbols            []SymbolMatchRecord `json:"symbols,omitempty"`
	ModelVersion       string              `json:"model_version,omitempty"`
	IndexVersion       string              `json:"index_version,omitempty"`
}

type MLShareRequest struct {
	Program ProgramBundle `json:"program"`
}

type MLShareResponse struct {
	BinaryID       string `json:"binary_id,omitempty"`
	CandidateCount uint32 `json:"candidate_count"`
	ModelVersion   string `json:"model_version,omitempty"`
	IndexVersion   string `json:"index_version,omitempty"`
}

type MLClient interface {
	Info(ctx context.Context) (MLInfo, error)
	Resolve(ctx context.Context, program ProgramBundle, topK int) (MLResolveResponse, error)
	Share(ctx context.Context, program ProgramBundle) (MLShareResponse, error)
}

type noopMLClient struct{}

func (noopMLClient) Info(context.Context) (MLInfo, error) {
	return MLInfo{}, nil
}

func (noopMLClient) Resolve(context.Context, ProgramBundle, int) (MLResolveResponse, error) {
	return MLResolveResponse{}, nil
}

func (noopMLClient) Share(context.Context, ProgramBundle) (MLShareResponse, error) {
	return MLShareResponse{}, nil
}

type httpMLClient struct {
	baseURL string
	client  *http.Client
}

func NewMLClient(baseURL string, timeout time.Duration) MLClient {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return noopMLClient{}
	}
	if timeout < 1 {
		timeout = 5 * time.Second
	}
	return &httpMLClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *httpMLClient) Info(ctx context.Context) (MLInfo, error) {
	var out MLInfo
	err := c.doJSON(ctx, http.MethodGet, "/healthz", nil, &out)
	return out, err
}

func (c *httpMLClient) Resolve(ctx context.Context, program ProgramBundle, topK int) (MLResolveResponse, error) {
	var out MLResolveResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/resolve", MLResolveRequest{
		Program: program,
		TopK:    topK,
	}, &out)
	return out, err
}

func (c *httpMLClient) Share(ctx context.Context, program ProgramBundle) (MLShareResponse, error) {
	var out MLShareResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/share", MLShareRequest{
		Program: program,
	}, &out)
	return out, err
}

func (c *httpMLClient) doJSON(ctx context.Context, method, path string, in any, out any) error {
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ml service returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
