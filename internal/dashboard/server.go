/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package dashboard provides an embedded HTTP server with a dark-themed
// HTMX-powered web UI for the Kube-Diagnose platform.
package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/morarez/kube-diagnose/internal/aggregator"
	"github.com/morarez/kube-diagnose/internal/llm"
)

// Server is the embedded dashboard HTTP server.
type Server struct {
	port          int
	incidentStore *aggregator.IncidentStore
	analyzer      *llm.Analyzer
	logger        *zap.Logger
	mux           *http.ServeMux
}

// NewServer creates a new dashboard Server.
func NewServer(
	port int,
	incidentStore *aggregator.IncidentStore,
	analyzer *llm.Analyzer,
	logger *zap.Logger,
) *Server {
	s := &Server{
		port:          port,
		incidentStore: incidentStore,
		analyzer:      analyzer,
		logger:        logger.With(zap.String("component", "dashboard")),
		mux:           http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// registerRoutes wires all HTTP endpoints.
func (s *Server) registerRoutes() {
	h := &handlers{store: s.incidentStore, analyzer: s.analyzer, logger: s.logger}

	// UI pages
	s.mux.HandleFunc("GET /", h.indexPage)
	s.mux.HandleFunc("GET /incidents", h.incidentsPage)
	s.mux.HandleFunc("GET /incidents/{fingerprint}", h.incidentDetailPage)
	s.mux.HandleFunc("GET /knowledge-base", h.knowledgeBasePage)

	// JSON API
	s.mux.HandleFunc("GET /api/v1/incidents", h.apiListIncidents)
	s.mux.HandleFunc("GET /api/v1/incidents/{fingerprint}", h.apiGetIncident)
	s.mux.HandleFunc("GET /api/v1/stats", h.apiStats)

	// Health endpoints
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
}

// Start launches the HTTP server and blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) {
	addr := fmt.Sprintf(":%d", s.port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      s.mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("dashboard server shutdown error", zap.Error(err))
		}
	}()

	s.logger.Info("dashboard server starting", zap.String("addr", addr))
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.logger.Error("dashboard server error", zap.Error(err))
	}
}
