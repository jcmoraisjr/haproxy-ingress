/*
Copyright 2019 The HAProxy Ingress Controller Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package acme

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/types"
)

// NewServer ...
func NewServer(logger types.Logger, socket string, resolver ServerResolver) Server {
	return &server{
		logger:   logger,
		socket:   socket,
		resolver: resolver,
	}
}

// ServerResolver ...
type ServerResolver interface {
	GetToken(domain, uri string) string
}

// Server ...
type Server interface {
	Listen(stopCh chan struct{}) error
}

type server struct {
	logger   types.Logger
	resolver ServerResolver
	server   *http.Server
	socket   string
}

func (s *server) Listen(stopCh chan struct{}) error {
	handler := http.NewServeMux()
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		uri := r.URL.Path
		token := s.resolver.GetToken(host, uri)
		if token == "" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "404 not found\n")
			s.logger.Warn("acme: url token not found: domain=%s uri=%s", host, uri)
			return
		}
		fmt.Fprint(w, token)
		s.logger.Info("acme: request token: domain=%s uri=%s", host, uri)
	})
	s.server = &http.Server{Addr: s.socket, Handler: handler}
	if err := os.Remove(s.server.Addr); err != nil && !os.IsNotExist(err) {
		s.logger.Warn("error removing an existent acme socket: %v", err)
	}
	l, err := net.Listen("unix", s.server.Addr)
	if err != nil {
		return err
	}
	if user, err := user.Lookup("haproxy"); err == nil {
		uid, e1 := strconv.Atoi(user.Uid)
		gid, e2 := strconv.Atoi(user.Gid)
		if e1 == nil && e2 == nil {
			if err := os.Chown(s.socket, uid, gid); err != nil {
				return err
			}
			if err := os.Chmod(s.socket, 0600); err != nil {
				return err
			}
		}
	}
	s.logger.Info("acme: listening on unix socket: %s", s.socket)
	go func() {
		_ = s.server.Serve(l)
	}()
	go func() {
		<-stopCh
		if s.server == nil {
			s.logger.Error("acme: cannot close, server is nil")
		}
		s.logger.Info("acme: closing unix socket")
		if err := s.server.Close(); err != nil {
			s.logger.Error("acme: error closing socket: %v", err)
		}
	}()
	return nil
}
