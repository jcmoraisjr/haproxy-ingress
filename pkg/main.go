/*
Copyright 2017 The Kubernetes Authors.

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

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"k8s.io/klog/v2"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/launch"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/legacy"
)

func main() {
	if strings.ToUpper(os.Getenv("HAPROXY_INGRESS_RUNTIME")) != "LEGACY" {
		run()
	} else {
		runLegacy()
	}
}

func run() {
	fs := flag.NewFlagSet("HAProxy Ingress", flag.ExitOnError)
	opt := config.NewOptions()
	opt.AddFlags(fs)
	fs.Parse(os.Args[1:])
	cfg, err := config.Create(opt)
	if err != nil {
		log.Fatalf("unable to parse static config: %s\n", err)
	}
	if err := launch.Run(cfg); err != nil {
		log.Fatal(err.Error())
	}
}

func runLegacy() {
	hc := legacy.NewHAProxyController()
	errCh := make(chan error)
	go handleSignal(hc, errCh)
	hc.Start()
	code := 0
	err := <-errCh
	if err != nil {
		klog.Warningf("Error stopping Ingress: %v", err)
		code++
	}
	klog.Infof("Exiting (%v)", code)
	os.Exit(code)
}

func handleSignal(hc *legacy.HAProxyController, err chan error) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	klog.Infof("Shutting down with signal %v", <-sig)
	err <- hc.Stop()
}
