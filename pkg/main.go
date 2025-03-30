/*
Copyright 2025 The HAProxy Ingress Controller Authors.

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

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/launch"
)

func main() {
	fs := flag.NewFlagSet("HAProxy Ingress", flag.ExitOnError)
	opt := config.NewOptions()
	opt.AddFlags(fs)
	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf("unable to parse command-line arguments: %s\n", err)
	}
	cfg, err := config.Create(opt)
	if err != nil {
		log.Fatalf("unable to parse static config: %s\n", err)
	}
	if err := launch.Run(cfg); err != nil {
		log.Fatal(err.Error())
	}
}
