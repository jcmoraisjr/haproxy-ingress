/*
Copyright 2024 The HAProxy Ingress Controller Authors.

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

package services

import (
	"context"
	"os"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	eventsv1client "k8s.io/client-go/kubernetes/typed/events/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/tools/record"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/controller/config"
)

func initRecorderProvider(ctx context.Context, cfg *config.Config) (*recorderProvider, error) {
	config := rest.CopyConfig(cfg.KubeConfig)

	cli, err := corev1client.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	httpClient, err := rest.HTTPClientFor(config)
	if err != nil {
		return nil, err
	}

	evCli, err := eventsv1client.NewForConfigAndClient(config, httpClient)
	if err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	return &recorderProvider{
		ctx:        ctx,
		log:        logr.FromContextOrDiscard(ctx).WithName("leader_recorder"),
		scheme:     cfg.Scheme,
		cli:        cli,
		evCli:      evCli,
		namespace:  cfg.ControllerPod.Namespace,
		hostname:   hostname,
		electionID: cfg.ElectionID,
	}, nil
}

type recorderProvider struct {
	ctx        context.Context
	log        logr.Logger
	scheme     *runtime.Scheme
	cli        *corev1client.CoreV1Client
	evCli      *eventsv1client.EventsV1Client
	namespace  string
	hostname   string
	electionID string
}

func (r *recorderProvider) GetEventRecorderFor(name string) record.EventRecorder {
	broadcaster := record.NewBroadcaster()
	_ = broadcaster.StartRecordingToSink(&corev1client.EventSinkImpl{Interface: r.cli.Events(r.namespace)})
	return broadcaster.NewRecorder(r.scheme, corev1.EventSource{
		Component: r.electionID + "_" + name,
		Host:      r.hostname,
	})
}

func (r *recorderProvider) GetEventRecorder(name string) events.EventRecorder {
	broadcaster := events.NewBroadcaster(&events.EventSinkImpl{Interface: r.evCli})
	if err := broadcaster.StartRecordingToSinkWithContext(r.ctx); err != nil {
		r.log.Error(err, "error starting recording for broadcaster")
	}
	return broadcaster.NewRecorder(r.scheme, name)
}
