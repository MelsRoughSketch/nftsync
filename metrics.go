package nftsync

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// updateFailureCount is counter for failed set updates
	updateFailureCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "nftsync",
		Name:      "update_failure_count_total",
		Help:      "It is counter of failure count of updating set.",
	}, []string{"server", "zone", "view", "name"})
)
