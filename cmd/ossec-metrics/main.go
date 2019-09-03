package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	addr        = flag.String("listen-address", ":7070", "The address to listen on for HTTP requests.")
	agentsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ossec_metrics",
		Name:      "total_agents",
		Help:      "total number of agents.",
	})
	agentsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ossec_metrics",
		Name:      "active_agents",
		Help:      "total number of active agents.",
	})
)

func main() {
	// Register the summary and the histogram with Prometheus's default registry.
	prometheus.MustRegister(agentsTotal)
	prometheus.MustRegister(agentsActive)

	// Add Go module build info.
	prometheus.MustRegister(prometheus.NewBuildInfoCollector())

	flag.Parse()
	http.Handle("/metrics", promhttp.Handler())

	go checkAgents()

	log.Fatal(http.ListenAndServe(*addr, nil))
}

func checkAgents() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()

	for {
		<-t.C

		cmd := exec.Command("/var/ossec/bin/agent_control", "-ls")
		out, err := cmd.StdoutPipe()

		if err != nil {
			log.Printf("could not get command output: %v", err)
			continue
		}

		if err := cmd.Start(); err != nil {
			log.Println(err)
			continue
		}

		r := csv.NewReader(out)
		total := 0
		active := 0
		for {
			record, err := r.Read()
			if err != nil {
				if err != io.EOF {
					log.Println(err)
				}
				break
			}

			total++
			if len(record) > 3 && strings.HasPrefix(record[3], "Active") {
				active++
			}
		}

		if err := cmd.Wait(); err != nil {
			log.Printf("waiting for command to complete failed: %v", err)
			continue
		}

		agentsTotal.Set(float64(total))
		agentsActive.Set(float64(active))
		fmt.Printf("Found %d active out of %d total agents\n", active, total)
	}
}
