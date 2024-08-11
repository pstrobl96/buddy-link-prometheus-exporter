package cmd

import (
	"net/http"
	"strconv"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/pstrobl96/prusa_exporter/syslog"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	syslogTTL            = kingpin.Flag("syslog.ttl", "TTL for syslog metrics in seconds.").Default("60").Int()
	metricsPath          = kingpin.Flag("exporter.metrics-path", "Path where to expose metrics.").Default("/metrics").String()
	metricsPort          = kingpin.Flag("exporter.metrics-port", "Port where to expose metrics.").Default("10010").Int()
	metricsListenAddress = kingpin.Flag("processor.address", "Address where to expose port for gathering metics.").Default("0.0.0.0:1514").String()
	logLevel             = kingpin.Flag("log.level", "Log level for prusa_log_processor.").Default("info").String()
)

// Run function to start the exporter
func Run() {
	kingpin.Parse()
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixNano

	log.Info().Msg("prusa_exporter starting")

	logLevel, err := zerolog.ParseLevel(*logLevel)

	if err != nil {
		logLevel = zerolog.InfoLevel // default log level
	}
	zerolog.SetGlobalLevel(logLevel)

	var collectors []prometheus.Collector

	log.Info().Msg("Syslog metrics server starting at: " + *metricsListenAddress)
	go syslog.HandleMetrics(*metricsListenAddress)
	collectors = append(collectors, syslog.NewCollector(*syslogTTL))

	prometheus.MustRegister(collectors...)
	log.Info().Msg("Metrics registered")
	http.Handle(*metricsPath, promhttp.Handler())
	log.Info().Msg("Listening at port: " + strconv.Itoa(*metricsPort))
	log.Fatal().Msg(http.ListenAndServe(":"+strconv.Itoa(*metricsPort), nil).Error())

}
