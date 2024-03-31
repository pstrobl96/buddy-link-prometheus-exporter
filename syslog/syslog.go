package syslog

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/castai/promwrite"
	"github.com/influxdata/influxdb/models"
	"github.com/rs/zerolog/log"
	"gopkg.in/mcuadros/go-syslog.v2"
)

type patterns struct {
	pattern string
	fields  []string
}

var (
	// syslogMetrics is a map of mac addresses and their metrics

	mutex sync.RWMutex

	syslogMetrics = map[string]map[string]map[string]string{} // mac -> metric -> field -> value ; field can be value or label

	// regexpPatterns is a map that stores the regular expression patterns for different types of log messages.
	// Each pattern is associated with a set of named capture groups and corresponding field names.
	regexpPatterns = map[string]patterns{
		"v_integer":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) v=(?P<value>-?\d+)i`, fields: []string{"name", "value"}},
		"float":                  {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) v=(?P<value>[-\d\.]+)`, fields: []string{"name", "value"}},
		"integer":                {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) v=(?P<value>[-\d\.]+)i`, fields: []string{"name", "value"}},
		"string":                 {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) v="(?P<value>.*)"`, fields: []string{"name", "value"}},
		"xyv":                    {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+),v=(?P<value>[-\d\.]+)`, fields: []string{"name", "x", "y", "value"}},
		"free_total":             {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) free=(?P<free>[-\d\.]+)i,total=(?P<total>[-\d\.]+)i`, fields: []string{"name", "free", "total"}},
		"axis_sens_period_speed": {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),axis=(?P<axis>[-\d\.]+) sens=(?P<sens>[-\d\.]+)i,period=(?P<period>[-\d\.]+)i,speed=(?P<speed>[-\d\.]+)`, fields: []string{"name", "axis", "sens", "period", "speed"}},
		"axis_last_total":        {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),axis=(?P<axis>[-\d\.]+) last=(?P<last>[-\d\.]+)i,total=(?P<total>[-\d\.]+)i`, fields: []string{"name", "axis", "last", "total"}},
		"xyz":                    {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+),z=(?P<z>[-\d\.]+)`, fields: []string{"name", "x", "y", "z"}},
		"a_f_x_y_z":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) a=(?P<a>[-\d\.]+),f=(?P<f>[-\d\.]+),x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+),z=(?P<z>[-\d\.]+)`, fields: []string{"name", "a", "f", "x", "y", "z"}},
		"ax_ok_v_n":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),ax=(?P<ax>[-\d\.]+),ok=(?P<ok>[-\d\.]+) v=(?P<v>[-\d\.]+),n=(?P<n>[-\d\.]+)`, fields: []string{"name", "ax", "ok", "value", "n"}},
		"ok_desc":                {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) ok=(?P<ok>[-\d\.]+),desc="(?P<desc>[-\d\.]+)"`, fields: []string{"name", "ok", "desc"}},
		"sent":                   {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) sent=(?P<sent>[-\d\.]+)i`, fields: []string{"name", "sent"}},
		"recv":                   {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) recv=(?P<recv>[-\d\.]+)i`, fields: []string{"name", "recv"}},
		"n_t_m":                  {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) t=(?P<t>[-\d\.]+),m=(?P<m>[-\d\.]+)`, fields: []string{"name", "n", "t", "m"}},
		"n_u":                    {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) u=(?P<u>[-\d\.]+)`, fields: []string{"name", "n", "u"}},
		"n_a_value":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+),a=(?P<a>[-\d\.]+) value=(?P<value>[-\d\.]+)`, fields: []string{"name", "n", "a", "value"}},
		"n_a_value_integer":      {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+),a=(?P<a>[-\d\.]+) value=(?P<value>[-\d\.]+)i`, fields: []string{"name", "n", "a", "value"}},
		"n_st_f_r_ri_sp":         {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) st=(?P<st>[-\d\.]+),f=(?P<f>[-\d\.]+),r=(?P<r>[-\d\.]+),ri=(?P<ri>[-\d\.]+),sp=(?P<sp>[-\d\.]+)`, fields: []string{"name", "n", "st", "f", "r", "ri", "sp"}},
		"n_v_integer":            {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) v=(?P<v>[-\d\.]+)i`, fields: []string{"name", "n", "value"}},
		"xy":                     {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+)`, fields: []string{"name", "x", "y"}},
		"as_fe_rs_ae":            {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) as=(?P<as>[-\d\.]+),fe=(?P<fe>[-\d\.]+),rs=(?P<rs>[-\d\.]+),ae=(?P<ae>[-\d\.]+)`, fields: []string{"name", "as", "fe", "rs", "ae"}},
		"ax_reg_regn_value":      {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),ax=(?P<ax>[-\d\.]+) reg=(?P<reg>[-\d\.]+),regn="(?P<regn>[-\d\.]+)",value=(?P<value>[-\d\.]+)i`, fields: []string{"name", "ax", "reg", "regn", "value"}},
		"fan_state_pwm_measured": {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),fan=(?P<fan>[-\d\.]+) state=(?P<state>[-\d\.]+),pwm=(?P<pwm>[-\d\.]+),measured=(?P<measured>[-\d\.]+)`, fields: []string{"name", "fan", "state", "pwm", "measured"}},
		"t_p_a_x_y":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),t=(?P<t>[-\d\.]+),p=(?P<p>[-\d\.]+),a=(?P<a>[-\d\.]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+)`, fields: []string{"name", "t", "p", "a", "x", "y"}},
		"t_p_x_y_z":              {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),t=(?P<t>[-\d\.]+),p=(?P<p>[-\d\.]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+),z=(?P<z>[-\d\.]+)`, fields: []string{"name", "t", "p", "x", "y", "z"}},
		"t_x_y_z":                {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),t=(?P<t>[-\d\.]+) x=(?P<x>[-\d\.]+),y=(?P<y>[-\d\.]+),z=(?P<z>[-\d\.]+)`, fields: []string{"name", "t", "x", "y", "z"}},
		"n_v":                    {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) v=(?P<v>[-\d\.]+)`, fields: []string{"name", "n", "value"}},
		"n_v_e_integer":          {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) v=(?P<v>[-\d\.]+)i,e=(?P<e>[-\d\.]+)i`, fields: []string{"name", "n", "value", "e"}},
		"n_p_i_d_tc":             {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) p=(?P<p>[-\d\.]+),i=(?P<i>[-\d\.]+),d=(?P<d>[-\d\.]+),tc=(?P<tc>[-\d\.]+)`, fields: []string{"name", "n", "p", "i", "d", "tc"}},
		"n_v_e":                  {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+),n=(?P<n>[-\d\.]+) v=(?P<v>[-\d\.]+),e=(?P<e>[-\d\.]+)`, fields: []string{"name", "n", "value", "e"}},
		"r_o_s":                  {pattern: `(?P<name>\w+[0-9]*[a-zA-Z]+) r=(?P<r>[-\d\.]+)i,o=(?P<o>[-\d\.]+)i,s=(?P<s>[-\d\.]+)`, fields: []string{"name", "r", "o", "s"}},
	}
)

// startSyslogServer is a function that starts a syslog server and returns a channel to receive log parts and the server instance.
// The syslog server listens for UDP connections on the specified address.
// It uses the RFC5424 format for log messages.
// The log parts are sent to the provided channel for further processing.
func startSyslogServer(listenUDP string) (syslog.LogPartsChannel, *syslog.Server) {
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC5424)
	server.SetHandler(handler)
	server.ListenUDP(listenUDP)
	server.Boot()
	return channel, server
}

// HandleMetrics is function that listens for syslog messages and parses them into map
func HandleMetrics(listenUDP string) {
	channel, server := startSyslogServer(listenUDP)
	log.Debug().Msg("Syslog server started at: " + listenUDP)
	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			var timestamp time.Time
			var output []string
			timestamp = time.Now().UTC()
			timestampUnix := timestamp.UnixNano()
			mac := logParts["hostname"].(string)
			if mac == "" {
				continue
			}
			ip := logParts["client"].(string)
			facility := logParts["facility"].(int)
			severity := logParts["severity"].(int)
			appName := logParts["app_name"].(string)
			if appName == "" {
				appName = "unknown"
			}
			procID := logParts["proc_id"].(string)
			if procID == "" {
				procID = "unknown"
			}
			msgID := logParts["msg_id"].(string)
			if msgID == "" {
				msgID = "unknown"
			}
			message := logParts["message"].(string)
			if message == "" {
				message = "unknown"
			}
			priority := logParts["priority"].(int)
			structuredData := logParts["structured_data"].(string)
			if structuredData == "" {
				structuredData = "unknown"
			}
			version := logParts["version"].(int)
			tlsPeer := logParts["tls_peer"].(string)
			if tlsPeer == "" {
				tlsPeer = "unknown"
			}

			if remoteWriteInflux {
				output = []string{}
				log.Info().Msg("Received message from: " + mac)
				var splittedMessage []string
				if strings.Contains(message, "\n") {
					splittedMessage = strings.Split(logParts["message"].(string), "\n")
				} else {
					splittedMessage = []string{logParts["message"].(string)}
				}

				for _, message := range splittedMessage {
					line := strings.Split(message, " ")
					length := len(line)
					pos := 0
					if strings.Contains(line[pos], "msg") { // getting rid of msg metrics
						line[0] = ""
						pos = 1
					}

					line[pos] = strings.Join([]string{"prusa_" + line[0], "ip=" + ip, "facility=" + strconv.Itoa(facility), "severity=" + strconv.Itoa(severity),
						"app_name=" + appName, "proc_id=" + procID, "msg_id=" + msgID, "priority=" + strconv.Itoa(priority), "structured_data=" + structuredData,
						"version=" + strconv.Itoa(version), "tls_peer=" + tlsPeer, "mac=" + mac}, ",")
					time, _ := strconv.ParseInt(line[length-1], 10, 64)
					line[length-1] = strconv.FormatInt(timestampUnix-(time*1000), 10)
					output = append(output, strings.Join(line, " "))
					//fmt.Println(line[length-1])
				}

				url := "http://influxproxy:8007/api/v1/push/influx/write"
				for _, line := range output {
					fmt.Println(line)
					body := strings.NewReader(line)
					req, err := http.NewRequest("POST", url, body)
					if err != nil {
						log.Error().Msg("Error creating request: " + err.Error())
						continue
					}
					req.Header.Set("Content-Type", "application/json")

					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						log.Error().Msg("Error sending request: " + err.Error())
						continue
					}

					//log.Debug().Msg("Sent message to InfluxProxy: " + line)
					defer resp.Body.Close()
				}

			} else if !remoteWriteInflux {
				var splittedMessage []string
				if strings.Contains(message, "\n") {
					splittedMessage = strings.Split(logParts["message"].(string), "\n")
				} else {
					splittedMessage = []string{logParts["message"].(string)}
				}

				for _, message := range splittedMessage {
					line := strings.Split(message, " ")
					length := len(line)
					pos := 0
					if strings.Contains(line[pos], "msg") { // getting rid of msg metrics
						line[0] = ""
						pos = 1
					}

					line[pos] = "prusa_" + line[pos]
					timestamp, _ := strconv.ParseInt(line[length-1], 10, 64)
					line[length-1] = strconv.FormatInt(timestampUnix-(timestamp*1000), 10)
					//fmt.Println(strings.Join(line, " "))
					points, _ := models.ParsePointsString(strings.Join(line, " "))

					fmt.Printf("tags: %v\n", points[0].Tags())
					client := promwrite.NewClient("http://mimir:9009/api/v1/push")

					fields, err := points[0].Fields()

					if err != nil {
						fmt.Println("Error getting fields:", err)
						continue
					}
					for k, v := range fields {
						labels := []promwrite.Label{
							{
								Name:  "__name__",
								Value: "prusa_" + string(points[0].Name()) + "_" + k,
							},
						}

						for _, v := range points[0].Tags() {
							labels = append(labels, promwrite.Label{
								Name:  string(v.Key),
								Value: string(v.Value),
							})
						}

						_, err := client.Write(context.Background(), &promwrite.WriteRequest{
							TimeSeries: []promwrite.TimeSeries{
								{
									Labels: labels,
									Sample: promwrite.Sample{
										Time:  time.Unix(timestampUnix-(timestamp), 0),
										Value: 123,
									},
								},
							},
						})
						if err != nil {
							fmt.Println("Error writing points:", err)
							continue
						}
						fmt.Println(k, v)
					}

				}

			} else {

				mac := logParts["hostname"].(string)
				if mac == "" { // Skip empty mac addresses
					continue
				} else {
					mutex.Lock()
					loadedPart := syslogMetrics[mac]

					if loadedPart == nil {
						loadedPart = make(map[string]map[string]string) // if found but empty, create a new map, at start it will be empty everytime
					}

					if loadedPart["ip"] == nil {
						loadedPart["ip"] = make(map[string]string)
					}

					if loadedPart["timestamp"] == nil {
						loadedPart["timestamp"] = make(map[string]string)
					}

					loadedPart["ip"]["value"] = logParts["client"].(string)
					loadedPart["timestamp"]["value"] = time.Now().Format(time.RFC3339Nano)

					log.Trace().Msg("Received message from: " + mac)

					message := logParts["message"].(string)

					var splittedMessage []string

					if strings.Contains(message, "\n") {
						splittedMessage = strings.Split(logParts["message"].(string), "\n")
					} else {
						splittedMessage = []string{logParts["message"].(string)}
					}

					for _, message := range splittedMessage {
						for name, pattern := range regexpPatterns {

							reg, err := regexp.Compile(pattern.pattern)
							if err != nil {
								log.Error().Msg("Error compiling regexp: " + err.Error())
								continue
							}

							log.Trace().Msg("Matching pattern: " + name + " for message: " + message)

							matches := reg.FindAllStringSubmatch(message, -1)
							if matches == nil {
								continue // No matches for this pattern
							}
							var metricName string

							for _, match := range matches {
								// Extract values based on named groups

								suffix := ""

								for i, field := range pattern.fields {
									if field == "n" {
										suffix = "_" + match[i+1]
									}
								}

								for i, field := range pattern.fields {
									if field == "name" {
										metricName = match[i+1] + suffix
									} else if match[i+1] != "" && field != "timestamp" { // todo - check if timestamp is needed
										if loadedPart[metricName] == nil {
											loadedPart[metricName] = make(map[string]string)
										}
										loadedPart[metricName][field] = match[i+1]
									}
								}
							}
						}
					}

					syslogMetrics[mac] = loadedPart

					mutex.Unlock()
				}
			}
		}
	}(channel)

	server.Wait()
}

// Metric represents a single data point
type Metric struct {
	Measurement string
	Tags        map[string]string
	Fields      map[string]float64 // Assuming numerical fields
	Timestamp   int64              // Optional timestamp (unix epoch in milliseconds)
}

func parseInfluxLine(line string) (*Metric, error) {
	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid line format: %s", line)
	}

	metric := &Metric{
		Tags:   make(map[string]string),
		Fields: make(map[string]float64),
	}

	// Parse measurement
	metric.Measurement = parts[0]

	// Parse tags
	for _, tag := range parts[1 : len(parts)-1] {
		keyVal := strings.Split(tag, "=")
		if len(keyVal) != 2 {
			return nil, fmt.Errorf("invalid tag format: %s", tag)
		}
		metric.Tags[keyVal[0]] = keyVal[1]
	}

	// Parse fields
	fieldPart := parts[len(parts)-1]
	fieldPairs := strings.Split(fieldPart, " ")
	for _, fieldPair := range fieldPairs {
		keyVal := strings.Split(fieldPair, "=")
		if len(keyVal) != 2 {
			return nil, fmt.Errorf("invalid field format: %s", fieldPair)
		}
		value, err := strconv.ParseFloat(keyVal[1], 64) // Assuming numerical fields
		if err != nil {
			return nil, fmt.Errorf("invalid field value: %s", keyVal[1])
		}
		metric.Fields[keyVal[0]] = value
	}

	// Parse timestamp (optional)
	if strings.Contains(fieldPart, " ") {
		timestampStr := strings.TrimPrefix(fieldPart, strings.Split(fieldPart, " ")[0]+" ")
		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp format: %s", timestampStr)
		}
		metric.Timestamp = timestamp
	}

	return metric, nil
}
