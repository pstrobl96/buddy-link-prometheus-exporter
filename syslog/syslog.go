package syslog

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

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
	debug := true
	channel, server := startSyslogServer(listenUDP)
	log.Debug().Msg("Syslog server started at: " + listenUDP)
	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			var timestamp time.Time
			var output []string
			if debug {
				output = []string{}
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
