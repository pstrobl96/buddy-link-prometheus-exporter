package measurements

import (
	"fmt"
	"time"
	"unsafe"

	"gopkg.in/mcuadros/go-syslog.v2"
)

var (
	logs = make(map[string][]string)
)

// Measurement represents a measurement with IP, interval, times, and size.
type Measurement struct {
	mac           string
	interval      int
	measurementNo int
	data          []string
	size          int64
}

func saveAsCSV(measurement Measurement) {
	// save measurement as CSV
}

// StartMeasurement starts the measurement
func StartMeasurement() {
	// start measurement
}

// Measure measures the size of logs from the syslog server
func Measure(listenUDP string, duration time.Duration) Measurement {
	logs = make(map[string][]string)
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC5424)
	server.SetHandler(handler)
	server.ListenUDP(listenUDP)
	server.Boot()

	startTime := time.Now()

	go func(channel syslog.LogPartsChannel, duration time.Duration) {
		for logParts := range channel {
			if startTime.Add(duration).Before(time.Now()) {
				fmt.Println(len(logs))
				result := make(map[string]int64)
				for k, _ := range logs {
					if logs[k] == nil {
						logs[k] = []string{}
					}
					for _, v := range logs[k] {
						result[k] += int64(unsafe.Sizeof(v))
					}
				}

				for k, v := range result {
					fmt.Println(k, v)
				}

				server.Kill()
				break
			}

			if logs[logParts["hostname"].(string)] == nil {
				logs[logParts["hostname"].(string)] = []string{}
			}

			logs[logParts["hostname"].(string)] = append(logs[logParts["hostname"].(string)], fmt.Sprintf("%v", logParts))

		}

	}(channel, duration)

	server.Wait()

	return Measurement{}
}
