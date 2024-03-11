package measurements

// Measurement represents a measurement with IP, interval, times, and size.
type Measurement struct {
	ip       string
	interval int
	times    int
	size     float64
}

func saveAsCSV(measurement Measurement) {
	// save measurement as CSV
}

// MeasureLogs measures the size of logs from the syslog server
func MeasureLogs(times int, interval int) Measurement {
	return Measurement{}
}
