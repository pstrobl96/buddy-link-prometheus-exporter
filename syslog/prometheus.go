package syslog

import (
	"log"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

func getLabels(mac string, ip string, labels []string, labelValues ...string) []string {
	labelValues = append(labelValues, labels...)
	return append([]string{mac, ip}, labelValues...)
}

func getNumberOf(s string) (int, string, error) {
	splitted := strings.Split(s, "_")
	if len(splitted) == 0 {
		return 0, s, nil
	}
	indexOfLast := len(splitted) - 1

	if num, err := strconv.Atoi(splitted[indexOfLast]); err == nil {
		return num, strings.Join(splitted[:indexOfLast], "_"), nil
	}

	return -1, s, nil
}

// Collector is a struct that defines all the syslog metrics
type Collector struct {
	printerActiveExtruder        *prometheus.Desc
	printerAppStart              *prometheus.Desc
	printerAxisZAdjustment       *prometheus.Desc
	printerBedletRegulationD     *prometheus.Desc // bedlet_regulation_d
	printerBedletRegulationI     *prometheus.Desc // bedlet_regulation_i
	printerBedletRegulationP     *prometheus.Desc // bedlet_regulation_p
	printerBedletRegulationTc    *prometheus.Desc // bedlet_regulation_tc
	printerBedletState           *prometheus.Desc // bedlet_state
	printerBedState              *prometheus.Desc
	printerBuddyBom              *prometheus.Desc
	printerBuddyRevision         *prometheus.Desc
	printerBuddyFW               *prometheus.Desc
	printerCPUUsage              *prometheus.Desc
	printerCrashSpeed            *prometheus.Desc
	printerCrashLength           *prometheus.Desc
	printerCrashStat             *prometheus.Desc
	printerCurrent               *prometheus.Desc
	printerCurrentRaw            *prometheus.Desc
	printerDwarfFastRefreshDelay *prometheus.Desc
	printerDwarfParkedRaw        *prometheus.Desc
	printerDwarfPickedRaw        *prometheus.Desc
	printerEeepromWrite          *prometheus.Desc
	printerExciteFreq            *prometheus.Desc
	printerFanActive             *prometheus.Desc
	printerFanSpeed              *prometheus.Desc
	printerFilename              *prometheus.Desc
	printerFilament              *prometheus.Desc
	printerFSensor               *prometheus.Desc
	printerFSensorRaw            *prometheus.Desc
	printerFreqGain              *prometheus.Desc
	printerG425Cen               *prometheus.Desc
	printerG425Offset            *prometheus.Desc
	printerG425Rxy               *prometheus.Desc
	printerG425Rz                *prometheus.Desc
	printerG425Xy                *prometheus.Desc
	printerG425XyDev             *prometheus.Desc
	printerG425Z                 *prometheus.Desc
	printerGcode                 *prometheus.Desc
	printerGuiLoopDuration       *prometheus.Desc
	printerHeapFree              *prometheus.Desc
	printerHeapTotal             *prometheus.Desc
	printerHeaterEnabled         *prometheus.Desc
	printerHomeDiffOk            *prometheus.Desc
	printerHomeDiff              *prometheus.Desc
	printerIpos                  *prometheus.Desc
	printerLoadcellAge           *prometheus.Desc
	printerLoadcellHp            *prometheus.Desc
	printerLoadcellHysteresis    *prometheus.Desc
	printerLoadcellScale         *prometheus.Desc
	printerLoadcellThreshold     *prometheus.Desc
	printerLoadcellThresholdCont *prometheus.Desc
	printerLoadcellValue         *prometheus.Desc
	printerLoadcellValueRaw      *prometheus.Desc
	printerLoadcellXY            *prometheus.Desc
	printerMaintaskLoop          *prometheus.Desc
	printerMediaPrefetched       *prometheus.Desc
	printerMMUComm               *prometheus.Desc
	printerModbusReqfail         *prometheus.Desc
	printerNetworkIn             *prometheus.Desc
	printerNetworkOut            *prometheus.Desc
	printerOvercurrent           *prometheus.Desc
	printerPointsDropped         *prometheus.Desc
	printerPos                   *prometheus.Desc
	printerPowerPanicCount       *prometheus.Desc
	printerPrinting              *prometheus.Desc
	printerProbeAnalysis         *prometheus.Desc
	printerProbeWindowStart      *prometheus.Desc
	printerProbeWindowFallEnd    *prometheus.Desc
	printerProbeWindowRiseStart  *prometheus.Desc
	printerProbeWindowEnd        *prometheus.Desc
	printerProbeStart            *prometheus.Desc
	printerProbeZ                *prometheus.Desc // probe_z
	printerProbeZDiff            *prometheus.Desc
	printerPwm                   *prometheus.Desc
	printerSideFSensor           *prometheus.Desc // side_fsensor
	printerSideFSensorRaw        *prometheus.Desc
	printerSyslogInfo            *prometheus.Desc // revision, bom
	printerTmcRead               *prometheus.Desc
	printerTmcSg                 *prometheus.Desc
	printerTmcWrite              *prometheus.Desc
	printerTKAcceleration        *prometheus.Desc
	printerTemp                  *prometheus.Desc
	printerTempTarget            *prometheus.Desc
	printerUsbhErrCount          *prometheus.Desc
	printerVoltage               *prometheus.Desc
	printerVoltageRaw            *prometheus.Desc
	printerXyDev                 *prometheus.Desc
	prusaBuddyTimeUs             *prometheus.Desc
	prusaPuppyTimeUs             *prometheus.Desc
	prusaSyncRoundtripUs         *prometheus.Desc
	prusaPuppyOffsetUs           *prometheus.Desc
	prusaPuppyDriftPpb           *prometheus.Desc
	prusaPuppyAverageOffsetUs    *prometheus.Desc
	prusaPuppyAverageDriftPpb    *prometheus.Desc
	printerSyslogUp              *prometheus.Desc
	printerPrintFilename         *prometheus.Desc
}

// NewCollector is a function that returns new Collector
// NewCollector creates a new instance of the Collector struct with the provided configuration.
// It initializes all the Prometheus metrics used for monitoring different aspects of the printer.
// The defaultLabels parameter is a list of labels that will be included in all the metrics.
// Returns a pointer to the created Collector.
func NewCollector(syslogTTL int, format string, endpoint string) *Collector {
	defaultLabels := []string{"mac", "ip"}
	if syslogTTL < 1 {
		log.Panic("syslog TTL must be greater than 0")
	}
	ttl = syslogTTL
	remoteWriteFormat = format
	remoteWriteEndpoint = endpoint
	return &Collector{
		printerActiveExtruder:        prometheus.NewDesc("prusa_active_extruder", "Active extruder - used for XL", defaultLabels, nil),
		printerAppStart:              prometheus.NewDesc("prusa_app_start", "Application start", defaultLabels, nil),
		printerAxisZAdjustment:       prometheus.NewDesc("prusa_axis_z_adjustment", "Axis Z adjustment", defaultLabels, nil),
		printerBedletRegulationD:     prometheus.NewDesc("prusa_bedlet_regulation_d", "Bedlet regulation d value", append(defaultLabels, "bedlet"), nil),
		printerBedletRegulationI:     prometheus.NewDesc("prusa_bedlet_regulation_i", "Bedlet regulation i value", append(defaultLabels, "bedlet"), nil),
		printerBedletRegulationP:     prometheus.NewDesc("prusa_bedlet_regulation_p", "Bedlet regulation p value", append(defaultLabels, "bedlet"), nil),
		printerBedletRegulationTc:    prometheus.NewDesc("prusa_bedlet_regulation_tc", "Bedlet regulation tc value", append(defaultLabels, "bedlet"), nil),
		printerBedletState:           prometheus.NewDesc("prusa_bedlet_state", "Bedlet state", append(defaultLabels, "bedlet"), nil),
		printerBedState:              prometheus.NewDesc("prusa_bed_state", "Bed state", defaultLabels, nil),
		printerBuddyBom:              prometheus.NewDesc("prusa_buddy_bom", "Buddy bom", defaultLabels, nil),
		printerBuddyRevision:         prometheus.NewDesc("prusa_buddy_revision", "Buddy revision", defaultLabels, nil),
		printerBuddyFW:               prometheus.NewDesc("prusa_buddy_fw", "Buddy firmware version", append(defaultLabels, "version"), nil),
		printerCPUUsage:              prometheus.NewDesc("prusa_cpu_usage_ratio", "CPU usage from 0.0 to 1.0", defaultLabels, nil),
		printerCrashSpeed:            prometheus.NewDesc("prusa_crash_speed", "Crash Speed", append(defaultLabels, "axis", "sens", "period"), nil),
		printerCrashLength:           prometheus.NewDesc("prusa_crash_length", "Crash length", append(defaultLabels, "x", "y"), nil),
		printerCrashStat:             prometheus.NewDesc("prusa_crash_stat", "Crash statistics", append(defaultLabels, "axis"), nil),
		printerCurrent:               prometheus.NewDesc("prusa_current", "Current of different devices in / on the printer in miliampers", append(defaultLabels, "rail", "device"), nil),
		printerCurrentRaw:            prometheus.NewDesc("prusa_current_raw", "Current of different devices in / on the printer in raw sensor value", append(defaultLabels, "rail", "device"), nil),
		printerDwarfFastRefreshDelay: prometheus.NewDesc("prusa_dwarf_fast_refresh_delay", "Dwarf fast refresh delay", defaultLabels, nil),
		printerDwarfParkedRaw:        prometheus.NewDesc("prusa_dwarf_parked_raw", "Dwarf parked raw sensor value", append(defaultLabels, "tool"), nil),
		printerDwarfPickedRaw:        prometheus.NewDesc("prusa_dwarf_picked_raw", "Dwarf picked raw sensor value", append(defaultLabels, "tool"), nil),
		printerEeepromWrite:          prometheus.NewDesc("prusa_eeeprom_write", "Eeeprom write", defaultLabels, nil),
		printerExciteFreq:            prometheus.NewDesc("prusa_excite_freq", "Excite frequency", defaultLabels, nil),
		printerFanActive:             prometheus.NewDesc("prusa_fan_active", "Fan active", append(defaultLabels, "fan"), nil),
		printerFanSpeed:              prometheus.NewDesc("prusa_fan_speed_ratio", "Fan", append(defaultLabels, "fan"), nil),
		printerFilename:              prometheus.NewDesc("prusa_filename", "Name of printed (b)gcode", append(defaultLabels, "file"), nil),
		printerFilament:              prometheus.NewDesc("prusa_filament", "Name of printed (b)gcode", append(defaultLabels, "filament"), nil),
		printerFSensor:               prometheus.NewDesc("prusa_fsensor", "Filament Sensor", defaultLabels, nil),
		printerFSensorRaw:            prometheus.NewDesc("prusa_fsensor_raw", "Filament Sensor - raw sensor value", append(defaultLabels, "sensor"), nil),
		printerFreqGain:              prometheus.NewDesc("prusa_freq_gain", "Frequency gain", defaultLabels, nil),
		printerG425Cen:               prometheus.NewDesc("prusa_g425_cen", "Absolute tool center - an input for offset computation [mm]", append(defaultLabels, "t", "x", "y", "z"), nil),   // ",t=%u x=%.3f,y=%.3f,z=%.3f"
		printerG425Offset:            prometheus.NewDesc("prusa_g425_off", "Offset from the absolute tool center [mm]", append(defaultLabels, "t", "x", "y", "z"), nil),                     //  ",t=%u x=%.3f,y=%.3f,z=%.3f",
		printerG425Rxy:               prometheus.NewDesc("prusa_g425_rxy", "Raw XY probe [mm]", append(defaultLabels, "t", "p", "a", "x", "y"), nil),                                        // ",t=%u,p=%u,a=%.3f x=%.3f,y=%.3f"
		printerG425Rz:                prometheus.NewDesc("prusa_g425_rz", "Raw Z probe [mm]", append(defaultLabels, "t", "p", "x", "y", "z"), nil),                                          // ",t=%u,p=%u x=%.3f,y=%.3f,z=%.3f",
		printerG425Xy:                prometheus.NewDesc("prusa_g425_xy", "Verified XY probe - two raw probes agree on position [mm]", append(defaultLabels, "t", "p", "a", "x", "y"), nil), // ",t=%u,p=%u,a=%.3f x=%.3f,y=%.3f"
		printerG425XyDev:             prometheus.NewDesc("prusa_g425_xy_dev", "Max deviation", defaultLabels, nil),                                                                          // ",t=%u,p=%u,x=%.3f,y=%.3f z=%.3f",
		printerG425Z:                 prometheus.NewDesc("prusa_g425_z", "Averaged Z probe - N raw probes averaged [mm]", append(defaultLabels, "t", "p", "x", "y", "z"), nil),              // ",t=%u,p=%u,x=%.3f,y=%.3f z=%.3f",
		printerGcode:                 prometheus.NewDesc("prusa_gcode", "Printed GCode", append(defaultLabels, "gcode"), nil),
		printerGuiLoopDuration:       prometheus.NewDesc("prusa_gui_loop_duration", "Gui loop duration", defaultLabels, nil),
		printerHeapFree:              prometheus.NewDesc("prusa_heap_free", "Free heap", defaultLabels, nil),
		printerHeapTotal:             prometheus.NewDesc("prusa_heap_total", "Total heap", defaultLabels, nil),
		printerHeaterEnabled:         prometheus.NewDesc("prusa_heater_enabled", "Heater enabled", defaultLabels, nil),
		printerHomeDiffOk:            prometheus.NewDesc("prusa_home_diff_ok", "Home diff ok", append(defaultLabels, "axis", "attempts"), nil),
		printerHomeDiff:              prometheus.NewDesc("prusa_home_diff", "Home diff value", append(defaultLabels, "axis", "attempts"), nil),
		printerIpos:                  prometheus.NewDesc("prusa_stepper_ipos", "Stepper possition from startup", append(defaultLabels, "axis"), nil),
		printerLoadcellAge:           prometheus.NewDesc("prusa_loadcell_age", "Loadcell age", defaultLabels, nil),
		printerLoadcellHysteresis:    prometheus.NewDesc("prusa_loadcell_hysteresis", "Loadcell hysteresis", defaultLabels, nil),
		printerLoadcellHp:            prometheus.NewDesc("prusa_loadcell_hp", "Loadcell filtered z load", defaultLabels, nil),
		printerLoadcellScale:         prometheus.NewDesc("prusa_loadcell_scale", "Loadcell scale", defaultLabels, nil),
		printerLoadcellThreshold:     prometheus.NewDesc("prusa_loadcell_threshold", "Loadcell threshold", defaultLabels, nil),
		printerLoadcellThresholdCont: prometheus.NewDesc("prusa_loadcell_threshold_cont", "Loadcell threshold continuous", defaultLabels, nil),
		printerLoadcellValue:         prometheus.NewDesc("prusa_loadcell", "Value from loadcell sensor", defaultLabels, nil),
		printerLoadcellValueRaw:      prometheus.NewDesc("prusa_loadcell_raw", "Value from loadcell sensor in raw sensor value", defaultLabels, nil),
		printerLoadcellXY:            prometheus.NewDesc("prusa_loadcell_xy", "Loadcell XY", defaultLabels, nil),
		printerMaintaskLoop:          prometheus.NewDesc("prusa_maintask_loop", "Maintask loop", defaultLabels, nil),
		printerMediaPrefetched:       prometheus.NewDesc("prusa_media_prefetched_bytes", "Media prefetched in bytes", defaultLabels, nil),
		printerMMUComm:               prometheus.NewDesc("prusa_mmu_comm", "MMU communication", append(defaultLabels, "msg"), nil),
		printerModbusReqfail:         prometheus.NewDesc("prusa_modbus_reqfail", "Modbus request fail", defaultLabels, nil),
		printerNetworkIn:             prometheus.NewDesc("prusa_network_in_total", "Network in", append(defaultLabels, "device"), nil),
		printerNetworkOut:            prometheus.NewDesc("prusa_network_out_total", "Network out", append(defaultLabels, "device"), nil),
		printerOvercurrent:           prometheus.NewDesc("prusa_overcurrent", "Overcurrent of different devices in / on the printer", append(defaultLabels, "device"), nil),
		printerPrinting:              prometheus.NewDesc("prusa_printing", "Printing printer", defaultLabels, nil),
		printerPointsDropped:         prometheus.NewDesc("prusa_points_dropped", "Points dropped", defaultLabels, nil),
		printerPos:                   prometheus.NewDesc("prusa_stepper_pos", "Stepper possition", append(defaultLabels, "axis"), nil),
		printerPowerPanicCount:       prometheus.NewDesc("prusa_power_panic_count", "Power panic triggered", defaultLabels, nil),
		printerProbeAnalysis:         prometheus.NewDesc("prusa_probe_analysis", "Probe analysis", append(defaultLabels, "desc"), nil),
		printerProbeWindowStart:      prometheus.NewDesc("prusa_probe_window_start", "Probe window analysis start", defaultLabels, nil),
		printerProbeWindowFallEnd:    prometheus.NewDesc("prusa_probe_window_fall_end", "Probe window fall ended", defaultLabels, nil),
		printerProbeWindowRiseStart:  prometheus.NewDesc("prusa_probe_window_rise_start", "Probe window rise start", defaultLabels, nil),
		printerProbeWindowEnd:        prometheus.NewDesc("prusa_probe_window_analysis_end", "Probe window analysis", defaultLabels, nil),
		printerProbeStart:            prometheus.NewDesc("prusa_probe_start", "Probe start", defaultLabels, nil),
		printerProbeZ:                prometheus.NewDesc("prusa_probe_z", "Probe Z", append(defaultLabels, "x", "y"), nil),
		printerProbeZDiff:            prometheus.NewDesc("prusa_probe_z_diff", "Probe Z difference", defaultLabels, nil),
		printerPwm:                   prometheus.NewDesc("prusa_pwm", "PWM value of nozzle and bed mostly", append(defaultLabels, "device"), nil),
		printerSideFSensor:           prometheus.NewDesc("prusa_side_fsensor", "Side Filament Sensor", defaultLabels, nil),
		printerSideFSensorRaw:        prometheus.NewDesc("prusa_side_fsensor_raw", "Side Filament Sensor - raw sensor value", append(defaultLabels, "sensor"), nil),
		printerSyslogInfo:            prometheus.NewDesc("prusa_syslog_info", "Buddy syslog info", append(defaultLabels, "revision", "bom"), nil),
		printerTmcRead:               prometheus.NewDesc("prusa_tmc_read", "Trinamic read", append(defaultLabels, "axis", "reg_addr", "reg_addr_name"), nil), //     metric_record_custom(&metric_read, ",ax=%c reg=%ui,regn=\"%s\",value=%ui",
		printerTmcSg:                 prometheus.NewDesc("prusa_tmc_sg", "Trinamic SG", append(defaultLabels, "axis"), nil),
		printerTmcWrite:              prometheus.NewDesc("prusa_tmc_write", "Trinamic write", append(defaultLabels, "axis", "reg_addr", "reg_addr_name"), nil),
		printerTKAcceleration:        prometheus.NewDesc("prusa_tk_acceleration", "TK acceleration", defaultLabels, nil),
		printerTemp:                  prometheus.NewDesc("prusa_temp", "Temperature of different devices in / on the printer", append(defaultLabels, "device"), nil),
		printerTempTarget:            prometheus.NewDesc("prusa_temp_target", "Target temperature of different devices in / on the printer", append(defaultLabels, "device"), nil),
		printerUsbhErrCount:          prometheus.NewDesc("prusa_usbh_err_count", "USBH error counter", defaultLabels, nil),
		printerVoltage:               prometheus.NewDesc("prusa_voltage", "Voltage of different devices in / on the printer", append(defaultLabels, "rail", "device"), nil),
		printerVoltageRaw:            prometheus.NewDesc("prusa_voltage_raw", "Voltage of different devices in / on the printer in raw sensor value", append(defaultLabels, "rail", "device"), nil),
		printerXyDev:                 prometheus.NewDesc("prusa_xy_dev", "XY deviation - max difference between two raw probes [mm]", defaultLabels, nil),
		prusaBuddyTimeUs:             prometheus.NewDesc("prusa_buddy_time_ms", "Buddy time in microseconds", defaultLabels, nil),
		prusaPuppyTimeUs:             prometheus.NewDesc("prusa_puppy_time_ms", "Puppy time in microseconds", defaultLabels, nil),
		prusaSyncRoundtripUs:         prometheus.NewDesc("prusa_sync_roundtrip_ms", "Sync roundtrip in microseconds", defaultLabels, nil),
		prusaPuppyOffsetUs:           prometheus.NewDesc("prusa_puppy_offset_ms", "Puppy offset in microseconds", defaultLabels, nil),
		prusaPuppyDriftPpb:           prometheus.NewDesc("prusa_puppy_drift_ppb", "Puppy drift in ppb", defaultLabels, nil),
		prusaPuppyAverageOffsetUs:    prometheus.NewDesc("prusa_puppy_average_offset_ms", "Puppy average offset in microseconds", defaultLabels, nil),
		prusaPuppyAverageDriftPpb:    prometheus.NewDesc("prusa_puppy_average_drift_ppb", "Puppy average drift in ppb", defaultLabels, nil),
		printerSyslogUp:              prometheus.NewDesc("prusa_up_syslog", "Printer up - from syslog metric - ttl is by default 60 seconds but can be different and it depends on choosen interval. That means if printer wont sent any data for 60 seconds is considered down.", defaultLabels, nil),
		printerPrintFilename:         prometheus.NewDesc("prusa_print_filename", "Printed file name", append(defaultLabels, "filename"), nil),
	}
}

// Describe is a function that describes all the metrics
func (collector *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.printerActiveExtruder
	ch <- collector.printerAppStart
	ch <- collector.printerAxisZAdjustment
	ch <- collector.printerBedletRegulationD
	ch <- collector.printerBedletRegulationI
	ch <- collector.printerBedletRegulationP
	ch <- collector.printerBedletRegulationTc
	ch <- collector.printerBedletState
	ch <- collector.printerBedState
	ch <- collector.printerBuddyBom
	ch <- collector.printerBuddyRevision
	ch <- collector.printerBuddyFW
	ch <- collector.printerCPUUsage
	ch <- collector.printerCrashSpeed
	ch <- collector.printerCrashLength
	ch <- collector.printerCrashStat
	ch <- collector.printerCurrent
	ch <- collector.printerCurrentRaw
	ch <- collector.printerDwarfFastRefreshDelay
	ch <- collector.printerDwarfParkedRaw
	ch <- collector.printerDwarfPickedRaw
	ch <- collector.printerEeepromWrite
	ch <- collector.printerExciteFreq
	ch <- collector.printerFanActive
	ch <- collector.printerFanSpeed
	ch <- collector.printerFilament
	ch <- collector.printerFilename
	ch <- collector.printerFSensor
	ch <- collector.printerFSensorRaw
	ch <- collector.printerFreqGain
	ch <- collector.printerG425Cen
	ch <- collector.printerG425Offset
	ch <- collector.printerG425Rxy
	ch <- collector.printerG425Rz
	ch <- collector.printerG425Xy
	ch <- collector.printerG425Z
	ch <- collector.printerGcode
	ch <- collector.printerGuiLoopDuration
	ch <- collector.printerHeapFree
	ch <- collector.printerHeapTotal
	ch <- collector.printerHeaterEnabled
	ch <- collector.printerHomeDiffOk
	ch <- collector.printerHomeDiff
	ch <- collector.printerIpos
	ch <- collector.printerLoadcellAge
	ch <- collector.printerLoadcellHp
	ch <- collector.printerLoadcellHysteresis
	ch <- collector.printerLoadcellScale
	ch <- collector.printerLoadcellThreshold
	ch <- collector.printerLoadcellThresholdCont
	ch <- collector.printerLoadcellValue
	ch <- collector.printerLoadcellValueRaw
	ch <- collector.printerMaintaskLoop
	ch <- collector.printerMediaPrefetched
	ch <- collector.printerMMUComm
	ch <- collector.printerModbusReqfail
	ch <- collector.printerNetworkIn
	ch <- collector.printerNetworkOut
	ch <- collector.printerOvercurrent
	ch <- collector.printerPointsDropped
	ch <- collector.printerPos
	ch <- collector.printerPowerPanicCount
	ch <- collector.printerProbeAnalysis
	ch <- collector.printerProbeWindowStart
	ch <- collector.printerProbeWindowFallEnd
	ch <- collector.printerProbeWindowRiseStart
	ch <- collector.printerProbeWindowEnd
	ch <- collector.printerProbeStart
	ch <- collector.printerProbeZ
	ch <- collector.printerProbeZDiff
	ch <- collector.printerPwm
	ch <- collector.printerSideFSensor
	ch <- collector.printerSideFSensorRaw
	ch <- collector.printerTmcRead
	ch <- collector.printerTmcSg
	ch <- collector.printerTmcWrite
	ch <- collector.printerTKAcceleration
	ch <- collector.printerTemp
	ch <- collector.printerTempTarget
	ch <- collector.printerUsbhErrCount
	ch <- collector.printerVoltage
	ch <- collector.printerVoltageRaw
	ch <- collector.printerXyDev
	ch <- collector.prusaBuddyTimeUs
	ch <- collector.prusaPuppyTimeUs
	ch <- collector.prusaSyncRoundtripUs
	ch <- collector.prusaPuppyOffsetUs
	ch <- collector.prusaPuppyDriftPpb
	ch <- collector.prusaPuppyAverageOffsetUs
	ch <- collector.prusaPuppyAverageDriftPpb
	ch <- collector.printerSyslogUp
	ch <- collector.printerPrintFilename
}
