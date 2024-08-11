package syslog

import (
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

var (
	ttl = 60
)

// Collect is a function that collects all the metrics
func (collector *Collector) Collect(ch chan<- prometheus.Metric) {
	defer mutex.RUnlock()
	log.Debug().Msgf("Collecting syslog metrics")

	mutex.RLock()

	for mac, v := range syslogMetrics {
		log.Trace().Msgf("Loading data for %s", mac)

		ip := strings.Split(v["ip"]["value"], ":")[0]

		alive := false

		timestamp := v["timestamp"]["value"]
		if timestamp == "" {
			log.Error().Msgf("No timestamp found for %s", mac)
			continue
		}
		timeParsed, err := time.Parse("2006-01-02T15:04:05.999999999Z07:00", timestamp)
		timeNowWithoutTTL := time.Now().Add(-time.Duration(ttl) * time.Second)

		if err != nil {
			log.Error().Msgf("Error parsing timestamp for %s: %s", mac, err)
			continue
		}

		if !timeParsed.Before(timeNowWithoutTTL) {
			alive = true
		}

		if alive {
			for k, v := range v {
				var (
					collectorItem *prometheus.Desc
					labels        = []string{}
					suffix        string
					valueParsed   float64
					valueKey      = "value" // mostly its value
				)

				length, name, err := getNumberOf(k)

				if err != nil {
					log.Error().Msgf("Error parsing metric name %s: %s", k, err)
					continue // Skip to next iteration if metric name parsing fails
				}

				if length != -1 {
					k = name
					suffix = "_" + strconv.Itoa(length)
				}

				splittedName := strings.Split(k, "_")
				switch k {
				case "temp_hbr":
					fallthrough
				case "temp_brd":
					fallthrough
				case "temp_chamber":
					fallthrough
				case "temp_mcu":
					fallthrough
				case "temp_sandwich":
					fallthrough
				case "temp_splitter":
					fallthrough
				case "temp_bed":
					fallthrough
				case "temp_noz":
					labels = []string{splittedName[1] + suffix}
					collectorItem = collector.printerTemp
				case "dwarf_board_temp":
					fallthrough
				case "dwarf_mcu_temp":
					fallthrough
				case "dwarfs_mcu_temp":
					fallthrough
				case "dwarfs_board_temp":
					fallthrough
				case "bed_mcu_temp":
					collectorItem = collector.printerTemp
					labels = []string{splittedName[0] + "_" + splittedName[1] + suffix}
				case "bedlet_temp":
					//labels = []string{splittedName[0] + suffix}
					//collectorItem = collector.printerTemp
					continue // firwmare returns constant value that contains only max measured current
				case "pos_x":
					fallthrough
				case "pos_y":
					fallthrough
				case "pos_z":
					labels = []string{splittedName[1] + suffix}
					collectorItem = collector.printerPos
				case "ipos_x":
					fallthrough
				case "ipos_y":
					fallthrough
				case "ipos_z":
					labels = []string{splittedName[1] + suffix}
					collectorItem = collector.printerIpos
				case "esp_out":
					fallthrough
				case "eth_out":
					valueParsed, err = strconv.ParseFloat(v["sent"], 64)
					if err != nil {
						log.Error().Msgf("Error parsing value for metric %s: %s", k, err)
						continue // Skip to next iteration if value parsing fails
					}

					ch <- prometheus.MustNewConstMetric(collector.printerNetworkOut, prometheus.CounterValue, valueParsed, getLabels(mac, ip, []string{splittedName[0]})...)
					continue
				case "esp_in":
					fallthrough
				case "eth_in":
					valueParsed, err = strconv.ParseFloat(v["recv"], 64)
					if err != nil {
						log.Error().Msgf("Error parsing value for metric %s: %s", k, err)
						continue // Skip to next iteration if value parsing fails
					}

					ch <- prometheus.MustNewConstMetric(collector.printerNetworkIn, prometheus.CounterValue, valueParsed, getLabels(mac, ip, []string{splittedName[0]})...)
					continue
				case "24VVoltage":
					fallthrough
				case "5VVoltage":
					labels = []string{strings.ReplaceAll(name, "Voltage", ""), ""}
					collectorItem = collector.printerVoltage
				case "volt_bed":
					fallthrough
				case "volt_nozz":
					labels = []string{"", splittedName[1] + suffix}
					collectorItem = collector.printerVoltage
				case "ttemp_bed":
					fallthrough
				case "ttemp_noz":
					fallthrough
				case "bedlet_target":
					labels = []string{splittedName[1] + suffix}
					collectorItem = collector.printerTempTarget
				case "Sandwitch5VCurrent":
					labels = []string{"5V", "sandwich"}
					collectorItem = collector.printerCurrent
				case "xlbuddy5VCurrent":
					labels = []string{"5V", "xlBuddy"}
					collectorItem = collector.printerCurrent
				case "splitter_5V_current":
					labels = []string{"5V", "splitter"}
					collectorItem = collector.printerCurrent
				case "curr_nozz":
					fallthrough
				case "curr_inp":
					fallthrough
				case "cur_mmu_imp":
					labels = []string{"", splittedName[1] + suffix}
					collectorItem = collector.printerCurrent
				case "bed_curr":
					fallthrough
				case "bedlet_curr":
					labels = []string{"", splittedName[0] + suffix}
					collectorItem = collector.printerCurrent
				case "dwarf_heat_curr":
					labels = []string{"", splittedName[0] + "_" + splittedName[1] + suffix}
					collectorItem = collector.printerCurrent
				case "tmc_sg_x":
					fallthrough
				case "tmc_sg_y":
					fallthrough
				case "tmc_sg_z":
					fallthrough
				case "tmc_sg_e":
					labels = []string{splittedName[2] + suffix}
					collectorItem = collector.printerTmcSg
				case "oc_nozz":
					fallthrough
				case "oc_inp":
					labels = []string{splittedName[1] + suffix}
					collectorItem = collector.printerOvercurrent
				case "curr_nozz_raw":
					fallthrough
				case "curr_inp_raw":
					labels = []string{"", splittedName[1] + suffix}
					collectorItem = collector.printerCurrentRaw
				case "volt_bed_raw":
					fallthrough
				case "volt_nozz_raw":
					labels = []string{"", splittedName[1] + suffix}
					collectorItem = collector.printerVoltageRaw
				case "fan":
					labels = []string{splittedName[1]}
					collectorItem = collector.printerFanActive
				case "fan_speed":
					valueParsed, err = strconv.ParseFloat(v[valueKey], 64)
					if err != nil {
						log.Error().Msgf("Error parsing value for metric %s: %s", k, err)
						continue // Skip to next iteration if value parsing fails
					}
					printerMetric := prometheus.MustNewConstMetric(collector.printerFanSpeed, prometheus.GaugeValue, valueParsed/255, getLabels(mac, ip, []string{"print"})...)
					ch <- printerMetric
					continue
				case "fan_hbr_speed":
					valueParsed, err = strconv.ParseFloat(v[valueKey], 64)
					if err != nil {
						log.Error().Msgf("Error parsing value for metric %s: %s", k, err)

						continue // Skip to next iteration if value parsing fails
					}
					ch <- prometheus.MustNewConstMetric(collector.printerFanSpeed, prometheus.GaugeValue, valueParsed/255, getLabels(mac, ip, []string{"heatbreak"})...)
					continue
				case "heater_enabled":
					collectorItem = collector.printerHeaterEnabled
				case "loadcell_age":
					collectorItem = collector.printerLoadcellAge
				case "loadcell_value":
					collectorItem = collector.printerLoadcellValue
				case "is_printing":
					collectorItem = collector.printerPrinting
				case "loadcell_hp":
					collectorItem = collector.printerLoadcellHp
				case "bed_pwm":
					labels = []string{"bed" + suffix}
					collectorItem = collector.printerPwm
				case "points_dropped":
					collectorItem = collector.printerPointsDropped
				case "hbr_fan_act":
					labels = []string{"heatbreak"}
					collectorItem = collector.printerFanActive
				case "adj_z":
					collectorItem = collector.printerAxisZAdjustment
				case "filament":
					valueParsed = 0
					if v[valueKey] != "---" {
						valueParsed = 1
					}
					ch <- prometheus.MustNewConstMetric(collector.printerFilament, prometheus.GaugeValue, valueParsed, getLabels(mac, ip, []string{v[valueKey]})...)
					continue
				case "nozzle_pwm":
					labels = []string{"nozzle" + suffix}
					collectorItem = collector.printerPwm
				case "heap_total":
					continue // just skip for now - it will collide with heap
				case "heap_free":
					continue // just skip for now - it will collide with heap
				case "heap":
					valueParsed, err = strconv.ParseFloat(v["free"], 64)
					if err != nil {
						log.Error().Msgf("Error parsing value for metric %s: %s", k, err)

						continue // Skip to next iteration if value parsing fails
					}
					ch <- prometheus.MustNewConstMetric(collector.printerHeapFree, prometheus.GaugeValue, valueParsed, getLabels(mac, ip, []string{})...)
					valueParsed, err = strconv.ParseFloat(v["total"], 64)
					if err != nil {
						log.Error().Msgf("Error parsing value for metric %s: %s", k, err)

						continue // Skip to next iteration if value parsing fails
					}
					ch <- prometheus.MustNewConstMetric(collector.printerHeapTotal, prometheus.GaugeValue, valueParsed, getLabels(mac, ip, []string{})...)
					continue
				case "print_fan_act":
					labels = []string{"print"}
					collectorItem = collector.printerFanActive
				case "gui_loop_dur":
					collectorItem = collector.printerGuiLoopDuration
				case "fsensor_raw":
					labels = []string{strconv.Itoa(length)}
					collectorItem = collector.printerFSensorRaw
				case "loadcell_xy":
					collectorItem = collector.printerLoadcellXY
				case "cpu_usage":
					valueParsed, err = strconv.ParseFloat(v[valueKey], 64)
					if err != nil {
						log.Error().Msgf("Error parsing value for metric %s: %s", k, err)
						continue // Skip to next iteration if value parsing fails
					}
					ch <- prometheus.MustNewConstMetric(collector.printerCPUUsage, prometheus.GaugeValue, valueParsed/100, getLabels(mac, ip, []string{})...)
					continue
				case "loadcell":
					collectorItem = collector.printerLoadcellValueRaw
					valueKey = "r"
				case "loadcell_scale":
					collectorItem = collector.printerLoadcellScale
				case "home_diff":
					valuesList := []string{"ok", "value"}
					for _, value := range valuesList {
						attempts := ""
						if length != -1 {
							attempts = strconv.Itoa(length)
						}
						valueParsed, err = strconv.ParseFloat(v[value], 64)
						if err != nil {
							log.Error().Msgf("Error parsing value for metric %s: %s", k, err)
							continue // Skip to next iteration if value parsing fails
						}
						if value == "value" {
							ch <- prometheus.MustNewConstMetric(collector.printerHomeDiff, prometheus.GaugeValue, valueParsed, getLabels(mac, ip, []string{v["ax"], attempts})...)
						} else if value == "ok" {
							ch <- prometheus.MustNewConstMetric(collector.printerHomeDiffOk, prometheus.GaugeValue, valueParsed, getLabels(mac, ip, []string{v["ax"], attempts})...)
						}
					}
					continue
				case "bedlet_pwm":
					labels = []string{"bedlet" + suffix}
					collectorItem = collector.printerPwm
				case "bedlet_reg":
					valueParsed, err = strconv.ParseFloat(v["d"], 64)
					if err != nil {
						log.Error().Msgf("Error parsing value for metric %s: %s", k, err)
						continue // Skip to next iteration if value parsing fails
					}
					ch <- prometheus.MustNewConstMetric(collector.printerBedletRegulationD, prometheus.GaugeValue, valueParsed, getLabels(mac, ip, []string{"bedlet" + suffix})...)
					valueParsed, err = strconv.ParseFloat(v["i"], 64)
					if err != nil {
						log.Error().Msgf("Error parsing value for metric %s: %s", k, err)
						continue // Skip to next iteration if value parsing fails
					}
					ch <- prometheus.MustNewConstMetric(collector.printerBedletRegulationI, prometheus.GaugeValue, valueParsed, getLabels(mac, ip, []string{"bedlet" + suffix})...)
					valueParsed, err = strconv.ParseFloat(v["p"], 64)
					if err != nil {
						log.Error().Msgf("Error parsing value for metric %s: %s", k, err)
						continue // Skip to next iteration if value parsing fails
					}
					ch <- prometheus.MustNewConstMetric(collector.printerBedletRegulationP, prometheus.GaugeValue, valueParsed, getLabels(mac, ip, []string{"bedlet" + suffix})...)
					valueParsed, err = strconv.ParseFloat(v["tc"], 64)
					if err != nil {
						log.Error().Msgf("Error parsing value for metric %s: %s", k, err)
						continue // Skip to next iteration if value parsing fails
					}
					ch <- prometheus.MustNewConstMetric(collector.printerBedletRegulationTc, prometheus.GaugeValue, valueParsed, getLabels(mac, ip, []string{"bedlet" + suffix})...)
					continue
				case "dwarf_parked_raw":
					labels = []string{strconv.Itoa(length)}
					collectorItem = collector.printerDwarfParkedRaw
				case "side_fsensor_raw":
					labels = []string{strconv.Itoa(length)}
					collectorItem = collector.printerSideFSensorRaw
				case "active_extruder":
					collectorItem = collector.printerActiveExtruder
				case "bed_state":
					collectorItem = collector.printerBedState
				case "bedlet_state":
					labels = []string{splittedName[0] + suffix}
					collectorItem = collector.printerBedletState
				case "dwarf_fast_refresh_delay":
					collectorItem = collector.printerDwarfFastRefreshDelay
				case "dwarf_picked_raw":
					labels = []string{strconv.Itoa(length)}
					collectorItem = collector.printerDwarfPickedRaw
				case "buddy_revision":
					collectorItem = collector.printerBuddyRevision
				case "fw_version":
					ch <- prometheus.MustNewConstMetric(collector.printerBuddyFW, prometheus.GaugeValue, 1, getLabels(mac, ip, []string{v[valueKey]})...)
					continue
				case "buddy_bom":
					collectorItem = collector.printerBuddyBom
				case "loadcell_threshold_cont":
					collectorItem = collector.printerLoadcellThresholdCont
				case "loadcell_threshold":
					collectorItem = collector.printerLoadcellThreshold
				case "loadcell_hysteresis":
					collectorItem = collector.printerLoadcellHysteresis
				case "media_prefetched":
					collectorItem = collector.printerMediaPrefetched
				case "crash":
					labels = []string{v["axis"], v["sens"], v["period"]}
					valueKey = "speed"
				case "crash_stat":
					labels = []string{v["axis"]}
					valueKey = "total"
				case "excite_freq":
					collectorItem = collector.printerExciteFreq
				case "g425_cen":
					labels = []string{v["t"], v["x"], v["y"], v["z"]}
					collectorItem = collector.printerG425Cen
				case "g425_off":
					labels = []string{v["t"], v["x"], v["y"], v["z"]}
					collectorItem = collector.printerG425Offset
				case "g425_rxy":
					labels = []string{v["t"], v["p"], v["a"], v["x"], v["y"], v["z"]}
					collectorItem = collector.printerG425Rxy
				case "g425_rz":
					labels = []string{v["t"], v["p"], v["x"], v["y"], v["z"]}
					collectorItem = collector.printerG425Rz
				case "g425_xy":
					collectorItem = collector.printerG425Xy
					labels = []string{v["t"], v["p"], v["a"], v["x"], v["y"]}
				case "g425_z":
					labels = []string{v["t"], v["p"], v["x"], v["y"], v["z"]}
					collectorItem = collector.printerG425Z
				case "g425_xy_dev":
					collectorItem = collector.printerG425XyDev
				case "gcode":
					ch <- prometheus.MustNewConstMetric(collector.printerGcode, prometheus.GaugeValue, 1, getLabels(mac, ip, []string{v[valueKey]})...)
					continue
				case "mmu_comm":
					ch <- prometheus.MustNewConstMetric(collector.printerMMUComm, prometheus.GaugeValue, 1, getLabels(mac, ip, []string{v[valueKey]})...)
					continue
				case "probe_analysis":
					valueKey = "ok"
					labels = []string{v["desc"]}
					collectorItem = collector.printerProbeAnalysis
				case "probe_start":
					collectorItem = collector.printerProbeStart
				case "probe_z":
					labels = []string{v["x"], v["y"]}
					collectorItem = collector.printerProbeZ
				case "probe_z_diff":
					collectorItem = collector.printerProbeZDiff
				case "tmc_read":
					labels = []string{v["ax"], v["reg"], v["regn"]}
					collectorItem = collector.printerTmcRead
				case "tmc_write":
					labels = []string{v["ax"], v["reg"], v["regn"]}
					collectorItem = collector.printerTmcWrite
				case "tmc_sg":
					labels = []string{splittedName[1]}
					collectorItem = collector.printerTmcSg
				case "usbh_err_count":
					collectorItem = collector.printerUsbhErrCount
				case "voltage":
					labels = []string{splittedName[0], ""}
					collectorItem = collector.printerVoltage
				case "voltage_raw":
					labels = []string{splittedName[0], ""}
					collectorItem = collector.printerVoltageRaw
				case "xy_dev":
					collectorItem = collector.printerXyDev
				case "power_panic":
					ch <- prometheus.MustNewConstMetric(collector.printerPowerPanicCount, prometheus.CounterValue, 1, getLabels(mac, ip, []string{})...)
				case "crash_length":
					labels = []string{v["x"], v["y"]}
					collectorItem = collector.printerCrashLength
				case "usbh_err_cnt":
					collectorItem = collector.printerUsbhErrCount
				case "probe_window":
					valuesList := []string{"as", "fe", "rs", "ae"} // " as=%0.3f,fe=%0.3f,rs=%0.3f,ae=%0.3f"
					collectorList := []*prometheus.Desc{collector.printerProbeWindowStart, collector.printerProbeWindowFallEnd, collector.printerProbeWindowRiseStart, collector.printerProbeWindowEnd}
					for i, value := range valuesList {
						valueParsed, err = strconv.ParseFloat(v[value], 64)
						if err != nil {
							log.Error().Msgf("Error parsing value for metric %s: %s", k, err)
							continue // Skip to next iteration if value parsing fails
						}
						ch <- prometheus.MustNewConstMetric(collectorList[i], prometheus.GaugeValue, valueParsed, getLabels(mac, ip, []string{})...)
					}
					continue
				case "eeprom_write":
					collectorItem = collector.printerEeepromWrite
				case "modbus_reqfail":
					collectorItem = collector.printerModbusReqfail
				case "puppy_t":
					collectorItem = collector.prusaPuppyTimeUs
				case "sync_rt":
					collectorItem = collector.prusaSyncRoundtripUs
				case "puppy_off":
					collectorItem = collector.prusaPuppyOffsetUs
				case "puppy_drift":
					collectorItem = collector.prusaPuppyDriftPpb
				case "puppy_aoff":
					collectorItem = collector.prusaPuppyAverageOffsetUs
				case "puppy_adrift":
					collectorItem = collector.prusaPuppyAverageDriftPpb
				case "print_filename":
					ch <- prometheus.MustNewConstMetric(collector.printerPrintFilename, prometheus.GaugeValue, 1, getLabels(mac, ip, []string{v[valueKey]})...)
					continue
				case "ip":
					continue // just ignore
				case "timestamp":
					continue // just ignore
				default:
					log.Debug().Msgf("No collector item found for metric %s", k)
					continue // Skip to next iteration if collector item is nil
				}

				if collectorItem == nil {
					log.Error().Msgf("No collector item found for metric %s", k) // not an error, just debug
					continue                                                     // Skip to next iteration if collector item is nil
				}

				valueParsed, err = strconv.ParseFloat(v[valueKey], 64)
				if err != nil {
					log.Error().Msgf("Error parsing value for metric %s: %s", k, err)
					continue // Skip to next iteration if value parsing fails
				}

				if collectorItem == collector.printerCurrent && !strings.Contains(k, "dwarf") {
					valueParsed = valueParsed * 1000 // firmware uses MODBUS_CURRENT_REGISTERS_SCALE = 1000 I'm upscaling this value ... just a little workaround
				}

				printerMetric := prometheus.MustNewConstMetric(collectorItem, prometheus.GaugeValue, valueParsed, getLabels(mac, ip, labels)...)
				ch <- printerMetric
			}
		}
	}
}
