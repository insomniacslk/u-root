// Copyright 2017-2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	"github.com/u-root/u-root/pkg/boot/systembooter"
	"github.com/u-root/u-root/pkg/ipmi"
	"github.com/u-root/u-root/pkg/ipmi/ocp"
	"github.com/u-root/u-root/pkg/smbios"
	"github.com/u-root/u-root/pkg/vpd"
)

var (
	allowInteractive = flag.Bool("i", true, "Allow user to interrupt boot process and run commands")
	doQuiet          = flag.Bool("q", false, fmt.Sprintf("Disable verbose output. If not specified, read it from VPD var '%s'. If missing, use default (default false)", vpdDebugEnabled))
	interval         = flag.Int("I", 1, "Interval in seconds before looping to the next boot command")
	noDefaultBoot    = flag.Bool("nodefault", false, "Do not attempt default boot entries if regular ones fail")
)

const (
	// vpdDebugEnabled is the name of the VPD variable used to check if debug output is desired.
	vpdDebugEnabled = "debug_enabled"
)

// isFlagPassed checks whether a flag was explicitly passed on the command line. Thank you StackOverflow.
func isFlagPassed(name string) bool {
    found := false
    flag.Visit(func(f *flag.Flag) {
        if f.Name == name {
            found = true
        }
    })
    return found
}

var defaultBootsequence = [][]string{
	{"fbnetboot", "-userclass", "linuxboot"},
	{"localboot", "-grub"},
}

// Product list for running IPMI OEM commands
var productList = [3]string{"Tioga Pass", "Mono Lake", "Delta Lake"}

var selRecorded bool

func isMatched(productName string) bool {
	for _, v := range productList {
		if strings.HasPrefix(productName, v) {
			return true
		}
	}
	return false
}

func getBaseboardProductName(si *smbios.Info) (string, error) {
	t2, err := si.GetBaseboardInfo()
	if err != nil {
		log.Printf("Error getting Baseboard Information: %v", err)
		return "", err
	}
	return t2[0].Product, nil
}

func getSystemFWVersion(si *smbios.Info) (string, error) {
	t0, err := si.GetBIOSInfo()
	if err != nil {
		log.Printf("Error getting BIOS Information: %v", err)
		return "", err
	}
	return t0.Version, nil
}

func checkCMOSClear(ipmi *ipmi.IPMI) error {
	if cmosclear, bootorder, err := ocp.IsCMOSClearSet(ipmi); cmosclear {
		log.Printf("CMOS clear starts")
		if err = cmosClear(); err != nil {
			return err
		}
		// ToDo: Reset RW_VPD to default values
		if err = ocp.ClearCMOSClearValidBits(ipmi, bootorder); err != nil {
			return err
		}
		addSEL("cmosclear")
		if err = reboot(); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	return nil
}

func runIPMICommands() {
	i, err := ipmi.Open(0)
	if err != nil {
		log.Printf("Failed to open ipmi device %v, watchdog may still be running", err)
		return
	}
	defer i.Close()

	if err = i.ShutoffWatchdog(); err != nil {
		log.Printf("Failed to stop watchdog %v.", err)
	} else {
		log.Printf("Watchdog is stopped.")
	}

	// Below IPMI commands would require SMBIOS data
	si, err := smbios.FromSysfs()
	if err != nil {
		log.Printf("Error reading SMBIOS info: %v", err)
		return
	}

	if fwVersion, err := getSystemFWVersion(si); err == nil {
		log.Printf("System firmware version: %s", fwVersion)
		if err = i.SetSystemFWVersion(fwVersion); err != nil {
			log.Printf("Failed to set system firmware version to BMC %v.", err)
		}
	}

	if productName, err := getBaseboardProductName(si); err == nil {
		if isMatched(productName) {
			log.Printf("Running OEM IPMI commands.")
			if err = checkCMOSClear(i); err != nil {
				log.Printf("IPMI CMOS clear err: %v", err)
			}

			dimmInfo, err := ocp.GetOemIpmiDimmInfo(si)
			if err == nil {
				if err = ocp.SendOemIpmiDimmInfo(i, dimmInfo); err == nil {
					log.Printf("Send the information of DIMMs to BMC.")
				} else {
					log.Printf("Failed to send the information of DIMMs to BMC: %v.", err)
				}
			} else {
				log.Printf("Failed to get the information of DIMMs: %v.", err)
			}

			processorInfo, err := ocp.GetOemIpmiProcessorInfo(si)
			if err == nil {
				if err = ocp.SendOemIpmiProcessorInfo(i, processorInfo); err == nil {
					log.Printf("Send the information of processors to BMC.")
				} else {
					log.Printf("Failed to send the information of processors to BMC: %v.", err)
				}
			} else {
				log.Printf("Failed to get the information of Processors: %v.", err)
			}

			if err = ocp.SetOemIpmiPostEnd(i); err == nil {
				log.Printf("Send IPMI POST end to BMC")
			} else {
				log.Printf("Failed to send IPMI POST end to BMC: %v.", err)
			}

		} else {
			log.Printf("No product name is matched for OEM commands.")
		}
	}
}

func addSEL(sequence string) {
	var bootErr ipmi.Event

	i, err := ipmi.Open(0)
	if err != nil {
		log.Printf("Failed to open ipmi device to send SEL %v", err)
		return
	}
	defer i.Close()

	switch sequence {
	case "fbnetboot":
		bootErr.RecordID = 0
		bootErr.RecordType = ipmi.OEM_NTS_TYPE
		bootErr.OEMNontsDefinedData[0] = 0x28
		bootErr.OEMNontsDefinedData[5] = 0xf0
		for idx := 6; idx < 13; idx++ {
			bootErr.OEMNontsDefinedData[idx] = 0xff
		}
		if err := i.LogSystemEvent(&bootErr); err != nil {
			log.Printf("SEL recorded: %s fail\n", sequence)
		}
	case "cmosclear":
		bootErr.RecordID = 0
		bootErr.RecordType = ipmi.OEM_NTS_TYPE
		bootErr.OEMNontsDefinedData[0] = 0x28
		bootErr.OEMNontsDefinedData[5] = 0xf1
		for idx := 6; idx < 13; idx++ {
			bootErr.OEMNontsDefinedData[idx] = 0xff
		}
		if err := i.LogSystemEvent(&bootErr); err != nil {
			log.Printf("SEL recorded: %s fail\n", sequence)
		}
	default:
	}
}

// getDebugEnabled checks whether debug output is requested, either via command line or via VPD
// variables.
// If -q was explicitly passed on the command line, will use that value, otherwise will look for
// the VPD variable "debug_enabled". Valid values are "true", "false", "1", "0", "yes", "no",
// case-insensitive.
// If the VPD variable is missing or it is set to an invalid value, it will use the default.
func getDebugEnabled() bool {
	if isFlagPassed("q") {
		return !*doQuiet
	} else {
		// -q was not passet, so `doQuiet` contains the default value
		defaultDebugEnabled := !*doQuiet
		// check for the VPD variable "debug_enabled". First the read-write, then the read-only
		v, err := vpd.Get(vpdDebugEnabled, false)
		if err != nil {
			// TODO do not print warning if file is not found
			log.Printf("Warning: failed to read read-write VPD variable '%s', will try the read-only one. Error was: %v", vpdDebugEnabled, err)
			v, err = vpd.Get(vpdDebugEnabled, true)
			if err != nil {
				// TODO do not print warning if file is not found
				log.Printf("Warning: failed to read read-only VPD variable '%s', will use the default value. Error was: %v", vpdDebugEnabled, err)
				return defaultDebugEnabled
			}
		}
		switch strings.ToLower(strings.TrimSpace(string(v))) {
		case "true", "1", "yes":
			return true
		case "false", "0", "no":
			return false
		default:
			log.Printf("Invalid value '%s' for VPD variable '%s', using default", v, vpdDebugEnabled)
			return defaultDebugEnabled
		}
	}
}

func main() {
	flag.Parse()

	debugEnabled := getDebugEnabled()

	log.Print(`
                     ____            _                 _                 _
                    / ___| _   _ ___| |_ ___ _ __ ___ | |__   ___   ___ | |_
                    \___ \| | | / __| __/ _ \ '_ ` + "`" + ` _ \| '_ \ / _ \ / _ \| __|
                     ___) | |_| \__ \ ||  __/ | | | | | |_) | (_) | (_) | |_
                    |____/ \__, |___/\__\___|_| |_| |_|_.__/ \___/ \___/ \__|
                           |___/
`)
	runIPMICommands()
	sleepInterval := time.Duration(*interval) * time.Second
	if *allowInteractive {
		log.Printf("**************************************************************************")
		log.Print("Starting boot sequence, press CTRL-C within 5 seconds to drop into a shell")
		log.Printf("**************************************************************************")
		time.Sleep(5 * time.Second)
	} else {
		signal.Ignore()
	}

	// Get and show boot entries
	bootEntries := systembooter.GetBootEntries()
	log.Printf("BOOT ENTRIES:")
	for _, entry := range bootEntries {
		log.Printf("    %v) %+v", entry.Name, string(entry.Config))
	}
	for _, entry := range bootEntries {
		log.Printf("Trying boot entry %s: %s", entry.Name, string(entry.Config))
		if err := entry.Booter.Boot(); err != nil {
			log.Printf("Warning: failed to boot with configuration: %+v", entry)
			addSEL(entry.Booter.TypeName())
		}
		if debugEnabled {
			log.Printf("Sleeping %v before attempting next boot command", sleepInterval)
		}
		time.Sleep(sleepInterval)
	}

	// if boot entries failed, use the default boot sequence
	log.Printf("Boot entries failed")

	if !*noDefaultBoot {
		log.Print("Falling back to the default boot sequence")
		for {
			for _, bootcmd := range defaultBootsequence {
				if debugEnabled {
					bootcmd = append(bootcmd, "-d")
				}
				log.Printf("Running boot command: %v", bootcmd)
				cmd := exec.Command(bootcmd[0], bootcmd[1:]...)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					log.Printf("Error executing %v: %v", cmd, err)
					if !selRecorded {
						addSEL(bootcmd[0])
					}
				}
			}
			selRecorded = true

			if debugEnabled {
				log.Printf("Sleeping %v before attempting next boot command", sleepInterval)
			}
			time.Sleep(sleepInterval)
		}
	}
}
