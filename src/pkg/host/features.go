// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"monarch/pkg/csource"
	"monarch/pkg/log"
	"monarch/pkg/osutil"
	"monarch/prog"
	"monarch/sys/targets"
)

const (
	FeatureCoverage = iota
	FeatureComparisons
	FeatureExtraCoverage
	FeatureSandboxSetuid
	FeatureSandboxNamespace
	FeatureSandboxAndroid
	FeatureFault
	FeatureLeak
	FeatureNetInjection
	FeatureNetDevices
	FeatureKCSAN
	FeatureDevlinkPCI
	FeatureUSBEmulation
	FeatureVhciInjection
	FeatureWifiEmulation
	Feature802154Emulation
	numFeatures
)

type Feature struct {
	Name    string
	Enabled bool
	Reason  string
}

type Features [numFeatures]Feature

func (features *Features) Supported() *Features {
	return features
}

var CheckFeature [numFeatures]func() string

func unconditionallyEnabled() string { return "" }

func checkHostFuzzer(hostFuzzerCheckerCmd string) string {

	/*
	   scpArgs := []string{
	       "-P", "1569",
	       "-F", "/dev/null",
	       "-o", "UserKnownHostsFile=/dev/null",
	       "-o", "BatchMode=yes",
	       "-o", "IdentitiesOnly=yes",
	       "-o", "StrictHostKeyChecking=no",
	       "-o", "ConnectTimeout=100",
	       "-i", "/home/tlyu/dfs-fuzzing/disk-images/nfs-image-test/stretch.id_rsa",
	       "/home/tlyu/dfs-fuzzing/gopath/src/monarch/features_check_ssh",
	       "root@localhost:/",
	   }

	   sshArgs := []string{
	       "-p", "1569",
	       "-F", "/dev/null",
	       "-o", "UserKnownHostsFile=/dev/null",
	       "-o", "BatchMode=yes",
	       "-o", "IdentitiesOnly=yes",
	       "-o", "StrictHostKeyChecking=no",
	       "-o", "ConnectTimeout=100",
	       "-i", "/home/tlyu/dfs-fuzzing/disk-images/nfs-image-test/stretch.id_rsa",
	       "root@localhost", "/features_check_ssh",
	   }

	   _, scpErr := exec.Command("/usr/bin/scp", scpArgs...).Output()
	   if scpErr != nil{
	       return ""
	   }
	*/

	//out, sshErr := exec.Command("/usr/bin/ssh", sshArgs...).Output()
	args := strings.Split(hostFuzzerCheckerCmd, " ")
	log.Logf(0, "---------------hostFuzzerCheckerCmd: %v\n", args)
	out, sshErr := exec.Command(args[0], args[1:]...).Output()
	if sshErr != nil {
		return ""
	}

	return string(out[:])

	//for n, ret := range strings.Split(string(out[:]), "\n") {
	//    fmt.Printf("-%v:%s", n, ret)
	//}
}

// Check detects features supported on the host.
// Empty string for a feature means the feature is supported,
// otherwise the string contains the reason why the feature is not supported.
func Check(target *prog.Target, hostFuzzerCheckerCmd string) (*Features, error) {
	const unsupported = "support is not implemented in syzkaller"
	res := &Features{
		FeatureCoverage:         {Name: "code coverage", Reason: unsupported},
		FeatureComparisons:      {Name: "comparison tracing", Reason: unsupported},
		FeatureExtraCoverage:    {Name: "extra coverage", Reason: unsupported},
		FeatureSandboxSetuid:    {Name: "setuid sandbox", Reason: unsupported},
		FeatureSandboxNamespace: {Name: "namespace sandbox", Reason: unsupported},
		FeatureSandboxAndroid:   {Name: "Android sandbox", Reason: unsupported},
		FeatureFault:            {Name: "fault injection", Reason: unsupported},
		FeatureLeak:             {Name: "leak checking", Reason: unsupported},
		FeatureNetInjection:     {Name: "net packet injection", Reason: unsupported},
		FeatureNetDevices:       {Name: "net device setup", Reason: unsupported},
		FeatureKCSAN:            {Name: "concurrency sanitizer", Reason: unsupported},
		FeatureDevlinkPCI:       {Name: "devlink PCI setup", Reason: unsupported},
		FeatureUSBEmulation:     {Name: "USB emulation", Reason: unsupported},
		FeatureVhciInjection:    {Name: "hci packet injection", Reason: unsupported},
		FeatureWifiEmulation:    {Name: "wifi device emulation", Reason: unsupported},
		Feature802154Emulation:  {Name: "802.15.4 emulation", Reason: unsupported},
	}
	//tao del
	/*
		if noHostChecks(target) {
			return res, nil
		}
	*/
	//tao end

	reasons := strings.Split(checkHostFuzzer(hostFuzzerCheckerCmd), "\n")

	var reason string

	for n, check := range CheckFeature {
		if check == nil {
			continue
		}
		if targets.Get(target.OS, target.Arch).HostFuzzer {
			reason = reasons[n]
		} else {
			reason = check()
		}
		//if reason := check(); reason == "" {
		if reason == "" {
			if n == FeatureCoverage && !target.ExecutorUsesShmem {
				return nil, fmt.Errorf("enabling FeatureCoverage requires enabling ExecutorUsesShmem")
			}
			res[n].Enabled = true
			res[n].Reason = "enabled"
		} else {
			res[n].Reason = reason
		}
	}
	return res, nil
}

// Setup enables and does any one-time setup for the requested features on the host.
// Note: this can be called multiple times and must be idempotent.
func Setup(target *prog.Target, features *Features, featureFlags csource.Features, executor string) error {
	if noHostChecks(target) {
		return nil
	}
	args := strings.Split(executor, " ")
	executor = args[0]
	args = append(args[1:], "setup")
	if features[FeatureLeak].Enabled {
		args = append(args, "leak")
	}
	if features[FeatureFault].Enabled {
		args = append(args, "fault")
	}
	if target.OS == targets.Linux && featureFlags["binfmt_misc"].Enabled {
		args = append(args, "binfmt_misc")
	}
	if features[FeatureKCSAN].Enabled {
		args = append(args, "kcsan")
	}
	if features[FeatureUSBEmulation].Enabled {
		args = append(args, "usb")
	}
	if featureFlags["ieee802154"].Enabled && features[Feature802154Emulation].Enabled {
		args = append(args, "802154")
	}
	output, err := osutil.RunCmd(5*time.Minute, "", executor, args...)
	log.Logf(1, "executor %v\n%s", args, output)
	return err
}

func noHostChecks(target *prog.Target) bool {
	// HostFuzzer targets can't run Go binaries on the targets,
	// so we actually run on the host on another OS. The same for targets.TestOS OS.
	return targets.Get(target.OS, target.Arch).HostFuzzer || target.OS == targets.TestOS
}
