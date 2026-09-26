package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"regexp"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const (
	version = "0.19.0"
	red   = "\033[0;91m"
	green = "\033[0;92m"
	reset = "\033[0m"
)

type KernelRequirement struct {
	Vendor    string
	Version   string
	MinKernel string
}

func isWSL() bool {
	if _, err := os.Stat("/proc/sys/fs/binfmt_misc/WSLInterop"); err == nil {
		return true
	}

	if data, err := os.ReadFile("/proc/version"); err == nil {
		return strings.Contains(strings.ToLower(string(data)), "microsoft")
	}
	
	return false
}

func isModuleLoaded(moduleName string) bool {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == moduleName {
			return true
		}
	}
	
	return false
}

func needMinorOSUpgrade(vendor string, protectedKernels []KernelRequirement) bool {
	_, version, _ := getSysInfo()

	if vendor != "almalinux" && vendor != "oracle" && vendor != "rocky" {
		return false
	}

	osMajor, osMinor := versionParts(version)

	for _, pk := range protectedKernels {
		if pk.Vendor != vendor {
			continue
		}

		pkMajor, pkMinor := versionParts(pk.Version)

		if osMajor == pkMajor && osMinor < pkMinor {
			return true
		}
	}

	return false
}


func getSysInfo() (vendor string, version string, kernelRelease string) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "", "", ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	id := ""
	versionID := ""

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			versionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}

	idLower := strings.ToLower(id)
	switch {
	case strings.Contains(idLower, "ol") || strings.Contains(idLower, "oracle"):
		vendor = "oracle"
	case strings.Contains(idLower, "almalinux"):
		vendor = "almalinux"
	case strings.Contains(idLower, "debian"):
		vendor = "debian"
	case strings.Contains(idLower, "ubuntu"):
		vendor = "ubuntu"
	case strings.Contains(idLower, "fedora"):
		vendor = "fedora"
	case strings.Contains(idLower, "rocky"):
	    vendor = "rocky"
	case strings.Contains(idLower, "centos"):
		vendor = "centos"
	default:
		vendor = ""
	}

	version = versionID

	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		kernelRelease = ""
	} else {
		kernelRelease = strings.TrimRight(string(utsname.Release[:]), "\x00")
	}

	return vendor, version, kernelRelease
}

func parseKernelVersion(version string) (major, minor, patch int, build []int) {
	mainPart := version

	if idx := strings.Index(mainPart, "+"); idx != -1 {
		mainPart = mainPart[:idx]
	}

	if idx := strings.Index(mainPart, ".el"); idx != -1 {
		mainPart = mainPart[:idx]
	} else if idx := strings.Index(mainPart, "-generic"); idx != -1 {
		mainPart = mainPart[:idx]
	} else if idx := strings.Index(mainPart, "-amd64"); idx != -1 {
		mainPart = mainPart[:idx]
	}

	if idx := strings.Index(mainPart, ".fc"); idx != -1 {
		mainPart = mainPart[:idx]
	}

	versionPartsLocal := strings.Split(mainPart, "-")

	if len(versionPartsLocal) >= 1 {
		verNums := strings.Split(versionPartsLocal[0], ".")
		if len(verNums) >= 1 {
			major, _ = strconv.Atoi(verNums[0])
		}
		if len(verNums) >= 2 {
			minor, _ = strconv.Atoi(verNums[1])
		}
		if len(verNums) >= 3 {
			patch, _ = strconv.Atoi(verNums[2])
		}
	}

	if len(versionPartsLocal) >= 2 {
		buildStrs := strings.Split(versionPartsLocal[1], ".")
		for _, bs := range buildStrs {
			num, err := strconv.Atoi(bs)
			if err == nil {
				build = append(build, num)
			}
		}
	}

	return major, minor, patch, build
}

func compareBuilds(b1, b2 []int) int {
	for i := 0; i < len(b1) && i < len(b2); i++ {
		if b1[i] > b2[i] {
			return 1
		} else if b1[i] < b2[i] {
			return -1
		}
	}

	if len(b1) > len(b2) {
		return 1
	} else if len(b1) < len(b2) {
		return -1
	}

	return 0
}

func compareKernelVersions(v1, v2 string) int {
	v1Major, v1Minor, v1Patch, v1Build := parseKernelVersion(v1)
	v2Major, v2Minor, v2Patch, v2Build := parseKernelVersion(v2)

	if v1Major != v2Major {
		return compare(v1Major, v2Major)
	}
	if v1Minor != v2Minor {
		return compare(v1Minor, v2Minor)
	}
	if v1Patch != v2Patch {
		return compare(v1Patch, v2Patch)
	}

	return compareBuilds(v1Build, v2Build)
}

func compare(a, b int) int {
	if a > b {
		return 1
	} else if a < b {
		return -1
	}
	return 0
}

func versionParts(version string) (int, int) {
	parts := strings.Split(version, ".")
	major := 0
	minor := 0
	if len(parts) > 0 {
		major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1])
	}
	return major, minor
}

func isProtectedOS(getProtectedKernels func() []KernelRequirement) bool {
	vendor, version, kernelRelease := getSysInfo()
	if vendor == "" || version == "" || kernelRelease == "" {
		return false
	}

	osMajor, _ := versionParts(version)

	protectedKernels := getProtectedKernels()
	for _, pk := range protectedKernels {
		if vendor != pk.Vendor {
			continue
		}
		pkMajor, _ := versionParts(pk.Version)

		if osMajor != pkMajor {
			continue
		}
		result := compareKernelVersions(kernelRelease, pk.MinKernel)
		return result >= 0
	}

	return false
}

func promptMinorUpgrade(moduleNames ...string) int {

	moduleList := "modules"

	if len(moduleNames) > 0 {
		moduleList = strings.Join(moduleNames, ",")
	}

	fmt.Printf("\n%sMinor OS upgrade available!%s\n", green, reset)
	fmt.Println("1. Upgrade OS packages (dnf upgrade -y)")
	fmt.Printf("2. Apply hotfix (fully disable %s module(s))\n", moduleList)
	fmt.Println("3. Exit")
	fmt.Print("\nChoose option [3]: ")

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return 3
	}

	defer term.Restore(int(os.Stdin.Fd()), oldState)

	b := make([]byte, 1)
	_, err = os.Stdin.Read(b)
	if err != nil || b[0] == 3 {
		term.Restore(int(os.Stdin.Fd()), oldState)
		fmt.Printf("\n\n%sInterrupted by user%s\n", red, reset)
		os.Exit(130)
	}

	input := strings.TrimSpace(string(b))

	if input == "" || input == "\r" || input == "\n" {
		fmt.Println("3")
		return 3
	}

	fmt.Println(input)

	switch input {
	case "1":
		return 1
	case "2":
		return 2
	default:
		return 3
	}
}

func tryMinorOSUpgrade() bool {
	fmt.Println("\nRunning: dnf upgrade -y")

	cmd := exec.Command("dnf", "upgrade", "-y")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("%sOS upgrade failed: %v%s\n", red, err, reset)
		return false
	}

	fmt.Printf("\nOS upgrade %ssuccessfully completed%s\n", green, reset)
	fmt.Printf("\nPlease %sreboot%s asap to load the new kernel and %srun me%s once again to check the result and to clean up hotfixes (if any exists).\n",
		red, reset, red, reset)

	return true
}

func isProtectedOSMaxVersion_CVE_2026_31431() bool {
	vendor, version, _ := getSysInfo()
	maxVersion := getMaxProtectedVersion_CVE_2026_31431(vendor)

	osMajor, osMinor := versionParts(version)
	maxMajor, maxMinor := versionParts(maxVersion)

	return osMajor > maxMajor || (osMajor == maxMajor && osMinor > maxMinor)
}

func isProtectedOSMaxVersion_CVE_2026_43284() bool {
	vendor, version, _ := getSysInfo()
	maxVersion := getMaxProtectedVersion_CVE_2026_43284(vendor)

	osMajor, osMinor := versionParts(version)
	maxMajor, maxMinor := versionParts(maxVersion)

	return osMajor > maxMajor || (osMajor == maxMajor && osMinor > maxMinor)
}

func isProtectedOSMaxVersion_CVE_2026_46300() bool {
	vendor, version, _ := getSysInfo()
	maxVersion := getMaxProtectedVersion_CVE_2026_46300(vendor)

	osMajor, osMinor := versionParts(version)
	maxMajor, maxMinor := versionParts(maxVersion)

	return osMajor > maxMajor || (osMajor == maxMajor && osMinor > maxMinor)
}

func isProtectedOSMaxVersion_CVE_2026_46331() bool {
	vendor, version, _ := getSysInfo()
	maxVersion := getMaxProtectedVersion_CVE_2026_46331(vendor)

	osMajor, osMinor := versionParts(version)
	maxMajor, maxMinor := versionParts(maxVersion)

	return osMajor > maxMajor || (osMajor == maxMajor && osMinor > maxMinor)
}

func isExactOSMatch_CVE_2026_31431() bool {
	vendor, version, kernelRelease := getSysInfo()
	osMajor, _ := versionParts(version)

	protectedKernels := getProtectedKernels_CVE_2026_31431()
	for _, pk := range protectedKernels {
		if vendor != pk.Vendor {
			continue
		}
		pkMajor, _ := versionParts(pk.Version)

		if osMajor == pkMajor {
			if strings.HasPrefix(pk.MinKernel, "9.9.9-99") {
				return false
			}
			result := compareKernelVersions(kernelRelease, pk.MinKernel)
			return result < 0
		}
	}
	return false
}

func isExactOSMatch_CVE_2026_43284() bool {
	vendor, version, kernelRelease := getSysInfo()
	osMajor, _ := versionParts(version)

	protectedKernels := getProtectedKernels_CVE_2026_43284()
	for _, pk := range protectedKernels {
		if vendor != pk.Vendor {
			continue
		}
		pkMajor, _ := versionParts(pk.Version)

		if osMajor == pkMajor {
			if strings.HasPrefix(pk.MinKernel, "9.9.9-99") {
				return false
			}
			result := compareKernelVersions(kernelRelease, pk.MinKernel)
			return result < 0
		}
	}
	return false
}

func isExactOSMatch_CVE_2026_46300() bool {
	vendor, version, kernelRelease := getSysInfo()
	osMajor, _ := versionParts(version)

	protectedKernels := getProtectedKernels_CVE_2026_46300()
	for _, pk := range protectedKernels {
		if vendor != pk.Vendor {
			continue
		}
		pkMajor, _ := versionParts(pk.Version)

		if osMajor == pkMajor {
			if strings.HasPrefix(pk.MinKernel, "9.9.9-99") {
				return false
			}
			result := compareKernelVersions(kernelRelease, pk.MinKernel)
			return result < 0
		}
	}
	return false
}

func isExactOSMatch_CVE_2026_46331() bool {
	vendor, version, kernelRelease := getSysInfo()
	osMajor, _ := versionParts(version)

	protectedKernels := getProtectedKernels_CVE_2026_46331()
	for _, pk := range protectedKernels {
		if vendor != pk.Vendor {
			continue
		}
		pkMajor, _ := versionParts(pk.Version)

		if osMajor == pkMajor {
			if strings.HasPrefix(pk.MinKernel, "9.9.9-99") {
				return false
			}
			result := compareKernelVersions(kernelRelease, pk.MinKernel)
			return result < 0
		}
	}
	return false
}

func handleAlreadyInstalledKernel() bool {
	vendor, _, _ := getSysInfo()

	var newKernel string
	var newVersion string

	if vendor == "debian" || vendor == "ubuntu" {
		out, err := exec.Command("sh", "-c", "ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -1").Output()
		if err != nil {
			return false
		}

		newKernel = strings.TrimSpace(string(out))
		if newKernel == "" {
			return false
		}

		newVersion = strings.TrimPrefix(newKernel, "/boot/vmlinuz-")
	} else {
		out, err := exec.Command("sh", "-c", "grubby --info=ALL | grep ^kernel= | sort -V | tail -1").Output()
		if err != nil {
			return false
		}

		line := strings.TrimSpace(string(out))
		if line == "" {
			return false
		}

		parts := strings.Split(line, "=")
		if len(parts) < 2 {
			return false
		}
		newKernel = strings.Trim(parts[1], "\"")
		newVersion = strings.TrimPrefix(newKernel, "/boot/vmlinuz-")
	}

	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return false
	}
	currentRelease := strings.TrimRight(string(utsname.Release[:]), "\x00")

	if newVersion == currentRelease {
		return false
	}

	fmt.Printf("\n%sKernel update already installed but not booted:%s\n", green, reset)
	fmt.Printf("  Current: %s\n", currentRelease)
	fmt.Printf("  New:     %s\n", newVersion)
	fmt.Printf("\nSetting new kernel as default...\n")

	if vendor == "debian" || vendor == "ubuntu" {
		fmt.Println("Running: update-grub")
		updateGrub := exec.Command("update-grub")
		updateGrub.Stdout = os.Stdout
		updateGrub.Stderr = os.Stderr
		if err := updateGrub.Run(); err != nil {
			fmt.Printf("%sFailed%s to update grub: %v\n", red, reset, err)
			return false
		}
	} else {
		fmt.Printf("Running: grubby --set-default=%s\n", newKernel)
		grubbyCmd := exec.Command("grubby", "--set-default="+newKernel)
		grubbyCmd.Stdout = os.Stdout
		grubbyCmd.Stderr = os.Stderr
		if err := grubbyCmd.Run(); err != nil {
			fmt.Printf("%sFailed%s to set default kernel: %v\n", red, reset, err)
			return false
		}

		fmt.Println("Running: grub2-mkconfig -o /boot/grub2/grub.cfg")
		grubCfg := exec.Command("grub2-mkconfig", "-o", "/boot/grub2/grub.cfg")
		grubCfg.Stdout = os.Stdout
		grubCfg.Stderr = os.Stderr
		if err := grubCfg.Run(); err != nil {
			fmt.Printf("%sFailed%s to update grub config: %v\n", red, reset, err)
			return false
		}
	}

	fmt.Printf("\nNew kernel %s installed %ssuccessfully%s\n", newVersion, green, reset )
	fmt.Printf("\nPlease %sreboot%s asap to load the new kernel and %srun me%s once again to check the result and to clean up hotfixes (if any exists).\n", red, reset, red, reset)
	return true
}

func cleanupHotfix_31431() {
	fmt.Println("\nCleaning up CVE-2026-31431 hotfix artifacts...")

	if entries, err := os.ReadDir("/etc/modprobe.d/"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			filePath := "/etc/modprobe.d/" + entry.Name()
			data, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			if strings.Contains(string(data), "algif_aead") {
				if err := os.Remove(filePath); err != nil {
					fmt.Printf("Removing %s - %sFAIL%s : %v\n", filePath, red, reset, err)
				} else {
					fmt.Printf("Removing %s - %sOK%s\n", filePath, green, reset)
				}
			}
		}
	}

	if entries, err := os.ReadDir("/etc/systemd/system/service.d/"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			filePath := "/etc/systemd/system/service.d/" + entry.Name()
			data, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			if strings.Contains(string(data), "AF_ALG") {
				if err := os.Remove(filePath); err != nil {
					fmt.Printf("Removing %s - %sFAIL%s : %v\n", filePath, red, reset, err)
				} else {
					fmt.Printf("Removing %s - %sOK%s\n", filePath, green, reset)
				}
			}
		}
		fmt.Println("Running: systemctl daemon-reload")
		exec.Command("systemctl", "daemon-reload").Run()
	}

	removeGrubBlacklist()
	
	fmt.Printf("\nCVE-2026-31431 hotfix cleanup %scompleted%s\n", green, reset)
}

func cleanupHotfix_43284() {
	fmt.Println("\nCleaning up CVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 hotfix artifacts...")

	if entries, err := os.ReadDir("/etc/modprobe.d/"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			filePath := "/etc/modprobe.d/" + entry.Name()
			data, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			content := string(data)
			for _, mod := range []string{"esp4", "esp6", "rxrpc"} {
				if strings.Contains(content, mod) {
					if err := os.Remove(filePath); err != nil {
						fmt.Printf("Removing %s - %sFAIL%s : %v\n", filePath, red, reset, err)
					} else {
						fmt.Printf("Removing %s - %sOK%s\n", filePath, green, reset)
					}
					break
				}
			}
		}
	}

	removeGrubBlacklist_43284()
	
	fmt.Printf("\nCVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 hotfix cleanup %scompleted%s\n", green, reset)
}

func cleanupHotfix_46331() {
	fmt.Println("\nCleaning up CVE-2026-46331 (PEdit-CoW) hotfix artifacts...")

	if entries, err := os.ReadDir("/etc/modprobe.d/"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			filePath := "/etc/modprobe.d/" + entry.Name()
			data, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			if strings.Contains(string(data), "act_pedit") {
				if err := os.Remove(filePath); err != nil {
					fmt.Printf("Removing %s - %sFAIL%s : %v\n", filePath, red, reset, err)
				} else {
					fmt.Printf("Removing %s - %sOK%s\n", filePath, green, reset)
				}
			}
		}
	}

	removeGrubBlacklist_46331()
	
	fmt.Printf("\nCVE-2026-46331 (PEdit-CoW) hotfix cleanup %scompleted%s\n", green, reset)
}

func removeGrubBlacklist_43284() {
	grub := "/etc/default/grub"
	backup := "/etc/default/grub.bak.afalg"

	if _, err := exec.LookPath("grubby"); err == nil {
		fmt.Println("Running: grubby --update-kernel=ALL --remove-args=module_blacklist=rxrpc,esp4,esp6")
		exec.Command("grubby", "--update-kernel=ALL", "--remove-args=module_blacklist=rxrpc,esp4,esp6").Run()
	}

	data, err := os.ReadFile(grub)
	if err != nil {
		return
	}
	
	cfg := string(data)
	originalCfg := cfg

	for _, key := range []string{"GRUB_CMDLINE_LINUX_DEFAULT", "GRUB_CMDLINE_LINUX"} {
		re := regexp.MustCompile(`(` + key + `\s*=\s*)"([^"]*)"`)
		matches := re.FindStringSubmatch(cfg)
		
		if len(matches) >= 3 {
			currentValue := matches[2]
			newValue := currentValue

			moduleRe := regexp.MustCompile(`\s*module_blacklist=([^ ]*(?:esp4|esp6|rxrpc)[^ ]*)\s*`)
			if moduleRe.MatchString(newValue) {
				newValue = moduleRe.ReplaceAllString(newValue, " ")
			}

			newValue = strings.TrimSpace(newValue)
			newValue = regexp.MustCompile(`\s+`).ReplaceAllString(newValue, " ")
			
			if newValue != currentValue {
				newLine := matches[1] + `"` + newValue + `"`
				cfg = strings.Replace(cfg, matches[0], newLine, 1)
			}
		}
	}
	
	if cfg == originalCfg {
		return
	}
	
	if err := os.WriteFile(grub, []byte(cfg), 0644); err != nil {
		return
	}

	var errUpdate error
	if _, err := exec.LookPath("grub2-mkconfig"); err == nil {
		fmt.Println("Running: grub2-mkconfig -o /boot/grub2/grub.cfg")
		errUpdate = exec.Command("grub2-mkconfig", "-o", "/boot/grub2/grub.cfg").Run()
	} else if _, err := exec.LookPath("grub-mkconfig"); err == nil {
		fmt.Println("Running: grub-mkconfig -o /boot/grub/grub.cfg")
		errUpdate = exec.Command("grub-mkconfig", "-o", "/boot/grub/grub.cfg").Run()
	} else if _, err := exec.LookPath("update-grub"); err == nil {
		fmt.Println("Running: update-grub")
		errUpdate = exec.Command("update-grub").Run()
	}
	
	if errUpdate != nil {
		_ = restoreFile(backup, grub)
	}
}

func removeGrubBlacklist_46331() {
	grub := "/etc/default/grub"
	backup := "/etc/default/grub.bak.afalg"

	if _, err := exec.LookPath("grubby"); err == nil {
		fmt.Println("Running: grubby --update-kernel=ALL --remove-args=module_blacklist=act_pedit")
		exec.Command("grubby", "--update-kernel=ALL", "--remove-args=module_blacklist=act_pedit").Run()
	}

	data, err := os.ReadFile(grub)
	if err != nil {
		return
	}
	
	cfg := string(data)
	originalCfg := cfg

	for _, key := range []string{"GRUB_CMDLINE_LINUX_DEFAULT", "GRUB_CMDLINE_LINUX"} {
		re := regexp.MustCompile(`(` + key + `\s*=\s*)"([^"]*)"`)
		matches := re.FindStringSubmatch(cfg)
		
		if len(matches) >= 3 {
			currentValue := matches[2]
			newValue := currentValue

			moduleRe := regexp.MustCompile(`\s*module_blacklist=([^ ]*act_pedit[^ ]*)\s*`)
			if moduleRe.MatchString(newValue) {
				newValue = moduleRe.ReplaceAllString(newValue, " ")
			}

			newValue = strings.TrimSpace(newValue)
			newValue = regexp.MustCompile(`\s+`).ReplaceAllString(newValue, " ")
			
			if newValue != currentValue {
				newLine := matches[1] + `"` + newValue + `"`
				cfg = strings.Replace(cfg, matches[0], newLine, 1)
			}
		}
	}
	
	if cfg == originalCfg {
		return
	}
	
	if err := os.WriteFile(grub, []byte(cfg), 0644); err != nil {
		return
	}

	var errUpdate error
	if _, err := exec.LookPath("grub2-mkconfig"); err == nil {
		fmt.Println("Running: grub2-mkconfig -o /boot/grub2/grub.cfg")
		errUpdate = exec.Command("grub2-mkconfig", "-o", "/boot/grub2/grub.cfg").Run()
	} else if _, err := exec.LookPath("grub-mkconfig"); err == nil {
		fmt.Println("Running: grub-mkconfig -o /boot/grub/grub.cfg")
		errUpdate = exec.Command("grub-mkconfig", "-o", "/boot/grub/grub.cfg").Run()
	} else if _, err := exec.LookPath("update-grub"); err == nil {
		fmt.Println("Running: update-grub")
		errUpdate = exec.Command("update-grub").Run()
	}
	
	if errUpdate != nil {
		_ = restoreFile(backup, grub)
	}
}

func hasAnyHotfixArtifacts_31431() bool {
	if entries, err := os.ReadDir("/etc/modprobe.d/"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile("/etc/modprobe.d/" + entry.Name())
			if err != nil {
				continue
			}
			if strings.Contains(string(data), "algif_aead") {
				return true
			}
		}
	}

	if entries, err := os.ReadDir("/etc/systemd/system/service.d/"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile("/etc/systemd/system/service.d/" + entry.Name())
			if err != nil {
				continue
			}
			if strings.Contains(string(data), "AF_ALG") {
				return true
			}
		}
	}

	if data, err := os.ReadFile("/proc/cmdline"); err == nil {
		cmdline := string(data)
		if strings.Contains(cmdline, "initcall_blacklist=algif_aead_init") {
			return true
		}
	}

	if data, err := os.ReadFile("/etc/default/grub"); err == nil {
		if strings.Contains(string(data), "initcall_blacklist=algif_aead_init") {
			return true
		}
	}

	return false
}

func hasAnyHotfixArtifacts_43284() bool {
	if entries, err := os.ReadDir("/etc/modprobe.d/"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile("/etc/modprobe.d/" + entry.Name())
			if err != nil {
				continue
			}
			content := string(data)
			for _, mod := range []string{"esp4", "esp6", "rxrpc"} {
				if strings.Contains(content, mod) {
					return true
				}
			}
		}
	}

	if data, err := os.ReadFile("/proc/cmdline"); err == nil {
		cmdline := string(data)
		if strings.Contains(cmdline, "module_blacklist=") {
			for _, mod := range []string{"esp4", "esp6", "rxrpc"} {
				if strings.Contains(cmdline, mod) {
					return true
				}
			}
		}
	}

	if data, err := os.ReadFile("/etc/default/grub"); err == nil {
		grubCfg := string(data)
		if strings.Contains(grubCfg, "module_blacklist=") {
			for _, mod := range []string{"esp4", "esp6", "rxrpc"} {
				if strings.Contains(grubCfg, mod) {
					return true
				}
			}
		}
	}

	return false
}

func hasAnyHotfixArtifacts_46331() bool {
	if entries, err := os.ReadDir("/etc/modprobe.d/"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile("/etc/modprobe.d/" + entry.Name())
			if err != nil {
				continue
			}
			if strings.Contains(string(data), "act_pedit") {
				return true
			}
		}
	}

	if data, err := os.ReadFile("/proc/cmdline"); err == nil {
		cmdline := string(data)
		if strings.Contains(cmdline, "module_blacklist=") && strings.Contains(cmdline, "act_pedit") {
			return true
		}
	}

	if data, err := os.ReadFile("/etc/default/grub"); err == nil {
		grubCfg := string(data)
		if strings.Contains(grubCfg, "module_blacklist=") && strings.Contains(grubCfg, "act_pedit") {
			return true
		}
	}

	return false
}

func tryKernelUpdate() bool {
	vendor, _, kernelRelease := getSysInfo()

	var cmd *exec.Cmd
	var checkCmd *exec.Cmd

	switch vendor {
	case "debian":
		fmt.Println("\nAttempting to update kernel via apt ( apt-get install -y linux-image-amd64 linux-headers-amd64 ) ...\n")

		fmt.Println("Running: apt update")
		updateCmd := exec.Command("apt", "update")
		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr
		if err := updateCmd.Run(); err != nil {
			fmt.Printf("apt update %serror%s\n", red, reset)
		}

		checkCmd = exec.Command("sh", "-c", "apt list --upgradable 2>/dev/null | grep -q linux-image")
		if err := checkCmd.Run(); err != nil {
			if handleAlreadyInstalledKernel() {
				return true
			}
			fmt.Printf("Kernel update package %snot found%s in repositories (check repository configuration)\n", red, reset)
			return false
		}

		cmd = exec.Command("apt-get", "install", "-y", "linux-image-amd64", "linux-headers-amd64")

	case "ubuntu":
		fmt.Println("\nAttempting to update kernel via apt ( apt-get install -y linux-image-generic linux-headers-generic ) ...\n")

		fmt.Println("Running: apt update")
		updateCmd := exec.Command("apt", "update")
		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr
		if err := updateCmd.Run(); err != nil {
			fmt.Printf("apt update %serror%s\n", red, reset)
		}

		checkCmd = exec.Command("sh", "-c", "apt list --upgradable 2>/dev/null | grep -q linux-image")
		if err := checkCmd.Run(); err != nil {
			if handleAlreadyInstalledKernel() {
				return true
			}
			fmt.Printf("Kernel update package %snot found%s in repositories (check repository configuration)\n", red, reset)
			return false
		}
		cmd = exec.Command("apt-get", "install", "-y", "linux-image-generic", "linux-headers-generic")

		case "almalinux", "fedora", "oracle", "rocky", "centos":
		    data, err := os.ReadFile("/etc/default/grub")
		    if err == nil {
		        cfg := string(data)
		        if !strings.Contains(cfg, "GRUB_ENABLE_BLSCFG") {
		            cfg += "\nGRUB_ENABLE_BLSCFG=false\n"
		            os.WriteFile("/etc/default/grub", []byte(cfg), 0644)
		            fmt.Println("Adding GRUB_ENABLE_BLSCFG=false to /etc/default/grub")
		        }
		    }
		    
		    fmt.Println("Running: sed -i s/GRUB_ENABLE_BLSCFG=true/GRUB_ENABLE_BLSCFG=false/ /etc/default/grub")
		    sedBLS := exec.Command("sed", "-i", "s/GRUB_ENABLE_BLSCFG=true/GRUB_ENABLE_BLSCFG=false/", "/etc/default/grub")
		    sedBLS.Stdout = os.Stdout
		    sedBLS.Stderr = os.Stderr
		    sedBLS.Run()
		    
		    fmt.Println("Running: sed -i s/GRUB_DEFAULT=saved/GRUB_DEFAULT=0/ /etc/default/grub")
		    sedDefault := exec.Command("sed", "-i", "s/GRUB_DEFAULT=saved/GRUB_DEFAULT=0/", "/etc/default/grub")
		    sedDefault.Stdout = os.Stdout
		    sedDefault.Stderr = os.Stderr
		    sedDefault.Run()
	
		fmt.Println("Running: dnf clean metadata")
		cleanCmd := exec.Command("dnf", "clean", "metadata")
		cleanCmd.Stdout = os.Stdout
		cleanCmd.Stderr = os.Stderr
		if err := cleanCmd.Run(); err != nil {
			fmt.Printf("Kernel update %sfailed%s: dnf clean metadata error\n", red, reset)
			return false
		}

		installHook := `#!/bin/bash
if [[ "$COMMAND" == "add" ]]; then
    grub2-mkconfig -o /boot/grub2/grub.cfg
fi
`
		os.MkdirAll("/etc/kernel/install.d", 0755)
		os.WriteFile("/etc/kernel/install.d/99-grub-update.install", []byte(installHook), 0755)
		fmt.Println("Running: kernel install hook added to /etc/kernel/install.d/99-grub-update.install")
	
		if strings.Contains(kernelRelease, "uek") {
			fmt.Println("\nAttempting to update kernel via dnf ( dnf upgrade kernel-uek kernel-uek-core -y ) ...\n")
	
			fmt.Println("Running: dnf check-update kernel-uek kernel-uek-core")
			checkCmd = exec.Command("dnf", "check-update", "kernel-uek", "kernel-uek-core")
			checkCmd.Stdout = os.Stdout
			checkCmd.Stderr = os.Stderr
	
			if err := checkCmd.Run(); err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					if exitErr.ExitCode() == 100 {
						cmd = exec.Command("dnf", "upgrade", "kernel-uek", "kernel-uek-core", "-y")
					} else {
						fmt.Printf("Kernel update %sfailed%s: repository error (exit code %d)\n", red, reset, exitErr.ExitCode())
						return false
					}
				} else {
					fmt.Printf("Kernel update failed: check-update %serror%s\n", red, reset)
					return false
				}
			} else {
				if handleAlreadyInstalledKernel() {
					return true
				}
				fmt.Printf("Kernel update package %snot found%s in repositories (check repository configuration)\n", red, reset)
				return false
			}
		} else {
			fmt.Println("\nAttempting to update kernel via dnf ( dnf upgrade kernel kernel-core -y ) ...\n")
	
			fmt.Println("Running: dnf check-update kernel kernel-core")
			checkCmd = exec.Command("dnf", "check-update", "kernel", "kernel-core")
			checkCmd.Stdout = os.Stdout
			checkCmd.Stderr = os.Stderr
	
			if err := checkCmd.Run(); err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					if exitErr.ExitCode() == 100 {
						cmd = exec.Command("dnf", "upgrade", "kernel", "kernel-core", "-y")
					} else {
						fmt.Printf("Kernel update %sfailed%s: repository error (exit code %d)\n", red, reset, exitErr.ExitCode())
						return false
					}
				} else {
					fmt.Printf("Kernel update failed: check-update %serror%s\n", red, reset)
					return false
				}
			} else {
				if handleAlreadyInstalledKernel() {
					return true
				}
				fmt.Printf("Kernel update package %snot found%s in repositories (check repository configuration)\n", red, reset)
				return false
			}
		}

	default:
		return false
	}

	if cmd == nil {
		return false
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("%sKernel update failed: %v%s\n", red, err, reset)
		return false
	}

	fmt.Println("Running: grub2-mkconfig -o /boot/grub2/grub.cfg")
	grubCfg := exec.Command("grub2-mkconfig", "-o", "/boot/grub2/grub.cfg")
	grubCfg.Stdout = os.Stdout
	grubCfg.Stderr = os.Stderr
	grubCfg.Run()

	fmt.Printf("\nNew kernel installed %ssuccessfully%s\n", green, reset )
	fmt.Printf("\nPlease %sreboot%s asap to load the new kernel and %srun me%s once again to check the result and to clean up hotfixes (if any exists).\n", red, reset, red, reset)
	return true
}

func promptKernelUpdate(moduleNames ...string) int {
	moduleList := "algif_aead"
	if len(moduleNames) > 0 {
		moduleList = strings.Join(moduleNames, ",")
	}
	
	fmt.Printf("\n%sKernel update is available for your OS!%s\n", green, reset)
	fmt.Println("1. Update kernel to fixed version (recommended)")
	fmt.Printf("2. Apply hotfix (fully disable %s module(s))\n", moduleList)
	fmt.Println("3. Exit")
	fmt.Print("\nChoose option [3]: ")

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return 3
	}

	b := make([]byte, 1)
	_, err = os.Stdin.Read(b)
	if err != nil || b[0] == 3 {
		term.Restore(int(os.Stdin.Fd()), oldState)
		fmt.Printf("\n\n%sInterrupted by user%s\n", red, reset)
		os.Exit(130)
	}

	char := string(b)
	input := strings.TrimSpace(char)

	term.Restore(int(os.Stdin.Fd()), oldState)

	if input == "" || input == "\r" || input == "\n" {
		fmt.Println("3")
		return 3
	}

	fmt.Println(input)

	switch input {
	case "1":
		return 1
	case "2":
		return 2
	case "3":
		return 3
	default:
		fmt.Printf("%sInvalid option, defaulting to 3%s\n", red, reset)
		return 3
	}
}

func getKernelUpdateCommand() string {
	vendor, _, kernelRelease := getSysInfo()

	switch vendor {
	case "debian":
		return "apt update && apt install linux-image-amd64 linux-headers-amd64 -y"
	case "ubuntu":
		return "apt update && apt install linux-image-generic linux-headers-generic -y"
	case "almalinux", "fedora", "oracle", "rocky", "centos":
		if strings.Contains(kernelRelease, "uek") {
			return "dnf upgrade kernel-uek kernel-uek-core -y"
		}
		return "dnf upgrade kernel kernel-core -y"
	default:
		return ""
	}
}

func removeGrubBlacklist() {
	grub := "/etc/default/grub"
	backup := "/etc/default/grub.bak.afalg"

	grubbyFixed := false
	if _, err := exec.LookPath("grubby"); err == nil {
		fmt.Println("Running: grubby --update-kernel=ALL --remove-args=initcall_blacklist=algif_aead_init")
		if err := exec.Command("grubby", "--update-kernel=ALL", "--remove-args=initcall_blacklist=algif_aead_init").Run(); err != nil {
			fmt.Printf("Removing initcall_blacklist=algif_aead_init via grubby - %sFAIL%s: %v\n", red, reset, err)
		} else {
			fmt.Printf("Removing initcall_blacklist=algif_aead_init via grubby - %sOK%s\n", green, reset)
			grubbyFixed = true
		}
		
		fmt.Println("Running: grubby --update-kernel=ALL --remove-args=module_blacklist=algif_aead")
		exec.Command("grubby", "--update-kernel=ALL", "--remove-args=module_blacklist=algif_aead").Run()
		
		fmt.Println("Running: grubby --update-kernel=ALL --remove-args=module_blacklist=rxrpc,esp4,esp6")
		exec.Command("grubby", "--update-kernel=ALL", "--remove-args=module_blacklist=rxrpc,esp4,esp6").Run()
		
		fmt.Println("Running: grubby --update-kernel=ALL --remove-args=module_blacklist=act_pedit")
		exec.Command("grubby", "--update-kernel=ALL", "--remove-args=module_blacklist=act_pedit").Run()
	}

	data, err := os.ReadFile(grub)
	if err != nil {
		return
	}
	
	cfg := string(data)
	originalCfg := cfg
	removedParams := []string{}

	for _, key := range []string{"GRUB_CMDLINE_LINUX_DEFAULT", "GRUB_CMDLINE_LINUX"} {
		re := regexp.MustCompile(`(` + key + `\s*=\s*)"([^"]*)"`)
		matches := re.FindStringSubmatch(cfg)
		
		if len(matches) >= 3 {
			currentValue := matches[2]
			newValue := currentValue

			if strings.Contains(newValue, "initcall_blacklist=algif_aead_init") {
				initcallRe := regexp.MustCompile(`\s*initcall_blacklist=algif_aead_init\s*`)
				newValue = initcallRe.ReplaceAllString(newValue, " ")
				removedParams = append(removedParams, "initcall_blacklist=algif_aead_init")
			}

			moduleRe := regexp.MustCompile(`\s*module_blacklist=([^ ]*(?:algif_aead|rxrpc|esp4|esp6|act_pedit)[^ ]*)\s*`)
			if moduleRe.MatchString(newValue) {
				match := moduleRe.FindStringSubmatch(newValue)
				if len(match) >= 2 {
					removedParams = append(removedParams, "module_blacklist="+match[1])
				}
				newValue = moduleRe.ReplaceAllString(newValue, " ")
			}

			newValue = strings.TrimSpace(newValue)
			newValue = regexp.MustCompile(`\s+`).ReplaceAllString(newValue, " ")
			
			if newValue != currentValue {
				newLine := matches[1] + `"` + newValue + `"`
				cfg = strings.Replace(cfg, matches[0], newLine, 1)
			}
		}
	}
	
	if len(removedParams) > 0 {
		fmt.Printf("Removing from grub config: %s\n", strings.Join(removedParams, ", "))
	}
	
	if cfg == originalCfg && grubbyFixed {
		fmt.Printf("Grub config already clean - %sOK%s\n", green, reset)
		return
	}
	
	if cfg == originalCfg {
		return
	}
	
	if err := os.WriteFile(grub, []byte(cfg), 0644); err != nil {
		fmt.Printf("Writing grub config - %sFAIL%s (cannot write): %v\n", red, reset, err)
		return
	} else {
		fmt.Printf("Writing grub config - %sOK%s\n", green, reset)
	}

	var errUpdate error
	if _, err := exec.LookPath("grub2-mkconfig"); err == nil {
		fmt.Println("Running: grub2-mkconfig -o /boot/grub2/grub.cfg")
		errUpdate = exec.Command("grub2-mkconfig", "-o", "/boot/grub2/grub.cfg").Run()
	} else if _, err := exec.LookPath("grub-mkconfig"); err == nil {
		fmt.Println("Running: grub-mkconfig -o /boot/grub/grub.cfg")
		errUpdate = exec.Command("grub-mkconfig", "-o", "/boot/grub/grub.cfg").Run()
	} else if _, err := exec.LookPath("update-grub"); err == nil {
		fmt.Println("Running: update-grub")
		errUpdate = exec.Command("update-grub").Run()
	}
	
	if errUpdate != nil {
		_ = restoreFile(backup, grub)
		fmt.Printf("Updating grub - %sFAIL%s: %v\n", red, reset, errUpdate)
		return
	}
	
	fmt.Printf("Updating grub - %sOK%s\n", green, reset)
}

func updateGrubBlacklist_46331() bool {
	data, err := os.ReadFile("/proc/cmdline")
	if err == nil && strings.Contains(string(data), "module_blacklist=act_pedit") {
		fmt.Printf("Blacklisting act_pedit module using grub - %sOK%s (already blacklisted)\n", green, reset)
		return true
	}

	if _, err := exec.LookPath("grubby"); err == nil {
		fmt.Println("Running: grubby --update-kernel=ALL --args=module_blacklist=act_pedit")
		if err := exec.Command("grubby", "--update-kernel=ALL", "--args=module_blacklist=act_pedit").Run(); err != nil {
			fmt.Printf("Blacklisting act_pedit module using grub - %sFAIL%s (grubby failed: %v)\n", red, reset, err)
			fmt.Printf("Falling back to grub config editing...\n")
		} else {
			fmt.Printf("Blacklisting act_pedit module using grub - %sOK%s\n", green, reset)
			return true
		}
	}

	backup := "/etc/default/grub.bak.afalg"
	grub := "/etc/default/grub"

	if _, err := os.Stat(backup); err != nil {
		_ = backupFile(grub, backup)
	}

	data, err = os.ReadFile(grub)
	if err != nil {
		fmt.Printf("Blacklisting act_pedit module using grub - %sFAIL%s (cannot read grub config: %v)\n", red, reset, err)
		return false
	}

	cfg := string(data)

	re := regexp.MustCompile(`(GRUB_CMDLINE_LINUX_DEFAULT\s*=\s*)"([^"]*)"`)
	matches := re.FindStringSubmatch(cfg)

	if len(matches) < 3 {
		fmt.Printf("Blacklisting act_pedit module using grub - %sFAIL%s (GRUB_CMDLINE_LINUX_DEFAULT not found)\n", red, reset)
		return false
	}

	currentValue := matches[2]

	if strings.Contains(currentValue, "module_blacklist=act_pedit") {
		fmt.Printf("Blacklisting act_pedit module using grub - %sOK%s (already in config)\n", green, reset)
		return true
	}

	var newValue string
	currentValue = strings.TrimSpace(currentValue)

	moduleRe := regexp.MustCompile(`\s*module_blacklist=([^"]*)`)
	if moduleRe.MatchString(currentValue) {
		newValue = moduleRe.ReplaceAllString(currentValue, " module_blacklist=$1,act_pedit")
	} else {
		if currentValue == "" {
			newValue = "module_blacklist=act_pedit"
		} else {
			newValue = currentValue + " module_blacklist=act_pedit"
		}
	}

	newLine := matches[1] + `"` + newValue + `"`
	cfg = re.ReplaceAllString(cfg, newLine)

	if err := os.WriteFile(grub, []byte(cfg), 0644); err != nil {
		fmt.Printf("Blacklisting act_pedit module using grub - %sFAIL%s (cannot write grub config: %v)\n", red, reset, err)
		return false
	}

	var errUpdate error
	if _, err := exec.LookPath("grub2-mkconfig"); err == nil {
		fmt.Println("Running: grub2-mkconfig -o /boot/grub2/grub.cfg")
		errUpdate = exec.Command("grub2-mkconfig", "-o", "/boot/grub2/grub.cfg").Run()
	} else if _, err := exec.LookPath("grub-mkconfig"); err == nil {
		fmt.Println("Running: grub-mkconfig -o /boot/grub/grub.cfg")
		errUpdate = exec.Command("grub-mkconfig", "-o", "/boot/grub/grub.cfg").Run()
	} else if _, err := exec.LookPath("update-grub"); err == nil {
		fmt.Println("Running: update-grub")
		errUpdate = exec.Command("update-grub").Run()
	}

	if errUpdate != nil {
		_ = restoreFile(backup, grub)
		fmt.Printf("Blacklisting act_pedit module using grub - %sFAIL%s (grub update failed: %v)\n", red, reset, errUpdate)
		return false
	}

	fmt.Printf("Blacklisting act_pedit module using grub - %sOK%s\n", green, reset)
	return true
}

func handleKernelUpdate(moduleNames ...string) {
	choice := promptKernelUpdate(moduleNames...)

	switch choice {
	case 1:
		if !tryKernelUpdate() {
			moduleList := "algif_aead"
			if len(moduleNames) > 0 {
				moduleList = strings.Join(moduleNames, ",")
			}
			
			fmt.Printf("\nKernel update %sfailed%s\nInstall hotfix instead? (disable %s module(s)) [y/N]: ", red, reset, moduleList)

			oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
			if err != nil {
				return
			}

			b := make([]byte, 1)
			_, err = os.Stdin.Read(b)
			if err != nil || b[0] == 3 {
				term.Restore(int(os.Stdin.Fd()), oldState)
				fmt.Printf("\n\n%sInterrupted by user%s\n", red, reset)
				os.Exit(130)
			}

			char := string(b)
			input := strings.ToLower(strings.TrimSpace(char))

			term.Restore(int(os.Stdin.Fd()), oldState)

			isYes := input == "y" || input == "н"

			if isYes {
				fmt.Println("y")
			} else {
				fmt.Println("N")
				cmd := getKernelUpdateCommand()
				if cmd != "" {
					fmt.Printf("Try: %s\n", cmd)
				}
				fmt.Println("Canceled by user")
				os.Exit(0)
			}
		} else {
			os.Exit(0)
		}

	case 2:
		fmt.Println("\nProceeding with module disable...")

	case 3:
		cmd := getKernelUpdateCommand()
		if cmd != "" {
			fmt.Printf("\nTry: %s\n", cmd)
		}
		fmt.Println("Canceled by user")
		os.Exit(0)
	}
}

func getProtectedKernels_CVE_2026_31431() []KernelRequirement {
	return []KernelRequirement{

		{Vendor: "debian", Version: "11", MinKernel: "5.10.0-41-amd64"},
		{Vendor: "debian", Version: "12", MinKernel: "6.1.0-45-amd64"},
		{Vendor: "debian", Version: "13", MinKernel: "6.12.85+deb13-amd64"},

		{Vendor: "ubuntu", Version: "22.04", MinKernel: "5.15.0-177-generic"},
		{Vendor: "ubuntu", Version: "24.04", MinKernel: "6.8.0-111-generic"},
		{Vendor: "ubuntu", Version: "25.04", MinKernel: "9.9.9-99-generic"},
		{Vendor: "ubuntu", Version: "26.04", MinKernel: "7.0.0-15-generic"},

		{Vendor: "almalinux", Version: "8.10", MinKernel: "4.18.0-553.121.1.el8_10.x86_64"},
		{Vendor: "almalinux", Version: "9.7", MinKernel: "5.14.0-611.49.2.el9_7.x86_64"},
		{Vendor: "almalinux", Version: "10.1", MinKernel: "6.12.0-124.52.3.el10_1.x86_64"},

		{Vendor: "fedora", Version: "42", MinKernel: "6.19.14-100.fc42.x86_64"},
		{Vendor: "fedora", Version: "43", MinKernel: "6.19.14-200.fc43.x86_64"},
		{Vendor: "fedora", Version: "44", MinKernel: "6.19.14-300.fc44.x86_64"},

		{Vendor: "oracle", Version: "8.10", MinKernel: "5.15.0-319.201.4.4.el8uek.x86_64"},
		{Vendor: "oracle", Version: "9.7", MinKernel: "6.12.0-201.74.2.2.el9uek.x86_64"},
		{Vendor: "oracle", Version: "10.1", MinKernel: "6.12.0-201.74.2.2.el10uek.x86_64"},

		{Vendor: "rocky", Version: "8.10", MinKernel: "4.18.0-553.123.1.el8_10.x86_64"},
		{Vendor: "rocky", Version: "9.7", MinKernel: "5.14.0-611.54.1.el9_7.x86_64"},
		{Vendor: "rocky", Version: "10.1", MinKernel: "6.12.0-124.55.1.el10_1.x86_64"},

		{Vendor: "centos", Version: "8", MinKernel: "9.9.9-999.el9.x86_64"},
		{Vendor: "centos", Version: "9", MinKernel: "5.14.0-701.el9.x86_64"},
		{Vendor: "centos", Version: "10", MinKernel: "6.12.0-226.el10.x86_64"},
	}
}

func getProtectedKernels_CVE_2026_43284() []KernelRequirement {
	return []KernelRequirement{

		{Vendor: "debian", Version: "11", MinKernel: "5.10.0-42-amd64"},
		{Vendor: "debian", Version: "12", MinKernel: "6.1.0-47-amd64"},
		{Vendor: "debian", Version: "13", MinKernel: "6.12.86+deb13-amd64"},

		{Vendor: "ubuntu", Version: "22.04", MinKernel: "9.9.9-99-generic"},
		{Vendor: "ubuntu", Version: "24.04", MinKernel: "6.8.0-124-generic"},
		{Vendor: "ubuntu", Version: "25.04", MinKernel: "9.9.9-99-generic"},
		{Vendor: "ubuntu", Version: "26.04", MinKernel: "7.0.0-22-generic"},

		{Vendor: "almalinux", Version: "8.10", MinKernel: "4.18.0-553.123.2.el8_10.x86_64"},
		{Vendor: "almalinux", Version: "9.7", MinKernel: "5.14.0-611.54.3.el9_7.x86_64"},
		{Vendor: "almalinux", Version: "10.1", MinKernel: "6.12.0-124.55.3.el10_1.x86_64"},

		{Vendor: "fedora", Version: "42", MinKernel: "6.19.14-101.fc42.x86_64"},
		{Vendor: "fedora", Version: "43", MinKernel: "7.0.4-100.fc43.x86_64"},
		{Vendor: "fedora", Version: "44", MinKernel: "7.0.4-200.fc44.x86_64"},

		{Vendor: "oracle", Version: "8.10", MinKernel: "5.15.0-319.201.4.6.el8uek.x86_64"},
		{Vendor: "oracle", Version: "9.7", MinKernel: "6.12.0-201.74.2.3.el9uek.x86_64"},
		{Vendor: "oracle", Version: "10.1", MinKernel: "6.12.0-201.74.2.3.el10uek.x86_64"},

		{Vendor: "rocky", Version: "8.10", MinKernel: "4.18.0-553.124.1.el8_10.x86_64"},
		{Vendor: "rocky", Version: "9.7", MinKernel: "5.14.0-611.55.1.el9_7.x86_64"},
		{Vendor: "rocky", Version: "10.1", MinKernel: "6.12.0-124.56.1.el10_1.x86_64"},

		{Vendor: "centos", Version: "8", MinKernel: "9.9.9-999.el9.x86_64"},
		{Vendor: "centos", Version: "9", MinKernel: "5.14.0-708.el9.x86_64"},
		{Vendor: "centos", Version: "10", MinKernel: "6.12.0-231.el10.x86_64"},
	}
}

func getProtectedKernels_CVE_2026_46300() []KernelRequirement {
	return []KernelRequirement{

		{Vendor: "debian", Version: "11", MinKernel: "5.10.0-43-amd64"},
		{Vendor: "debian", Version: "12", MinKernel: "6.1.0-48-amd64"},
		{Vendor: "debian", Version: "13", MinKernel: "6.12.88+deb13-amd64"},

		{Vendor: "ubuntu", Version: "22.04", MinKernel: "9.9.9-99-generic"},
		{Vendor: "ubuntu", Version: "24.04", MinKernel: "6.8.0-124-generic"},
		{Vendor: "ubuntu", Version: "25.04", MinKernel: "9.9.9-99-generic"},
		{Vendor: "ubuntu", Version: "26.04", MinKernel: "7.0.0-22-generic"},

		{Vendor: "almalinux", Version: "8.10", MinKernel: "4.18.0-553.124.4.el8_10.x86_64"},
		{Vendor: "almalinux", Version: "9.7", MinKernel: "5.14.0-611.54.6.el9_7.x86_64"},
		{Vendor: "almalinux", Version: "10.1", MinKernel: "6.12.0-124.56.5.el10_1.x86_64"},

		{Vendor: "fedora", Version: "42", MinKernel: "6.19.14-108.fc42.x86_64"},
		{Vendor: "fedora", Version: "43", MinKernel: "7.0.9-105.fc43.x86_64"},
		{Vendor: "fedora", Version: "44", MinKernel: "7.0.9-205.fc44.x86_64"},

		{Vendor: "oracle", Version: "8.10", MinKernel: "5.15.0-320.202.8.5.el8uek.x86_64"},
		{Vendor: "oracle", Version: "9.7", MinKernel: "6.12.0-202.76.4.4.el9uek.x86_64"},
		{Vendor: "oracle", Version: "10.1", MinKernel: "6.12.0-202.76.4.4.el10uek.x86_64"},

		{Vendor: "rocky", Version: "8.10", MinKernel: "4.18.0-553.126.1.el8_10.x86_64"},
		{Vendor: "rocky", Version: "9.7", MinKernel: "5.14.0-687.12.1.el9_8.x86_64"},
		{Vendor: "rocky", Version: "10.1", MinKernel: "6.12.0-211.16.1.el10_2.0.1.x86_64"},

		{Vendor: "centos", Version: "8", MinKernel: "9.9.9-99.el9.x86_64"},
		{Vendor: "centos", Version: "9", MinKernel: "9.9.9-99.el9.x86_64"},
		{Vendor: "centos", Version: "10", MinKernel: "9.9.9-99.el10.x86_64"},
	}
}

func getProtectedKernels_CVE_2026_46331() []KernelRequirement {
	return []KernelRequirement{

		{Vendor: "debian", Version: "11", MinKernel: "5.10.0-45-amd64"},
		{Vendor: "debian", Version: "12", MinKernel: "6.1.0-50-amd64"},
		{Vendor: "debian", Version: "13", MinKernel: "6.12.94+deb13-amd64"},

		{Vendor: "ubuntu", Version: "22.04", MinKernel: "9.9.9-99-generic"},
		{Vendor: "ubuntu", Version: "24.04", MinKernel: "9.9.9-99-generic"},
		{Vendor: "ubuntu", Version: "25.04", MinKernel: "9.9.9-99-generic"},
		{Vendor: "ubuntu", Version: "26.04", MinKernel: "7.0.0-27-generic"},

		{Vendor: "almalinux", Version: "8.10", MinKernel: "4.18.0-553.136.1.el8_10.x86_64"},
		{Vendor: "almalinux", Version: "9.8",  MinKernel: "5.14.0-687.17.1.el9_8.x86_64"},
		{Vendor: "almalinux", Version: "10.2", MinKernel: "6.12.0-211.26.1.el10_2.x86_64"},

		{Vendor: "fedora", Version: "42", MinKernel: "6.19.14-108.fc42.x86_64"},
		{Vendor: "fedora", Version: "43", MinKernel: "7.0.12-101.fc43.x86_64"},
		{Vendor: "fedora", Version: "44", MinKernel: "7.0.12-201.fc44.x86_64"},

		{Vendor: "oracle", Version: "8.10", MinKernel: "5.15.0-322.203.3.2.el8uek.x86_64"},
		{Vendor: "oracle", Version: "9.7", MinKernel: "6.12.0-204.92.4.2.el9uek.x86_64"},
		{Vendor: "oracle", Version: "10.1", MinKernel: "6.12.0-204.92.4.2.el10uek.x86_64"},

		{Vendor: "rocky", Version: "8.10", MinKernel: "4.18.0-553.136.1.el8_10.x86_64"},
		{Vendor: "rocky", Version: "9.8", MinKernel: "5.14.0-687.17.1.el9_8.x86_64"},
		{Vendor: "rocky", Version: "10.2", MinKernel: "6.12.0-211.26.1.el10_2.x86_64"},

		{Vendor: "centos", Version: "8", MinKernel: "9.9.9-99.el9.x86_64"},
		{Vendor: "centos", Version: "9", MinKernel: "5.14.0-721.el9.x86_64"},
		{Vendor: "centos", Version: "10", MinKernel: "6.12.0-246.el10.x86_64"},
	}
}

func getMaxProtectedVersion_CVE_2026_31431(vendor string) string {
	switch vendor {
	case "debian":
		return "13"
	case "ubuntu":
		return "26.04"
	case "almalinux":
		return "10.1"
	case "fedora":
		return "43"
	case "oracle":
		return "10.1"
	case "rocky":
	    return "10.1"
	case "centos":
		return "10"
	default:
		return "0"
	}
}

func getMaxProtectedVersion_CVE_2026_43284(vendor string) string {
	switch vendor {
	case "debian":
		return "13"
	case "ubuntu":
		return "26.04"
	case "almalinux":
		return "10.1"
	case "fedora":
		return "43"
	case "oracle":
		return "10.1"
	case "rocky":
	    return "10.1"
	case "centos":
		return "10"
	default:
		return "0"
	}
}

func getMaxProtectedVersion_CVE_2026_46300(vendor string) string {
	switch vendor {
	case "debian":
		return "13"
	case "ubuntu":
		return "26.04"
	case "almalinux":
		return "10.1"
	case "fedora":
		return "43"
	case "oracle":
		return "10.1"
	case "rocky":
	    return "10.1"
	case "centos":
		return "10"
	default:
		return "0"
	}
}

func getMaxProtectedVersion_CVE_2026_46331(vendor string) string {
	switch vendor {
	case "debian":
		return "13"
	case "ubuntu":
		return "26.04"
	case "almalinux":
		return "10.2"
	case "fedora":
		return "43"
	case "oracle":
		return "10.1"
	case "rocky":
	    return "10.1"
	case "centos":
		return "10"
	default:
		return "0"
	}
}

func promptHotfix(cve string) bool {
	fmt.Printf("Apply hotfix for %s anyway ? [y/N]: ", cve)

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return false
	}

	b := make([]byte, 1)
	_, err = os.Stdin.Read(b)
	if err != nil || b[0] == 3 {
		term.Restore(int(os.Stdin.Fd()), oldState)
		fmt.Printf("\r\033[K\n\n%sInterrupted by user%s\n", red, reset)
		os.Exit(130)
	}

	char := string(b)
	input := strings.ToLower(strings.TrimSpace(char))

	displayChar := "N"
	isYes := false

	if input == "y" || input == "н" {
		displayChar = "y"
		isYes = true
	}

	term.Restore(int(os.Stdin.Fd()), oldState)

	fmt.Printf("\r\033[KApply hotfix for %s anyway ? [y/N]: %s\n", cve, displayChar)

	return isYes
}

func getVulnStatus() string {
	if hasBlacklistInCmdline() {
		return "kernel cmdline contains initcall_blacklist=algif_aead_init"
	}

	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return "AF_ALG socket creation failed (kernel/permissions restriction)"
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrALG{
		Type: "aead",
		Name: "authencesn(hmac(sha256),cbc(aes))",
	}

	if err := unix.Bind(fd, sa); err != nil {
		return "AF_ALG bind failed (algif_aead likely unavailable or blocked)"
	}

	return "AF_ALG bind success"
}

func check() bool {
	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrALG{
		Type: "aead",
		Name: "authencesn(hmac(sha256),cbc(aes))",
	}

	return unix.Bind(fd, sa) == nil
}

func root() bool {
	return os.Geteuid() == 0
}

func hasSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func applySystemdRestrict() bool {
	if !hasSystemd() {
		fmt.Printf("Adding systemd drop-in ( /etc/systemd/system/service.d/disable-algif-aead.conf ) - %sFAIL%s (no systemd)\n", red, reset)
		return false
	}

	_ = os.MkdirAll("/etc/systemd/system/service.d", 0755)

	path := "/etc/systemd/system/service.d/disable-algif-aead.conf"
	data := []byte("[Service]\nRestrictAddressFamilies=~AF_ALG\n")

	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Printf("Adding systemd drop-in ( /etc/systemd/system/service.d/disable-algif-aead.conf ) - %sFAIL%s : %v\n", red, reset, err)
		return false
	}

	fmt.Println("Running: systemctl daemon-reload")
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		fmt.Printf("Adding systemd drop-in ( /etc/systemd/system/service.d/disable-algif-aead.conf ) - %sFAIL%s : %v\n", red, reset, err)
		return false
	}

	fmt.Printf("Adding systemd drop-in ( /etc/systemd/system/service.d/disable-algif-aead.conf ) - %sOK%s\n", green, reset)
	return true
}

func isBuiltin(moduleName string) bool {
	output, err := exec.Command("modinfo", moduleName).CombinedOutput()
	if err != nil {
		return false
	}

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "filename:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "filename:"))
			return val == "(builtin)"
		}
	}

	return false
}

func skipCleanupForOS() []string {
	return []string{
		"ubuntu",
	}
}

func hasBlacklistInCmdline() bool {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "initcall_blacklist=algif_aead_init")
}

func isModuleBlacklistedInCmdline(moduleName string) bool {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false
	}
	cmdline := string(data)
	return strings.Contains(cmdline, "module_blacklist=") && strings.Contains(cmdline, moduleName)
}

func backupFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func restoreFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func updateGrubBlacklist() bool {
	if hasBlacklistInCmdline() {
		fmt.Printf("Blacklisting algif_aead module using grub - %sOK%s (already blacklisted)\n", green, reset)
		return true
	}

	if _, err := exec.LookPath("grubby"); err == nil {
		fmt.Println("Running: grubby --update-kernel=ALL --args=initcall_blacklist=algif_aead_init")
		if err := exec.Command("grubby", "--update-kernel=ALL", "--args=initcall_blacklist=algif_aead_init").Run(); err != nil {
			fmt.Printf("Blacklisting algif_aead module using grub - %sFAIL%s (grubby failed: %v)\n", red, reset, err)
			fmt.Printf("Falling back to grub config editing...\n")
		} else {
			fmt.Printf("Blacklisting algif_aead module using grub - %sOK%s\n", green, reset)
			return true
		}
	}

	backup := "/etc/default/grub.bak.afalg"
	grub := "/etc/default/grub"

	if _, err := os.Stat(backup); err != nil {
		_ = backupFile(grub, backup)
	}

	data, err := os.ReadFile(grub)
	if err != nil {
		fmt.Printf("Blacklisting algif_aead module using grub - %sFAIL%s (cannot read grub config: %v)\n", red, reset, err)
		return false
	}

	cfg := string(data)

	re := regexp.MustCompile(`(GRUB_CMDLINE_LINUX_DEFAULT\s*=\s*)"([^"]*)"`)
	matches := re.FindStringSubmatch(cfg)

	if len(matches) < 3 {
		fmt.Printf("Blacklisting algif_aead module using grub - %sFAIL%s (GRUB_CMDLINE_LINUX_DEFAULT not found)\n", red, reset)
		return false
	}

	currentValue := matches[2]

	if strings.Contains(currentValue, "initcall_blacklist=algif_aead_init") {
		fmt.Printf("Blacklisting algif_aead module using grub - %sOK%s (already in config)\n", green, reset)
		return true
	}

	var newValue string
	currentValue = strings.TrimSpace(currentValue)
	if currentValue == "" {
		newValue = "initcall_blacklist=algif_aead_init"
	} else {
		newValue = currentValue + " initcall_blacklist=algif_aead_init"
	}

	newLine := matches[1] + `"` + newValue + `"`
	cfg = re.ReplaceAllString(cfg, newLine)

	if err := os.WriteFile(grub, []byte(cfg), 0644); err != nil {
		fmt.Printf("Blacklisting algif_aead module using grub - %sFAIL%s (cannot write grub config: %v)\n", red, reset, err)
		return false
	}

	var errUpdate error
	if _, err := exec.LookPath("update-grub"); err == nil {
		fmt.Println("Running: update-grub")
		errUpdate = exec.Command("update-grub").Run()
	} else {
		fmt.Println("Running: grub-mkconfig -o /boot/grub/grub.cfg")
		errUpdate = exec.Command("grub-mkconfig", "-o", "/boot/grub/grub.cfg").Run()
	}

	if errUpdate != nil {
		_ = restoreFile(backup, grub)
		fmt.Printf("Blacklisting algif_aead module using grub - %sFAIL%s (grub update failed: %v)\n", red, reset, errUpdate)
		return false
	}

	fmt.Printf("Blacklisting algif_aead module using grub - %sOK%s\n", green, reset)
	return true
}

func disableModules(moduleNames []string) bool {
	allOk := true
	
	for _, moduleName := range moduleNames {
		builtin := isBuiltin(moduleName)
		
		if builtin {
			fmt.Printf("Checking %s is built in - %sYES%s (cannot disable)\n", moduleName, red, reset)
			allOk = false
		} else {
			fmt.Printf("Checking %s is built in - %sNO%s\n", moduleName, green, reset)
			
			if isModuleLoaded(moduleName) {
				fmt.Printf("Module %s is %sloaded%s\n", moduleName, red, reset)
			} else {
				fmt.Printf("Module %s is %snot loaded%s\n", moduleName, green, reset)
			}
			
			configPath := fmt.Sprintf("/etc/modprobe.d/disable-%s.conf", moduleName)
			configContent := fmt.Sprintf("install %s /bin/false\n", moduleName)
			
			if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
				fmt.Printf("Editing %s - %sFAIL%s : %v\n", configPath, red, reset, err)
				allOk = false
			} else {
				fmt.Printf("Editing %s - %sOK%s\n", configPath, green, reset)
			}

			if isModuleLoaded(moduleName) {
				_ = unix.DeleteModule(moduleName, 0)
				_ = unix.DeleteModule(moduleName, unix.O_NONBLOCK)
				_ = exec.Command("modprobe", "-r", moduleName).Run()
				_ = exec.Command("rmmod", "-f", moduleName).Run()
				
				if isModuleLoaded(moduleName) {
					fmt.Printf("Module %s %sstill loaded%s (reboot may be required)\n", moduleName, red, reset)
				} else {
					fmt.Printf("Module %s %sunloaded successfully%s\n", moduleName, green, reset)
				}
			}
		}
	}
	
	return allOk
}

func checkModuleDisabled(moduleName string) bool {
	configPath := fmt.Sprintf("/etc/modprobe.d/disable-%s.conf", moduleName)
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	
	expectedContent := fmt.Sprintf("install %s /bin/false", moduleName)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == expectedContent {
			return true
		}
	}
	
	return false
}

func isModuleActive(moduleName string) bool {
	return isBuiltin(moduleName) || isModuleLoaded(moduleName)
}

func hasAnyModuleActive(moduleNames []string) bool {
	for _, moduleName := range moduleNames {
		if isModuleActive(moduleName) {
			return true
		}
	}
	return false
}

func handleCVEMitigation(cve string, moduleNames []string) {
	vendor, version, kernelRelease := getSysInfo()

	var isProtectedOSMaxVersionFunc func() bool
	var isExactMatchFunc func() bool
	var protectedKernelsFunc func() []KernelRequirement
	
	switch cve {

		case "CVE-2026-31431":
			isProtectedOSMaxVersionFunc = isProtectedOSMaxVersion_CVE_2026_31431
			isExactMatchFunc = isExactOSMatch_CVE_2026_31431
			protectedKernelsFunc = getProtectedKernels_CVE_2026_31431
	
		case "CVE-2026-43284":
			isProtectedOSMaxVersionFunc = isProtectedOSMaxVersion_CVE_2026_43284
			isExactMatchFunc = isExactOSMatch_CVE_2026_43284
			protectedKernelsFunc = getProtectedKernels_CVE_2026_43284
	
		case "CVE-2026-46300":
		    isProtectedOSMaxVersionFunc = isProtectedOSMaxVersion_CVE_2026_46300
		    isExactMatchFunc = isExactOSMatch_CVE_2026_46300
		    protectedKernelsFunc = getProtectedKernels_CVE_2026_46300
	
		case "CVE-2026-46331":
		    isProtectedOSMaxVersionFunc = isProtectedOSMaxVersion_CVE_2026_46331
		    isExactMatchFunc = isExactOSMatch_CVE_2026_46331
		    protectedKernelsFunc = getProtectedKernels_CVE_2026_46331
	
		default:
			applyCVEModuleDisable(cve, moduleNames)
			return
	}
	
	knownOS := vendor == "ubuntu" || vendor == "debian" || vendor == "almalinux" || vendor == "fedora" || vendor == "oracle" || vendor == "rocky" || vendor == "centos"

	if knownOS && needMinorOSUpgrade(vendor, protectedKernelsFunc()) {
	
		fmt.Printf(
			"\n%s OS minor upgrade available%s (OS: %s %s)\n",
			green, reset, vendor, version,
		)
	
		switch promptMinorUpgrade(moduleNames...) {
	
		case 1:
	
			if tryMinorOSUpgrade() {
				os.Exit(0)
			}
	
			fmt.Println("\nProceeding with hotfix...")
	
		case 2:
	
			fmt.Println("\nProceeding with hotfix...")
	
		case 3:
	
			fmt.Println("Canceled by user")
			os.Exit(0)
		}
	}

	if !knownOS {
		fmt.Printf("%s - Unknown OS, applying hotfix directly...\n", cve)
		applyCVEModuleDisable(cve, moduleNames)
		return
	}
	
	if isExactMatchFunc() {
		if cve == "CVE-2026-46300" || cve == "CVE-2026-43284" {
			fmt.Printf("\nCVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 %svulnerable - kernel update available%s (OS: %s %s, current kernel: %s)\n",
				red, reset, vendor, version, kernelRelease)
		} else if cve == "CVE-2026-46331" {
			fmt.Printf("\n%s (PEdit-CoW) %svulnerable - kernel update available%s (OS: %s %s, current kernel: %s)\n",
				cve, red, reset, vendor, version, kernelRelease)
		} else {
			fmt.Printf("\n%s %svulnerable - kernel update available%s (OS: %s %s, current kernel: %s)\n",
				cve, red, reset, vendor, version, kernelRelease)
		}
	    handleKernelUpdate(moduleNames...)
            return
	}
	
	if isProtectedOSMaxVersionFunc() {
		if cve == "CVE-2026-46300" || cve == "CVE-2026-43284" {
			fmt.Printf("\nCVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 %snot vulnerable / blocked%s (OS: %s %s, current kernel: %s)\n",
				green, reset, vendor, version, kernelRelease)
		} else if cve == "CVE-2026-46331" {
			fmt.Printf("\n%s (PEdit-CoW) %snot vulnerable / blocked%s (OS: %s %s, current kernel: %s)\n",
				cve, green, reset, vendor, version, kernelRelease)
		} else {
			fmt.Printf("\n%s %snot vulnerable / blocked%s (OS: %s %s, current kernel: %s)\n",
				cve, green, reset, vendor, version, kernelRelease)
		}
		
		if !promptHotfix(cve) {
			fmt.Println("Canceled by user")
			return
		}
		applyCVEModuleDisable(cve, moduleNames)
		return
	}
	
	if isProtectedOS(protectedKernelsFunc) {
		if cve == "CVE-2026-46300" || cve == "CVE-2026-43284" {
			fmt.Printf("\nCVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 %snot vulnerable / blocked%s (OS: %s %s, current kernel: %s)\n",
				green, reset, vendor, version, kernelRelease)
		} else if cve == "CVE-2026-46331" {
			fmt.Printf("\n%s (PEdit-CoW) %snot vulnerable / blocked%s (OS: %s %s, current kernel: %s)\n",
				cve, green, reset, vendor, version, kernelRelease)
		} else {
			fmt.Printf("\n%s %snot vulnerable / blocked%s (OS: %s %s, current kernel: %s)\n",
				cve, green, reset, vendor, version, kernelRelease)
		}
		
		if !promptHotfix(cve) {
			fmt.Println("Canceled by user")
			return
		}
		applyCVEModuleDisable(cve, moduleNames)
		return
	}

	needFix := false
	
	for _, moduleName := range moduleNames {
		if isBuiltin(moduleName) {
			fmt.Printf("%s - Module %s is %sBUILTIN%s, mitigation needed\n", cve, moduleName, red, reset)
			needFix = true
			break
		}

		if !checkModuleDisabled(moduleName) {
			fmt.Printf("%s - Module %s is %snot disabled%s, mitigation needed\n", cve, moduleName, red, reset)
			needFix = true
			break
		}

		if isModuleLoaded(moduleName) {
			fmt.Printf("%s - Module %s is %sloaded%s, mitigation needed\n", cve, moduleName, red, reset)
			needFix = true
			break
		}
	}
	
	if !needFix {
		if cve == "CVE-2026-46300" || cve == "CVE-2026-43284" {
			fmt.Printf("\nCVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 %salready mitigated%s (all modules disabled)\n", green, reset)
		} else if cve == "CVE-2026-46331" {
			fmt.Printf("\n%s (PEdit-CoW) %salready mitigated%s (all modules disabled)\n", cve, green, reset)
		} else {
			fmt.Printf("\n%s %salready mitigated%s (all modules disabled)\n", cve, green, reset)
		}
		return
	}

	applyCVEModuleDisable(cve, moduleNames)
}

func applyCVEModuleDisable(cve string, moduleNames []string) {
	if !root() {
		fmt.Println("Need root / sudo to proceed")
		os.Exit(1)
	}
	
	if cve == "CVE-2026-46300" || cve == "CVE-2026-43284" {
		fmt.Printf("\nApplying CVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 mitigation by disabling modules: %s\n", strings.Join(moduleNames, ", "))
	} else if cve == "CVE-2026-46331" {
		fmt.Printf("\nApplying %s (PEdit-CoW) mitigation by disabling modules: %s\n", cve, strings.Join(moduleNames, ", "))
	} else {
		fmt.Printf("\nApplying %s mitigation by disabling modules: %s\n", cve, strings.Join(moduleNames, ", "))
	}
	
	disableModules(moduleNames)
	
	if cve == "CVE-2026-46331" {
		updateGrubBlacklist_46331()
	}
	
	_ = exec.Command("sync").Run()
	_ = os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0644)
	
	fmt.Println()
	
	if cve == "CVE-2026-31431" {
		modprobeOk := checkModuleDisabled("algif_aead")
		builtin := isBuiltin("algif_aead")
		grubOk := hasBlacklistInCmdline()
		
		if !builtin {
			_ = unix.DeleteModule("algif_aead", 0)
			_ = unix.DeleteModule("algif_aead", unix.O_NONBLOCK)
			_ = exec.Command("modprobe", "-r", "algif_aead").Run()
			_ = exec.Command("rmmod", "-f", "algif_aead").Run()
		}

		runtimeFixed := false

		if modprobeOk && !builtin {
			if !check() {
				runtimeFixed = true
				fmt.Println("Hotfix " + green + "SUCCESS" + reset + ". Reboot not required.")
			} else {
				fmt.Println("algif_aead still functional")
			}
		}

		if !runtimeFixed {
			if grubOk {
				fmt.Println("Reboot required. Run me again after that to get the result")
			} else {
				fmt.Println("Hotfix " + red + "FAILED" + reset + " - no effective mitigation applied")
			}
		}
		return
	}
	
	allDisabled := true
	for _, moduleName := range moduleNames {
		if !checkModuleDisabled(moduleName) && !isBuiltin(moduleName) {
			allDisabled = false
			break
		}
	}
	
	anyBuiltin := false
	for _, moduleName := range moduleNames {
		if isBuiltin(moduleName) {
			anyBuiltin = true
			break
		}
	}
	
	if allDisabled {
		if anyBuiltin {
			if cve == "CVE-2026-46300" || cve == "CVE-2026-43284" {
				fmt.Printf("CVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 Hotfix %srequires reboot%s (modules are builtin, grub blacklist applied)\n", red, reset)
			} else if cve == "CVE-2026-46331" {
				fmt.Printf("%s (PEdit-CoW) Hotfix %srequires reboot%s (module is builtin, grub blacklist applied)\n", cve, red, reset)
			} else {
				fmt.Printf("%s Hotfix %srequires reboot%s (modules are builtin, grub blacklist applied)\n", cve, red, reset)
			}
		} else {
			if cve == "CVE-2026-46300" || cve == "CVE-2026-43284" {
				fmt.Printf("CVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 Hotfix %ssuccess%s. Modules disabled. Reboot not required.\n", green, reset)
			} else if cve == "CVE-2026-46331" {
				fmt.Printf("%s (PEdit-CoW) Hotfix %ssuccess%s. Modules disabled. Reboot not required.\n", cve, green, reset)
			} else {
				fmt.Printf("%s Hotfix %ssuccess%s. Modules disabled. Reboot not required.\n", cve, green, reset)
			}
		}
	} else {
		if cve == "CVE-2026-46300" || cve == "CVE-2026-43284" {
			fmt.Printf("CVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 Hotfix %spartial%s - Some modules could not be disabled\n", red, reset)
		} else if cve == "CVE-2026-46331" {
			fmt.Printf("%s (PEdit-CoW) Hotfix %spartial%s - Some modules could not be disabled\n", cve, red, reset)
		} else {
			fmt.Printf("%s Hotfix %spartial%s - Some modules could not be disabled\n", cve, red, reset)
		}
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-v" {
		fmt.Printf("2026 Frag family CVE mitigation tool v%s\n", version)
		os.Exit(0)
	}

	fmt.Printf("2026 Frag family CVE mitigation tool v%s\n\n", version)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		fmt.Printf("\n\n%sInterrupted by user%s\n", red, reset)
		os.Exit(130)
	}()

	vendor, version, kernelRelease := getSysInfo()

	wsl := isWSL()

	if wsl {
		if !check() {
			fmt.Printf("CVE-2026-31431 %snot vulnerable / blocked%s", green, reset)
			fmt.Println(" (" + getVulnStatus() + ")")
		} else {
			fmt.Printf("%s=== WSL Mitigation Instructions ===%s\nTo mitigate CVE-2026-31431 in WSL2, add to %%userprofile%%\\.wslconfig:\n\n[wsl2]\nkernelCommandLine=module_blacklist=algif_aead\n\nThen restart WSL with: wsl --shutdown\n", red, reset)
		}
	
		cve43284Modules := []string{"esp4", "esp6", "rxrpc"}
		cve43284Vulnerable := false
		for _, mod := range cve43284Modules {
			if isBuiltin(mod) || isModuleLoaded(mod) || !isModuleBlacklistedInCmdline(mod) {
				cve43284Vulnerable = true
				break
			}
		}
		
		if !cve43284Vulnerable {
			fmt.Printf("\nCVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 %snot vulnerable / blocked%s (modules blacklisted)\n", green, reset)
		} else {
			fmt.Printf("\n%s=== WSL Mitigation Instructions ===%s\nTo mitigate CVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 in WSL2, add to %%userprofile%%\\.wslconfig:\n\n[wsl2]\nkernelCommandLine=module_blacklist=rxrpc,esp4,esp6\n\nThen restart WSL with: wsl --shutdown\n", red, reset)
		}
		
		cve46331Vulnerable := isBuiltin("act_pedit") || isModuleLoaded("act_pedit") || !isModuleBlacklistedInCmdline("act_pedit")
		if !cve46331Vulnerable {
			fmt.Printf("\nCVE-2026-46331 (PEdit-CoW) %snot vulnerable / blocked%s (module blacklisted)\n", green, reset)
		} else {
			fmt.Printf("\n%s=== WSL Mitigation Instructions ===%s\nTo mitigate CVE-2026-46331 (PEdit-CoW) in WSL2, add to %%userprofile%%\\.wslconfig:\n\n[wsl2]\nkernelCommandLine=module_blacklist=act_pedit\n\nThen restart WSL with: wsl --shutdown\n", red, reset)
		}
		return
	}

	knownOSCheck := vendor == "ubuntu" || vendor == "debian" || vendor == "almalinux" || vendor == "fedora" || vendor == "oracle" || vendor == "rocky" || vendor == "centos"

	cleanedUp31431 := false
	if knownOSCheck && (isProtectedOSMaxVersion_CVE_2026_31431() || isProtectedOS(getProtectedKernels_CVE_2026_31431)) {
		skipOS := false
		for _, os := range skipCleanupForOS() {
			if vendor == os {
				skipOS = true
				break
			}
		}
		if !skipOS && hasAnyHotfixArtifacts_31431() && root() {
			fmt.Printf("CVE-2026-31431 %snot vulnerable / blocked%s (OS: %s %s, current kernel: %s)\n",
				green, reset, vendor, version, kernelRelease)
			cleanupHotfix_31431()
			cleanedUp31431 = true
		}
	}

	cleanedUp43284 := false
	protectedFrom43284 := isProtectedOSMaxVersion_CVE_2026_43284() || isProtectedOS(getProtectedKernels_CVE_2026_43284)
	protectedFrom46300 := isProtectedOSMaxVersion_CVE_2026_46300() || isProtectedOS(getProtectedKernels_CVE_2026_46300)
	
	if knownOSCheck && protectedFrom43284 && protectedFrom46300 {
	    skipOS := false
	    for _, os := range skipCleanupForOS() {
	        if vendor == os {
	            skipOS = true
	            break
	        }
	    }

	    if !skipOS && hasAnyHotfixArtifacts_43284() && root() && !hasAnyModuleActive([]string{"esp4", "esp6", "rxrpc"}) {
	        fmt.Printf("\nCVE-2026-46300 / CVE-2026-43500 / CVE-2026-43284 %snot vulnerable / blocked%s (OS: %s %s, current kernel: %s)\n",
	            green, reset, vendor, version, kernelRelease)
	        cleanupHotfix_43284()
	        cleanedUp43284 = true
	    }
	}

	cleanedUp46331 := false
	protectedFrom46331 := isProtectedOSMaxVersion_CVE_2026_46331() || isProtectedOS(getProtectedKernels_CVE_2026_46331)
	
	if knownOSCheck && protectedFrom46331 {
	    skipOS := false
	    for _, os := range skipCleanupForOS() {
	        if vendor == os {
	            skipOS = true
	            break
	        }
	    }

	    if !skipOS && hasAnyHotfixArtifacts_46331() && root() && !hasAnyModuleActive([]string{"act_pedit"}) {
	        fmt.Printf("\nCVE-2026-46331 (PEdit-CoW) %snot vulnerable / blocked%s (OS: %s %s, current kernel: %s)\n",
	            green, reset, vendor, version, kernelRelease)
	        cleanupHotfix_46331()
	        cleanedUp46331 = true
	    }
	}

	if cleanedUp31431 || cleanedUp43284 || cleanedUp46331 {
		if !cleanedUp43284 {
			handleCVEMitigation("CVE-2026-46300", []string{"esp4", "esp6", "rxrpc"})
		}
		if !cleanedUp46331 {
			handleCVEMitigation("CVE-2026-46331", []string{"act_pedit"})
		}
		os.Exit(0)
	}

	knownOS := vendor == "ubuntu" || vendor == "debian" || vendor == "almalinux" || vendor == "fedora" || vendor == "oracle" || vendor == "rocky" || vendor == "centos"

	if knownOS {
		needHotfix31431 := false
		forcedHotfix31431 := false

		if isProtectedOSMaxVersion_CVE_2026_31431() {
			fmt.Printf("CVE-2026-31431 %snot vulnerable / blocked%s (OS: %s %s,  current kernel: %s)\n",
				green, reset, vendor, version, kernelRelease)

			if !promptHotfix("CVE-2026-31431") {
				fmt.Println("Canceled by user")
				goto handle43284
			}
			needHotfix31431 = true
			forcedHotfix31431 = true
		}

		if !needHotfix31431 && isProtectedOS(getProtectedKernels_CVE_2026_31431) {
			fmt.Printf("CVE-2026-31431 %snot vulnerable / blocked%s (OS: %s %s, current kernel: %s)\n",
				green, reset, vendor, version, kernelRelease)

			if !promptHotfix("CVE-2026-31431") {
				fmt.Println("Canceled by user")
				goto handle43284
			}
			needHotfix31431 = true
			forcedHotfix31431 = true
		}

		if !needHotfix31431 && isExactOSMatch_CVE_2026_31431() {
			fmt.Printf("CVE-2026-31431 %svulnerable - kernel update available%s (OS: %s %s, current kernel: %s)\n",
				red, reset, vendor, version, kernelRelease)

			handleKernelUpdate("algif_aead")
			needHotfix31431 = true
		}

		if !needHotfix31431 {
			if !check() {
				fmt.Print("CVE-2026-31431 ", green+"not vulnerable / blocked"+reset)
				fmt.Println(" (" + getVulnStatus() + ")")
			} else {
				needHotfix31431 = true
			}
		}

		if needHotfix31431 && !root() {
			fmt.Println("Need root / sudo to proceed")
			os.Exit(1)
		}

		if needHotfix31431 {
			if !forcedHotfix31431 {
				fmt.Println("CVE-2026-31431 " + red + "vulnerable (pre-condition met)" + reset + " kernel\n")
			} else {
				fmt.Println("\nApplying hotfix as requested...\n")
			}

			applySystemdRestrict()
			updateGrubBlacklist()
			applyCVEModuleDisable("CVE-2026-31431", []string{"algif_aead"})
			
			fmt.Println()
		}
	} else {
		if check() {
			if !root() {
				fmt.Println("CVE-2026-31431", red+"vulnerable (pre-condition met) "+reset+"kernel (no root to fix)")
				os.Exit(1)
			}
			fmt.Println("CVE-2026-31431 " + red + "vulnerable (pre-condition met)" + reset + " kernel\n")
			applySystemdRestrict()
			updateGrubBlacklist()
			applyCVEModuleDisable("CVE-2026-31431", []string{"algif_aead"})
		}
	}

handle43284:
	handleCVEMitigation("CVE-2026-46300", []string{"esp4", "esp6", "rxrpc"})
	handleCVEMitigation("CVE-2026-46331", []string{"act_pedit"})
}