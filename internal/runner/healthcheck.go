package runner

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/projectdiscovery/interactsh/pkg/options"
	fileutil "github.com/projectdiscovery/utils/file"
)

// DoHealthCheck performs healthcheck on server and client
func DoHealthCheck(cfgFilePath string) string {
	// RW permissions on config file
	var test strings.Builder
	test.WriteString(fmt.Sprintf("Version: %s\n", options.Version))
	test.WriteString(fmt.Sprintf("Operative System: %s\n", runtime.GOOS))
	test.WriteString(fmt.Sprintf("Architecture: %s\n", runtime.GOARCH))
	test.WriteString(fmt.Sprintf("Go Version: %s\n", runtime.Version()))
	test.WriteString(fmt.Sprintf("Compiler: %s\n", runtime.Compiler))

	var testResult string
	ok, err := fileutil.IsReadable(cfgFilePath)
	if ok {
		testResult = "Ok"
	} else {
		testResult = "Ko"
	}
	if err != nil {
		testResult += fmt.Sprintf(" (%s)", err)
	}
	test.WriteString(fmt.Sprintf("Config file \"%s\" Read => %s\n", cfgFilePath, testResult))
	ok, err = fileutil.IsWriteable(cfgFilePath)
	if ok {
		testResult = "Ok"
	} else {
		testResult = "Ko"
	}
	if err != nil {
		testResult += fmt.Sprintf(" (%s)", err)
	}
	test.WriteString(fmt.Sprintf("Config file \"%s\" Write => %s\n", cfgFilePath, testResult))
	c3, err := net.Dial("udp", "scanme.sh:53")
	if err == nil && c3 != nil {
		c3.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("UDP connectivity to scanme.sh:53 => %s\n", testResult))
	c4, err := net.Dial("tcp4", "scanme.sh:80")
	if err == nil && c4 != nil {
		c4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("IPv4 connectivity to scanme.sh:80 => %s\n", testResult))
	c6, err := net.Dial("tcp6", "scanme.sh:80")
	if err == nil && c6 != nil {
		c6.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("IPv6 connectivity to scanme.sh:80 => %s\n", testResult))

	return test.String()
}
