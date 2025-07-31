package table

import (
	"fmt"
	"os"
)

type OperaMode int

const (
	OperaDisabled OperaMode = iota
	OperaEnabled
)

var operaConfig struct {
	mode OperaMode
}

func InitOperaFromEnv() {
	val := os.Getenv("GOBGP_OPERA_ENABLED")
	if val == "1" || val == "true" {
		SetOperaMode(OperaEnabled)
		fmt.Println("OPERA is ENABLED")
		fmt.Println("To disable OPERA, unset GOBGP_OPERA_ENABLED or set it to 0 or false.")
		fmt.Println("Windows CMD: set GOBGP_OPERA_ENABLED=0")
		fmt.Println("PowerShell:  $env:GOBGP_OPERA_ENABLED=\"0\"")
		fmt.Println("Linux/macOS: export GOBGP_OPERA_ENABLED=false")
	} else {
		SetOperaMode(OperaDisabled)
		fmt.Println("OPERA is DISABLED")
		fmt.Println("To enable OPERA, set GOBGP_OPERA_ENABLED=1 or true.")
		fmt.Println("Windows CMD: set GOBGP_OPERA_ENABLED=1")
		fmt.Println("PowerShell:  $env:GOBGP_OPERA_ENABLED=\"1\"")
		fmt.Println("Linux/macOS: export GOBGP_OPERA_ENABLED=true")
	}
}

func SetOperaMode(mode OperaMode) {
	operaConfig.mode = mode
}

func getOperaMode() OperaMode {
	return operaConfig.mode
}

func isOperaEnabled() bool {
	return getOperaMode() == OperaEnabled
}

func isBetterOperaPath(newPath, existingPath *Path) bool {
	newPathLength := newPath.GetAsPathLen()
	existingPathLength := existingPath.GetAsPathLen()
	if newPathLength != existingPathLength {
		return newPathLength < existingPathLength
	}

	newSegments := newPath.GetAsPath().Value
	existingSegments := existingPath.GetAsPath().Value

	for segmentIndex := 0; segmentIndex < len(newSegments); segmentIndex++ {
		newASList := newSegments[segmentIndex].GetAS()
		existingASList := existingSegments[segmentIndex].GetAS()

		minLength := len(newASList)
		if len(existingASList) < minLength {
			minLength = len(existingASList)
		}

		for asIndex := 0; asIndex < minLength; asIndex++ {
			newASNumber := newASList[asIndex]
			existingASNumber := existingASList[asIndex]
			if newASNumber != existingASNumber {
				return newASNumber < existingASNumber
			}
		}

	}

	return false
}
