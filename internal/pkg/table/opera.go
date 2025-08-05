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

func IsOperaEnabled() bool {
	return getOperaMode() == OperaEnabled
}

func GetOperaType(p *Path) string {
	if HasOperaPath(p, 100) {
		return "highbw"
	}
	if HasOperaPath(p, 200) {
		return "lowlat"
	}
	return "standard"
}

func HasOperaPath(path *Path, suffix uint16) bool {
	asList := path.GetAsList()
	if len(asList) == 0 {
		return false
	}

	communities := path.GetCommunities()

	asToSuffix := make(map[uint32]map[uint16]bool)
	for _, c := range communities {
		asn := c >> 16
		suf := uint16(c & 0xFFFF)

		if _, exists := asToSuffix[asn]; !exists {
			asToSuffix[asn] = make(map[uint16]bool)
		}
		asToSuffix[asn][suf] = true
	}

	for _, asn := range asList {
		if suffixes, ok := asToSuffix[asn]; !ok || !suffixes[suffix] {
			return false
		}
	}

	return true
}

func getOperaMode() OperaMode {
	return operaConfig.mode
}

func isBetterOperaPath(newPath, existingPath *Path) bool {
	if newPath == nil || existingPath == nil {
		return false
	}

	newPathLength := newPath.GetAsPathLen()
	existingPathLength := existingPath.GetAsPathLen()
	if newPathLength != existingPathLength {
		return newPathLength < existingPathLength
	}

	newAsPath := newPath.GetAsPath()
	existingAsPath := existingPath.GetAsPath()
	if newAsPath == nil || existingAsPath == nil {
		return false
	}

	newSegments := newAsPath.Value
	existingSegments := existingAsPath.Value

	for segmentIndex := 0; segmentIndex < len(newSegments); segmentIndex++ {
		if segmentIndex >= len(existingSegments) {
			break
		}

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
