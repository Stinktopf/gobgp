package table

import (
	"fmt"
	"os"
	"strings"
)

type OperaMode int

const (
	OperaDisabled OperaMode = iota
	OperaEnabled
)

var operaConfig struct {
	mode OperaMode
	asn  uint32
}

func InitOperaFromEnv() {
	val := os.Getenv("GOBGP_OPERA_ENABLED")
	if val == "1" || strings.ToLower(val) == "true" {
		SetOperaMode(OperaEnabled)
		fmt.Println("[OPERA] ALTERNATIVE PATH SELECTION ENABLED")
	} else {
		SetOperaMode(OperaDisabled)
		fmt.Println("[OPERA] ALTERNATIVE PATH SELECTION DISABLED")
	}
	if v := os.Getenv("ASN"); v != "" {
		var parsed uint64
		fmt.Sscanf(v, "%d", &parsed)
		operaConfig.asn = uint32(parsed)
	}
}

func SetOperaMode(mode OperaMode) {
	operaConfig.mode = mode
}
func IsOperaEnabled() bool {
	return getOperaMode() == OperaEnabled
}
func getOperaMode() OperaMode {
	return operaConfig.mode
}

func OperaImportAccept(known []*Path, cand *Path) bool {
	if !IsOperaEnabled() || cand.IsWithdraw {
		return true
	}
	return OperaImportAcceptInternal(known, cand)
}

func OperaImportAcceptInternal(known []*Path, cand *Path) bool {
	var worstKnownPath *Path = nil

	for _, existing := range known {
		if existing == nil || existing.IsWithdraw {
			continue
		}

		if worstKnownPath == nil {
			worstKnownPath = existing
		} else if IsWorseOperaPath(existing, worstKnownPath) {
			worstKnownPath = existing
		}
	}

	if worstKnownPath == nil {
		return true
	}

	return IsBetterOperaPath(cand, worstKnownPath)
}

func IsBetterOperaPath(newPath, existingPath *Path) bool {
	if newPath == nil || existingPath == nil {
		return false
	}
	newLen := newPath.GetAsPathLen()
	exLen := existingPath.GetAsPathLen()
	if newLen != exLen {
		return newLen < exLen
	}
	newAsPath := newPath.GetAsPath()
	exAsPath := existingPath.GetAsPath()
	if newAsPath == nil || exAsPath == nil {
		return false
	}
	newSegs := newAsPath.Value
	exSegs := exAsPath.Value
	for i := 0; i < len(newSegs); i++ {
		if i >= len(exSegs) {
			break
		}
		newASList := newSegs[i].GetAS()
		exASList := exSegs[i].GetAS()
		minL := len(newASList)
		if len(exASList) < minL {
			minL = len(exASList)
		}
		for j := 0; j < minL; j++ {
			if newASList[j] != exASList[j] {
				return newASList[j] < exASList[j]
			}
		}
	}
	return false
}

func IsWorseOperaPath(newPath, existingPath *Path) bool {
	if newPath == nil || existingPath == nil {
		return false
	}
	newLen := newPath.GetAsPathLen()
	exLen := existingPath.GetAsPathLen()
	if newLen != exLen {
		return newLen > exLen
	}
	newAsPath := newPath.GetAsPath()
	exAsPath := existingPath.GetAsPath()
	if newAsPath == nil || exAsPath == nil {
		return false
	}
	newSegs := newAsPath.Value
	exSegs := exAsPath.Value
	for i := 0; i < len(newSegs); i++ {
		if i >= len(exSegs) {
			break
		}
		newASList := newSegs[i].GetAS()
		exASList := exSegs[i].GetAS()
		minL := len(newASList)
		if len(exASList) < minL {
			minL = len(exASList)
		}
		for j := 0; j < minL; j++ {
			if newASList[j] != exASList[j] {
				return newASList[j] > exASList[j]
			}
		}
	}
	return false
}
