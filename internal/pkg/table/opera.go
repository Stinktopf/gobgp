package table

import (
	"fmt"
	"os"
	"strings"
)

type OperaMode int
type OperaKind int

const (
	OperaDisabled OperaMode = iota
	OperaEnabled
)

const (
	OperaFuzzy OperaKind = iota
	OperaBitfield
)

var operaConfig struct {
	mode OperaMode
	kind OperaKind
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
	switch strings.ToLower(os.Getenv("GOBGP_OPERA_MODE")) {
	case "bitfield":
		operaConfig.kind = OperaBitfield
		fmt.Println("[OPERA] MODE: BITFIELD")
	default:
		operaConfig.kind = OperaFuzzy
		fmt.Println("[OPERA] MODE: FUZZY")
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

func IsOperaBitfieldMode() bool {
	return operaConfig.kind == OperaBitfield
}

func GetOperaType(p *Path) string {
	if p == nil {
		return "STANDARD"
	}
	if IsOperaBitfieldMode() {
		ok, capExp, sumLat := bitfieldMetrics(p)
		if !ok {
			return "STANDARD"
		}
		return fmt.Sprintf("OPERA(%s,%dms)", humanCap(capExp), sumLat)
	}
	if HasOperaPath(p, 100) {
		return "HIGH-BANDWIDTH"
	}
	if HasOperaPath(p, 200) {
		return "LOW-LATENCY"
	}
	return "STANDARD"
}

func HasOperaPath(path *Path, suffix uint16) bool {
	asList := path.GetAsList()
	if len(asList) == 0 {
		return false
	}
	if len(asList) == 1 {
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
	for _, asn := range asList[:len(asList)-1] {
		if suffixes, ok := asToSuffix[asn]; !ok || !suffixes[suffix] {
			return false
		}
	}
	return true
}

func OperaImportAccept(known []*Path, cand *Path) bool {
	if !IsOperaEnabled() || cand.IsWithdraw {
		return true
	}

	if IsOperaBitfieldMode() {
		return OperaImportAcceptBitfield(known, cand)
	}
	return OperaImportAcceptFuzzy(known, cand)
}

func OperaImportAcceptBitfield(known []*Path, cand *Path) bool {
	okCand, capCand, latCand := GetBitfieldMetrics(cand)

	for _, existing := range known {
		if existing == nil || existing.IsWithdraw {
			continue
		}

		okEx, capEx, latEx := GetBitfieldMetrics(existing)

		if okCand && okEx {
			if !(capCand > capEx || latCand < latEx) {
				return false
			}
		} else {
			if !IsBetterOperaPath(cand, existing) {
				return false
			}
		}
	}
	return true
}

func OperaImportAcceptFuzzy(known []*Path, cand *Path) bool {
	candType := GetOperaType(cand)

	for _, existing := range known {
		if existing == nil || existing.IsWithdraw {
			continue
		}

		existingType := GetOperaType(existing)

		if existingType == candType {
			if !IsBetterOperaPath(cand, existing) {
				return false
			}
		}
	}
	return true
}

func IsBetterOperaPath(newPath, existingPath *Path) bool {
	if newPath == nil || existingPath == nil {
		return false
	}
	newPathLength := newPath.GetAsPathLen()
	existingPathLength := existingPath.GetAsPathLen()
	if newPathLength != existingPathLength {
		return newPathLength > existingPathLength
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
				return newASNumber > existingASNumber
			}
		}
	}
	return false
}

func bitfieldMetrics(p *Path) (ok bool, minCapExp uint8, sumLatMs uint32) {
	asList := p.GetAsList()
	if len(asList) == 0 {
		return false, 0, 0
	}
	communities := p.GetCommunities()
	asToPairs := make(map[uint32][][2]uint8)
	for _, c := range communities {
		asn := c >> 16
		suf := uint16(c & 0xFFFF)
		capExp := uint8(suf >> 8)
		latMs := uint8(suf & 0xFF)
		asToPairs[asn] = append(asToPairs[asn], [2]uint8{capExp, latMs})
	}

	checkAS := []uint32{}
	if operaConfig.asn != 0 {
		checkAS = append(checkAS, operaConfig.asn)
	}
	checkAS = append(checkAS, asList[:len(asList)-1]...)

	minCap := uint8(255)
	var sumLat uint32
	for _, asn := range checkAS {
		pairs, ok := asToPairs[asn]
		if !ok || len(pairs) == 0 {
			return false, 0, 0
		}
		bestCap := uint8(0)
		bestLat := uint8(255)
		for _, pr := range pairs {
			cExp, lMs := pr[0], pr[1]
			if cExp > bestCap {
				bestCap = cExp
			}
			if lMs < bestLat {
				bestLat = lMs
			}
		}
		if bestCap < minCap {
			minCap = bestCap
		}
		sumLat += uint32(bestLat)
	}
	return true, minCap, sumLat
}

func GetBitfieldMetrics(p *Path) (bool, uint8, uint32) {
	return bitfieldMetrics(p)
}

func humanCap(exp uint8) string {
	mbps := float64(uint64(1) << exp)
	switch {
	case mbps >= 1_000_000:
		return fmt.Sprintf("%.1fTbps", mbps/1_000_000)
	case mbps >= 1_000:
		g := mbps / 1_000
		if g == float64(int64(g)) {
			return fmt.Sprintf("%.0fGbps", g)
		}
		return fmt.Sprintf("%.1fGbps", g)
	default:
		if mbps == float64(int64(mbps)) {
			return fmt.Sprintf("%.0fMbps", mbps)
		}
		return fmt.Sprintf("%.1fMbps", mbps)
	}
}
