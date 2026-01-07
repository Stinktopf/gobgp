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

var operaBandwidthLUT = []uint64{
	0, 10, 100, 1000, 10000, 25000, 40000, 100000, 200000, 400000, 800000, 1600000,
}

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

var operaDebug = false

func SetOperaDebug(enabled bool) {
	operaDebug = enabled
}
func IsOperaDebug() bool {
	return operaDebug
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

func GetOperaType(p *Path) string {
	if p == nil || !IsOperaEnabled() {
		return "STANDARD"
	}
	coverage, capIndex, sumLat := GetOperaMetrics(p)
	if coverage == 0.0 {
		return "STANDARD"
	} else if coverage == 1.0 {
		return fmt.Sprintf("OPERA-COMPLETE(%s,%dms)", humanBandwidth(capIndex), sumLat)
	} else {
		return fmt.Sprintf("OPERA-PARTIAL[%.0f%%](%s,%dms)", coverage*100, humanBandwidth(capIndex), sumLat)
	}
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

func calculateMetrics(p *Path) (coverage uint16, minCapIndex uint8, sumLatMs uint32) {
	asList := p.GetAsList()
	totalIntermediateHops := 0
	if len(asList) > 1 {
		totalIntermediateHops = len(asList) - 1
		if operaConfig.asn != 0 {
			totalIntermediateHops++
		}
	}
	if totalIntermediateHops == 0 {
		return 10000, 0, 0 // 1.0 * 10000
	}

	communities := p.GetCommunities()
	asToPairs := make(map[uint32][][2]uint8)
	for _, c := range communities {
		asn := c >> 16
		suf := uint16(c & 0xFFFF)
		capIndex := uint8(suf >> 8)
		latMs := uint8(suf & 0xFF)
		asToPairs[asn] = append(asToPairs[asn], [2]uint8{capIndex, latMs})
	}

	checkAS := []uint32{}
	if operaConfig.asn != 0 {
		checkAS = append(checkAS, operaConfig.asn)
	}
	checkAS = append(checkAS, asList[:len(asList)-1]...)

	minCapIndex = 0
	var sumLat uint32
	participatingHops := 0

	for _, asn := range checkAS {
		pairs, ok := asToPairs[asn]
		if !ok || len(pairs) == 0 {
			continue
		}

		participatingHops++
		bestCapIndex := uint8(255)
		bestLat := uint8(255)

		for _, pr := range pairs {
			cIdx, lMs := pr[0], pr[1]
			if cIdx < bestCapIndex {
				bestCapIndex = cIdx
			}
			if lMs < bestLat {
				bestLat = lMs
			}
		}

		if bestCapIndex > minCapIndex {
			minCapIndex = bestCapIndex
		}
		sumLat += uint32(bestLat)
	}

	if participatingHops == 0 {
		return 0, 0, 0
	}

	ratio := float64(participatingHops) / float64(totalIntermediateHops)
	if ratio > 1.0 {
		ratio = 1.0
	}
	coverage = uint16(ratio * 10000.0)
	return coverage, minCapIndex, sumLat
}

func GetOperaMetrics(p *Path) (float64, uint8, uint32) {
	if p == nil {
		return 0.0, 0, 0
	}

	p.operaCache.RLock()
	if p.operaCache.valid {
		cov := p.operaCache.coverage
		capIdx := p.operaCache.capIndex
		sumLat := p.operaCache.sumLat
		p.operaCache.RUnlock()
		return float64(cov) / 10000.0, capIdx, sumLat
	}
	p.operaCache.RUnlock()

	cov, capIdx, lat := calculateMetrics(p)

	p.operaCache.Lock()
	p.operaCache.coverage = cov
	p.operaCache.capIndex = capIdx
	p.operaCache.sumLat = lat
	p.operaCache.valid = true
	p.operaCache.Unlock()

	return float64(cov) / 10000.0, capIdx, lat
}

func humanBandwidth(index uint8) string {
	if index >= uint8(len(operaBandwidthLUT)) {
		return fmt.Sprintf("Idx!%d", index)
	}
	mbps := float64(operaBandwidthLUT[index])
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

func AsPath(p *Path) string {
	l := p.GetAsList()
	if len(l) == 0 {
		return "<EMPTY>"
	}
	s := make([]string, len(l))
	for i, as := range l {
		s[i] = fmt.Sprintf("%d", as)
	}
	return strings.Join(s, " ")
}
