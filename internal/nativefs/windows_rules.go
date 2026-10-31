package nativefs

import (
	"encoding/binary"
	"strings"
)

// The Windows candidate deliberately qualifies only exact printable-ASCII long
// names. Unicode/case-fold equivalence and DOS short-name aliases are not proof.
// These rules are also executed by the portable boundary tests, not NT models.
func winComponent(s string) error {
	if len(s) == 0 || len(s) > 255 || s == "." || s == ".." || s[len(s)-1] == '.' || s[len(s)-1] == ' ' || s[0] == '$' {
		return ErrPath
	}
	for _, c := range s {
		if c < 32 || c > 126 || strings.ContainsRune(`\/:*?"<>|~`, c) {
			return ErrPath
		}
	}
	base := strings.ToUpper(strings.TrimRight(strings.SplitN(s, ".", 2)[0], " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return ErrPath
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return ErrPath
	}
	return nil
}
func winRootPath(s string) (string, []string, error) {
	s = strings.ReplaceAll(s, "/", `\`)
	if len(s) < 3 || len(s) > 4096 || s[1] != ':' || s[2] != '\\' || !((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) {
		return "", nil, ErrPath
	}
	drive := strings.ToUpper(s[:2])
	if len(s) == 3 {
		return drive, nil, nil
	}
	parts := strings.Split(s[3:], `\`)
	if len(parts) > 128 {
		return "", nil, ErrLimit
	}
	for _, p := range parts {
		if winComponent(p) != nil {
			return "", nil, ErrPath
		}
	}
	return drive, parts, nil
}
func winLinkPath(prefix []string, target string, tail []string) (string, error) {
	if len(target) == 0 || len(target) > 4096 || strings.HasPrefix(target, "/") || strings.Contains(target, `\`) {
		return "", ErrPath
	}
	p := append([]string(nil), prefix...)
	for _, c := range strings.Split(target, "/") {
		switch c {
		case "..":
			if len(p) == 0 {
				return "", ErrPath
			}
			p = p[:len(p)-1]
		case ".":
		case "":
			return "", ErrPath
		default:
			if winComponent(c) != nil {
				return "", ErrPath
			}
			p = append(p, c)
		}
	}
	p = append(p, tail...)
	name := strings.Join(p, "/")
	if len(p) == 0 {
		return ".", nil
	}
	if validRelative(name) != nil {
		return "", ErrPath
	}
	return name, nil
}

// FILE_FS_DEVICE_INFORMATION and FILE_FS_ATTRIBUTE_INFORMATION replies.
// MS-FSA specifies underlying FILE_DEVICE_DISK (7). This is a bootstrap
// qualification, NOT an argument that an arbitrary opened disk is safe.
func winVolumeReply(device, attributes []byte) error {
	if len(device) < 8 || len(attributes) < 20 || binary.LittleEndian.Uint32(device) != 7 || binary.LittleEndian.Uint32(device[4:])&0x10 != 0 || binary.LittleEndian.Uint32(attributes[4:]) != 255 || binary.LittleEndian.Uint32(attributes[8:]) != 8 {
		return ErrUnavailable
	}
	if string(attributes[12:20]) != "N\x00T\x00F\x00S\x00" {
		return ErrUnavailable
	}
	return nil
}

func winSame(a, b stamp) bool { return a.dev == b.dev && a.ino == b.ino && a.kind() == b.kind() }

// Called only after native acquisition proved every edge and qualified the
// SAME captured volume device. Serial-number equality alone is not that proof.
func winDisjointChains(a, b []stamp) (int, error) {
	if len(a) == 0 || len(b) == 0 || len(a) > 129 || len(b) > 129 || !winSame(a[0], b[0]) {
		return 0, ErrUnavailable
	}
	for _, x := range a {
		if winSame(x, b[len(b)-1]) {
			return 0, ErrPath
		}
	}
	for _, x := range b {
		if winSame(x, a[len(a)-1]) {
			return 0, ErrPath
		}
	}
	common := 0
	for i := 1; i < len(a) && i < len(b); i++ {
		if !winSame(a[i], b[i]) {
			break
		}
		common = i
	}
	return common, nil
}

// REPARSE_DATA_BUFFER's symbolic-link arm (ntifs.h). Only genuinely relative
// Microsoft symlinks are eligible; junctions, cloud/unknown providers and all
// absolute substitute names are refused. Every byte offset is validated first.
func winReparseTarget(b []byte) (string, error) {
	if len(b) < 20 || binary.LittleEndian.Uint32(b) != 0xa000000c {
		return "", ErrPath
	}
	end := 8 + int(binary.LittleEndian.Uint16(b[4:]))
	if end < 20 || end > len(b) || end > 16384 || binary.LittleEndian.Uint32(b[16:]) != 1 {
		return "", ErrPath
	}
	area := b[20:end]
	for _, i := range []int{8, 12} {
		off, n := int(binary.LittleEndian.Uint16(b[i:])), int(binary.LittleEndian.Uint16(b[i+2:]))
		if off%2 != 0 || n%2 != 0 || off > len(area) || n > len(area)-off {
			return "", ErrPath
		}
	}
	off, n := int(binary.LittleEndian.Uint16(b[8:])), int(binary.LittleEndian.Uint16(b[10:]))
	if n == 0 || n > 8192 {
		return "", ErrPath
	}
	out := make([]byte, n/2)
	for i := range out {
		u := binary.LittleEndian.Uint16(area[off+2*i:])
		if u < 32 || u > 126 {
			return "", ErrPath
		}
		out[i] = byte(u)
	}
	s := strings.ReplaceAll(string(out), `\`, "/")
	// Check syntax without constraining '..' to this synthetic prefix. Actual
	// containment is checked with the captured link's real root-relative prefix.
	if strings.HasPrefix(s, "/") {
		return "", ErrPath
	}
	for _, p := range strings.Split(s, "/") {
		if p != "." && p != ".." && winComponent(p) != nil {
			return "", ErrPath
		}
	}
	return s, nil
}
