package intelstore

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"sort"
)

// archive/zip checks payload CRC/EOF but deliberately skips local-header names.
// This bounded preflight rejects contradictory local/central entry identities,
// multi-disk/SFX/trailing records and overlapping payloads without extracting.
func validateZIPStructure(input io.ReaderAt, size int64, files []*zip.File) error {
	read := func(offset int64, n int) ([]byte, error) {
		if offset < 0 || n < 0 || offset > size || int64(n) > size-offset {
			return nil, ErrCorrupt
		}
		b := make([]byte, n)
		if _, e := input.ReadAt(b, offset); e != nil {
			return nil, ErrCorrupt
		}
		return b, nil
	}
	tailSize := size
	if tailSize > 65557 {
		tailSize = 65557
	}
	tail, e := read(size-tailSize, int(tailSize))
	if e != nil {
		return e
	}
	end := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == 0x06054b50 && i+22+int(binary.LittleEndian.Uint16(tail[i+20:])) == len(tail) {
			end = i
			break
		}
	}
	if end < 0 {
		return ErrCorrupt
	}
	footer := tail[end:]
	endOffset := size - tailSize + int64(end)
	u16 := binary.LittleEndian.Uint16
	u32 := binary.LittleEndian.Uint32
	u64 := binary.LittleEndian.Uint64
	if u16(footer[4:]) != 0 || u16(footer[6:]) != 0 || u16(footer[8:]) != u16(footer[10:]) {
		return ErrCorrupt
	}
	count, centralBytes, centralOffset := uint64(u16(footer[10:])), uint64(u32(footer[12:])), uint64(u32(footer[16:]))
	if count == 0xffff || centralBytes == 0xffffffff || centralOffset == 0xffffffff {
		locator, e := read(endOffset-20, 20)
		if e != nil || u32(locator) != 0x07064b50 || u32(locator[4:]) != 0 || u32(locator[16:]) != 1 {
			return ErrCorrupt
		}
		offset := u64(locator[8:])
		if offset > uint64(size) {
			return ErrCorrupt
		}
		record, e := read(int64(offset), 56)
		if e != nil || u32(record) != 0x06064b50 || u64(record[4:]) != 44 || u32(record[16:]) != 0 || u32(record[20:]) != 0 || u64(record[24:]) != u64(record[32:]) {
			return ErrCorrupt
		}
		count, centralBytes, centralOffset = u64(record[32:]), u64(record[40:]), u64(record[48:])
		endOffset = int64(offset)
	}
	if count != uint64(len(files)) || centralOffset > uint64(endOffset) || centralBytes != uint64(endOffset)-centralOffset {
		return ErrCorrupt
	}
	type region struct{ start, end uint64 }
	regions := make([]region, 0, len(files))
	position := centralOffset
	for _, file := range files {
		c, e := read(int64(position), 46)
		if e != nil || u32(c) != 0x02014b50 || u16(c[34:]) != 0 {
			return ErrCorrupt
		}
		nameLen, extraLen, commentLen := int(u16(c[28:])), int(u16(c[30:])), int(u16(c[32:]))
		if nameLen > 255 {
			return ErrCorrupt
		}
		variable, e := read(int64(position)+46, nameLen+extraLen+commentLen)
		if e != nil || string(variable[:nameLen]) != file.Name {
			return ErrCorrupt
		}
		localOffset := uint64(u32(c[42:]))
		if localOffset == 0xffffffff {
			extra := variable[nameLen : nameLen+extraLen]
			found := false
			for len(extra) >= 4 {
				tag, n := u16(extra), int(u16(extra[2:]))
				extra = extra[4:]
				if n > len(extra) {
					return ErrCorrupt
				}
				data := extra[:n]
				extra = extra[n:]
				if tag != 1 {
					continue
				}
				at := 0
				if u32(c[24:]) == 0xffffffff {
					at += 8
				}
				if u32(c[20:]) == 0xffffffff {
					at += 8
				}
				if len(data) < at+8 {
					return ErrCorrupt
				}
				localOffset = u64(data[at:])
				found = true
				break
			}
			if !found {
				return ErrCorrupt
			}
		}
		if localOffset >= centralOffset {
			return ErrCorrupt
		}
		local, e := read(int64(localOffset), 30)
		if e != nil || u32(local) != 0x04034b50 || u16(local[6:]) != file.Flags || u16(local[8:]) != file.Method || int(u16(local[26:])) != len(file.Name) {
			return ErrCorrupt
		}
		name, e := read(int64(localOffset)+30, len(file.Name))
		if e != nil || !bytes.Equal(name, []byte(file.Name)) {
			return ErrCorrupt
		}
		dataOffset := localOffset + 30 + uint64(u16(local[26:])) + uint64(u16(local[28:]))
		offset, e := file.DataOffset()
		if e != nil || uint64(offset) != dataOffset || dataOffset > centralOffset || file.CompressedSize64 > centralOffset-dataOffset {
			return ErrCorrupt
		}
		if file.Flags&8 == 0 && (u32(local[14:]) != file.CRC32 || u32(local[18:]) != 0xffffffff && uint64(u32(local[18:])) != file.CompressedSize64 || u32(local[22:]) != 0xffffffff && uint64(u32(local[22:])) != file.UncompressedSize64) {
			return ErrCorrupt
		}
		entryEnd := dataOffset + file.CompressedSize64
		if file.Flags&8 != 0 {
			length := 16
			wide := u32(local[18:]) == 0xffffffff || u32(local[22:]) == 0xffffffff
			if wide {
				length = 24
			}
			if uint64(length) > centralOffset-entryEnd {
				return ErrCorrupt
			}
			descriptor, err := read(int64(entryEnd), length)
			if err != nil || u32(descriptor) != 0x08074b50 || u32(descriptor[4:]) != file.CRC32 {
				return ErrCorrupt
			}
			if wide {
				if u64(descriptor[8:]) != file.CompressedSize64 || u64(descriptor[16:]) != file.UncompressedSize64 {
					return ErrCorrupt
				}
			} else if uint64(u32(descriptor[8:])) != file.CompressedSize64 || uint64(u32(descriptor[12:])) != file.UncompressedSize64 {
				return ErrCorrupt
			}
			entryEnd += uint64(length)
		}
		regions = append(regions, region{localOffset, entryEnd})
		position += uint64(46 + len(variable))
	}
	if position != centralOffset+centralBytes {
		return ErrCorrupt
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].start < regions[j].start })
	if len(regions) > 0 && regions[0].start != 0 {
		return ErrCorrupt
	}
	for i := 1; i < len(regions); i++ {
		if regions[i].start != regions[i-1].end {
			return ErrCorrupt
		}
	}
	if len(regions) != 0 && regions[len(regions)-1].end != centralOffset {
		return ErrCorrupt
	}
	return nil
}
