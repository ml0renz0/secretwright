package keytab

import (
	"encoding/binary"
	"io"
	"math"
	"time"
)

type enctypeInfo struct {
	name     string
	strength string
	length   int
}

func knownEnctype(value uint16) (enctypeInfo, bool) {
	switch value {
	case 1:
		return enctypeInfo{"des-cbc-crc", "legacy", 8}, true
	case 2:
		return enctypeInfo{"des-cbc-md4", "legacy", 8}, true
	case 3:
		return enctypeInfo{"des-cbc-md5", "legacy", 8}, true
	case 16:
		return enctypeInfo{"des3-cbc-sha1-kd", "legacy", 24}, true
	case 17:
		return enctypeInfo{"aes128-cts-hmac-sha1-96", "strong", 16}, true
	case 18:
		return enctypeInfo{"aes256-cts-hmac-sha1-96", "strong", 32}, true
	case 19:
		return enctypeInfo{"aes128-cts-hmac-sha256-128", "strong", 16}, true
	case 20:
		return enctypeInfo{"aes256-cts-hmac-sha384-192", "strong", 32}, true
	case 23:
		return enctypeInfo{"arcfour-hmac", "legacy", 16}, true
	case 24:
		return enctypeInfo{"arcfour-hmac-exp", "legacy", 16}, true
	case 25:
		return enctypeInfo{"camellia128-cts-cmac", "strong", 16}, true
	case 26:
		return enctypeInfo{"camellia256-cts-cmac", "strong", 32}, true
	default:
		return enctypeInfo{"unknown", "unknown", 0}, false
	}
}

type entryCursor struct {
	body   []byte
	offset int
}

func (cursor *entryCursor) take(size int) ([]byte, bool) {
	if size < 0 || size > len(cursor.body)-cursor.offset {
		return nil, false
	}
	result := cursor.body[cursor.offset : cursor.offset+size]
	cursor.offset += size
	return result, true
}

func (cursor *entryCursor) number16() (uint16, bool) {
	body, ok := cursor.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(body), true
}

func (cursor *entryCursor) number32() (uint32, bool) {
	body, ok := cursor.take(4)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint32(body), true
}

func (cursor *entryCursor) text() (string, bool) {
	size, ok := cursor.number16()
	if !ok || size == 0 || size > MaxStringBytes {
		return "", false
	}
	body, ok := cursor.take(int(size))
	if !ok {
		return "", false
	}
	text := string(body)
	if !validPrincipalString(text) {
		return "", false
	}
	return text, true
}

func inspectEntry(body []byte) (EntryReport, error) {
	cursor := entryCursor{body: body}
	count, ok := cursor.number16()
	if !ok || count == 0 || count > MaxComponents {
		return EntryReport{}, ErrInvalidInput
	}
	realm, ok := cursor.text()
	if !ok {
		return EntryReport{}, ErrInvalidInput
	}
	components := make([]string, int(count))
	for index := range components {
		components[index], ok = cursor.text()
		if !ok {
			return EntryReport{}, ErrInvalidInput
		}
	}
	principal, err := CanonicalPrincipal(realm, components)
	if err != nil {
		return EntryReport{}, ErrInvalidInput
	}
	nameType, nameOK := cursor.number32()
	timestamp, timeOK := cursor.number32()
	versionByte, versionOK := cursor.take(1)
	enctype, typeOK := cursor.number16()
	keyLength, keyOK := cursor.number16()
	if !nameOK || !timeOK || !versionOK || !typeOK || !keyOK || enctype == 0 || keyLength == 0 {
		return EntryReport{}, ErrInvalidInput
	}
	if _, ok := cursor.take(int(keyLength)); !ok {
		return EntryReport{}, ErrInvalidInput
	}
	info, known := knownEnctype(enctype)
	if known && int(keyLength) != info.length {
		return EntryReport{}, ErrInvalidInput
	}
	version := uint32(versionByte[0])
	if len(body)-cursor.offset >= 4 {
		extended, _ := cursor.number32()
		if extended != 0 {
			version = extended
		}
	}
	return EntryReport{
		Principal: principal, Realm: realm, Components: components,
		NameType: nameType, Timestamp: time.Unix(int64(timestamp), 0).UTC(),
		KVNO: version, Enctype: enctype, EnctypeName: info.name,
		Strength: info.strength, KeyLength: int(keyLength),
	}, nil
}

// Inspect follows the MIT v2 record layout. Deleted slots and record padding
// are opaque; neither they nor live key bytes enter the returned report.
func Inspect(input io.Reader) (Report, error) {
	if input == nil {
		return Report{}, ErrInvalidInput
	}
	body, err := io.ReadAll(io.LimitReader(input, MaxInputBytes+1))
	if err != nil || len(body) < 2 || len(body) > MaxInputBytes || body[0] != 5 || body[1] != 2 {
		return Report{}, ErrInvalidInput
	}
	result := Report{Version: 2, Entries: make([]EntryReport, 0)}
	records := 0
	for position := 2; position < len(body); {
		if len(body)-position < 4 {
			return Report{}, ErrInvalidInput
		}
		size := int32(binary.BigEndian.Uint32(body[position : position+4]))
		position += 4
		if size == 0 {
			for _, value := range body[position:] {
				if value != 0 {
					return Report{}, ErrInvalidInput
				}
			}
			break
		}
		records++
		if records > MaxRecords || size == math.MinInt32 {
			return Report{}, ErrInvalidInput
		}
		length := int64(size)
		if length < 0 {
			length = -length
		}
		if length > int64(len(body)-position) {
			return Report{}, ErrInvalidInput
		}
		end := position + int(length)
		if size < 0 {
			result.Holes++
		} else {
			entry, err := inspectEntry(body[position:end])
			if err != nil {
				return Report{}, ErrInvalidInput
			}
			result.Entries = append(result.Entries, entry)
		}
		position = end
	}
	return result, nil
}
