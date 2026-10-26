package keytab_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ml0renz0/secretwright/internal/keytab"
)

var ktPrivateKeyMarker = []byte("private-keytab-key-material-1234")

type ktRecord struct {
	realm      string
	components []string
	nameType   uint32
	timestamp  uint32
	kvno8      uint8
	enctype    uint16
	key        []byte
	kvno32     *uint32
	padding    []byte
}

func ktNumber(value uint32) *uint32 {
	return &value
}

func ktFixtureRecord() ktRecord {
	return ktRecord{
		realm:      "EXAMPLE.TEST",
		components: []string{"HTTP", "app.example.test"},
		nameType:   2,
		timestamp:  0x90000000,
		kvno8:      3,
		enctype:    18,
		key:        append([]byte(nil), ktPrivateKeyMarker...),
	}
}

func ktCounted(output *bytes.Buffer, value string) {
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(value)))
	output.Write(size[:])
	output.WriteString(value)
}

func ktEntry(record ktRecord) []byte {
	var output bytes.Buffer
	var small [2]byte
	var large [4]byte
	binary.BigEndian.PutUint16(small[:], uint16(len(record.components)))
	output.Write(small[:])
	ktCounted(&output, record.realm)
	for _, component := range record.components {
		ktCounted(&output, component)
	}
	binary.BigEndian.PutUint32(large[:], record.nameType)
	output.Write(large[:])
	binary.BigEndian.PutUint32(large[:], record.timestamp)
	output.Write(large[:])
	output.WriteByte(record.kvno8)
	binary.BigEndian.PutUint16(small[:], record.enctype)
	output.Write(small[:])
	binary.BigEndian.PutUint16(small[:], uint16(len(record.key)))
	output.Write(small[:])
	output.Write(record.key)
	if record.kvno32 != nil {
		binary.BigEndian.PutUint32(large[:], *record.kvno32)
		output.Write(large[:])
	}
	output.Write(record.padding)
	return output.Bytes()
}

func ktFrame(body []byte) []byte {
	result := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(result, uint32(len(body)))
	return append(result, body...)
}

func ktFile(records ...ktRecord) []byte {
	result := []byte{5, 2}
	for _, record := range records {
		result = append(result, ktFrame(ktEntry(record))...)
	}
	return result
}

func ktPolicy() keytab.Policy {
	return keytab.Policy{
		APIVersion:       "secretwright/keytab/v1",
		Name:             "web",
		Principal:        keytab.PrincipalSpec{Realm: "EXAMPLE.TEST", Components: []string{"HTTP", "app.example.test"}},
		MinimumKVNO:      3,
		AllowedEnctypes:  []uint16{17, 18, 19, 20},
		RequiredEnctypes: []uint16{18},
	}
}

func ktRequireError(t *testing.T, err error, expected error) {
	t.Helper()
	if err != expected {
		t.Fatal("keytab operation did not return its fixed approved error")
	}
}
