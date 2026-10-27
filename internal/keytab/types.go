// Package keytab inspects bounded native Kerberos keytab files without exposing
// key material or contacting a KDC, Vault, or an external executable.
package keytab

import (
	"errors"
	"time"
)

const APIVersion = "secretwright/keytab/v1"
const MaxInputBytes = 1 << 20
const MaxRecords = 4096
const MaxComponents = 32
const MaxStringBytes = 1024
const MaxPrincipalBytes = 4096

var ErrInvalidInput = errors.New("invalid or oversized keytab input")
var ErrInvalidPolicy = errors.New("invalid or oversized keytab policy")
var ErrValidation = errors.New("keytab policy validation failed")

type PrincipalSpec struct {
	Realm      string   `json:"realm"`
	Components []string `json:"components"`
}

type EntryReport struct {
	Principal   string    `json:"principal"`
	Realm       string    `json:"realm"`
	Components  []string  `json:"components"`
	NameType    uint32    `json:"name_type"`
	Timestamp   time.Time `json:"timestamp"`
	KVNO        uint32    `json:"kvno"`
	Enctype     uint16    `json:"enctype"`
	EnctypeName string    `json:"enctype_name"`
	Strength    string    `json:"strength"`
	KeyLength   int       `json:"key_length"`
}

type Report struct {
	Version               int           `json:"version"`
	Entries               []EntryReport `json:"entries"`
	Holes                 int           `json:"holes"`
	AuthenticationChecked bool          `json:"authentication_checked"`
}

type Policy struct {
	APIVersion           string        `json:"api_version"`
	Name                 string        `json:"name"`
	Principal            PrincipalSpec `json:"principal"`
	MinimumKVNO          uint32        `json:"minimum_kvno"`
	AllowedEnctypes      []uint16      `json:"allowed_enctypes"`
	RequiredEnctypes     []uint16      `json:"required_enctypes"`
	AllowOtherPrincipals bool          `json:"allow_other_principals"`
}

type ValidationReport struct {
	Valid                 bool   `json:"valid"`
	Reason                string `json:"reason,omitempty"`
	PolicyChecked         bool   `json:"policy_checked"`
	AuthenticationChecked bool   `json:"authentication_checked"`
	Principal             string `json:"principal,omitempty"`
	EntryCount            int    `json:"entry_count"`
	HighestKVNO           uint32 `json:"highest_kvno"`
}
