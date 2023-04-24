package otpauth

import (
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/richardjennings/totp/pkg/totp"
	"net/url"
	"strconv"

	"google.golang.org/protobuf/proto"
)

type (
	// AuthURI represents an otpauth AuthURI which has the format: otpauth://TYPE/LABEL?PARAMETERS

	AuthURI struct {

		// should be otpauth://
		Scheme string

		// Valid types are hotp and totp, to distinguish whether the key will be used for counter-based HOTP or for TOTP.
		Type string

		// label = accountname / issuer (“:” / “%3A”) *”%20” accountname
		Label string

		// REQUIRED: The secret parameter is an arbitrary key value encoded in Base32 according to RFC 3548.
		// The padding specified in RFC 3548 section 2.2 is not required and should be omitted.
		Secret string

		// STRONGLY RECOMMENDED: The issuer parameter is a string value indicating the provider or service this account is
		// associated with, URL-encoded according to RFC 3986.
		// If the issuer parameter is absent, issuer information may be taken from the issuer prefix of the label.
		// If both issuer parameter and issuer label prefix are present, they should be equal.
		Issuer string

		// The algorithm may have the values: SHA1, SHA256, SHA512
		Algorithm totp.Algo

		// The digits parameter may have the values 6 or 8, and determines how long of a one-time passcode to display to
		// the user. The default is 6.
		Digits int

		// The counter parameter is required when provisioning a key for use with HOTP. It will set the initial counter
		// value.
		Counter int

		// The period parameter defines a period that a TOTP code will be valid for, in seconds. The default value is 30.
		Period int
	}

	MigrationURI []AuthURI
)

// AuthURIFromString parses an AuthURI from an otpauth:// string
func AuthURIFromString(otpAuth string) (uri AuthURI, err error) {
	var u *url.URL

	u, err = url.Parse(otpAuth)
	if err != nil {
		return
	}

	if u.Scheme != "otpauth" {
		return uri, fmt.Errorf("invalid scheme %s", u.Scheme)
	}
	uri.Scheme = u.Scheme

	if u.Host != "totp" {
		return uri, fmt.Errorf("invalid host %s", u.Host)
	}
	uri.Type = u.Host

	if len(u.Path) > 0 {
		uri.Label = u.Path[1:]
	}

	c := u.Query()

	d := c.Get("digits")
	if d == "" {
		uri.Digits = 6
	} else {
		uri.Digits, err = strconv.Atoi(d)
		if err != nil {
			return
		}
	}

	p := c.Get("period")
	if p == "" {
		uri.Period = 30
	} else {
		uri.Period, err = strconv.Atoi(p)
		if err != nil {
			return
		}
	}
	uri.Issuer = c.Get("issuer")

	uri.Secret = c.Get("secret")

	switch c.Get("algorithm") {
	case "SHA1":
		uri.Algorithm = totp.SHA1
	case "SHA256":
		uri.Algorithm = totp.SHA256
	case "SHA512":
		uri.Algorithm = totp.SHA512
	}

	return
}

// NewAuthURI creates an AuthURI.
func NewAuthURI(label string, algo string, digits int, issuer string, secret string, period int) (AuthURI, error) {
	a := AuthURI{
		Scheme:  "otpauth",
		Type:    "totp",
		Counter: 0,
	}

	switch algo {
	case "SHA1":
		a.Algorithm = totp.SHA1
	case "SHA256":
		a.Algorithm = totp.SHA256
	case "SHA512":
		a.Algorithm = totp.SHA512
	default:
		return a, fmt.Errorf("invalid algorithm %s", algo)
	}
	if len(secret) == 0 {
		return a, errors.New("secret required")
	}
	a.Secret = secret
	if digits != 8 && digits != 6 {
		return a, errors.New("digits must be 6 or 8")
	}
	a.Digits = digits
	a.Period = period
	a.Label = label
	a.Issuer = issuer

	return a, nil
}

// URL returns a url.URL representation of an AuthURI
func (a AuthURI) URL() *url.URL {
	u := &url.URL{
		Scheme: a.Scheme,
		Host:   a.Type,
	}
	q := url.Values{}
	if len(a.Label) > 0 {
		u.Path = fmt.Sprintf("/%s", a.Label)
	}
	switch a.Algorithm {
	case totp.SHA1:
		q.Add("algorithm", "SHA1")
	case totp.SHA256:
		q.Add("algorithm", "SHA256")
	case totp.SHA512:
		q.Add("algorithm", "SHA512")
	}
	q.Add("digits", strconv.Itoa(a.Digits))
	q.Add("period", strconv.Itoa(a.Period))
	q.Add("secret", a.Secret)
	if len(a.Issuer) > 0 {
		q.Add("issuer", a.Issuer)
	}

	u.RawQuery = q.Encode()
	return u
}

// String returns a string representation of a MigrationURI
func (m MigrationURI) String() string {
	var o string
	for _, v := range m {
		o += v.URL().String() + "\n"
	}
	return o
}

// MigrationURIDecode transforms a otpauth-migration type url.URL into a MigrationURL
func MigrationURIDecode(u *url.URL) (m MigrationURI, err error) {
	if u.Scheme != "otpauth-migration" {
		return nil, fmt.Errorf("invalid scheme: Expected otpauth-migration got %s", u.Scheme)
	}
	if u.Host != "offline" {
		return nil, fmt.Errorf("invalid host: Expected offline got %s", u.Host)
	}
	if u.Query().Get("data") == "" {
		return nil, errors.New("data missing from otpauth-migration URI")
	}
	rs, err := base64.StdEncoding.DecodeString(u.Query().Get("data"))
	if err != nil {
		return nil, err
	}
	var mp MigrationPayload
	if err := proto.Unmarshal(rs, &mp); err != nil {
		return nil, err
	}
	for _, v := range mp.OtpParameters {
		var a string
		var d int
		switch v.Algorithm {
		case MigrationPayload_ALGORITHM_MD5:
			return nil, errors.New("unsupported algorithm md5")
		case MigrationPayload_ALGORITHM_SHA1:
			a = "SHA1"
		case MigrationPayload_ALGORITHM_SHA256:
			a = "SHA256"
		case MigrationPayload_ALGORITHM_SHA512:
			a = "SHA512"
		}
		switch v.Digits {
		case MigrationPayload_DIGIT_COUNT_UNSPECIFIED, MigrationPayload_DIGIT_COUNT_SIX:
			d = 6
		case MigrationPayload_DIGIT_COUNT_EIGHT:
			d = 8
		}
		secret := base32.StdEncoding.EncodeToString(v.Secret)
		uri, err := NewAuthURI(v.Name, a, d, v.Issuer, secret, 30)
		if err != nil {
			return m, err
		}
		m = append(m, uri)
	}

	return
}

// GenerateTOTPFromAuthURI generates a TOTP code from an AuthURI
func GenerateTOTPFromAuthURI(otpAuth AuthURI, timestamp string) (code string, err error) {
	var secret []byte
	var t int
	secret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(otpAuth.Secret)
	if err != nil {
		return
	}
	opts := totp.Opts{
		Timestep:  uint(otpAuth.Period),
		Secret:    secret,
		Digits:    uint(otpAuth.Digits),
		Algorithm: otpAuth.Algorithm,
	}

	if timestamp != "" {
		t, err = strconv.Atoi(timestamp)
		if err != nil {
			return
		}
		opts.CurrentUnixTime = uint64(t)
	}

	code = totp.GenerateTOTP(opts)
	return code, nil
}
