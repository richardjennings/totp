package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"github.com/richardjennings/totp/pkg/hotp"
	"hash"
	"net/url"
	"strconv"
	"time"
)

type Algo int

const (
	Invalid Algo = iota
	SHA1
	SHA256
	SHA512
)

type Opts struct {
	// the number of seconds between generating TOTPs. A default timestep of 30 seconds is recommended
	Timestep uint
	// The shared secret
	Secret []byte
	// Number of Digits required
	Digits uint
	// the algorithm to use
	Algorithm Algo
	// For testing purposes, the current Unix time
	CurrentUnixTime uint64
}

func (o Opts) Algo() func() hash.Hash {
	switch o.Algorithm {
	case SHA1:
		return func() hash.Hash { return sha1.New() }
	case SHA256:
		return func() hash.Hash { return sha256.New() }
	case SHA512:
		return func() hash.Hash { return sha512.New() }
	default:
		return nil
	}
}

// Generate a TOTP
func GenerateTOTP(opts Opts) (code string) {
	t := opts.CurrentUnixTime
	if t == 0 {
		t = uint64(time.Now().Unix())
	}
	// calculate number of timesteps
	steps := t / uint64(opts.Timestep)

	return hotp.GenerateHOTP(opts.Algo(), opts.Secret, steps, opts.Digits)
}

func GenerateTOTPFromOTPAuth(otpAuth string, timestamp string) (label string, code string, err error) {
	var u *url.URL
	var digits int
	var period int
	var secret []byte
	var algorithm Algo
	var t int

	u, err = url.Parse(otpAuth)
	if err != nil {
		return
	}

	c := u.Query()

	d := c.Get("digits")
	if d == "" {
		digits = 6
	} else {
		digits, err = strconv.Atoi(d)
		if err != nil {
			return
		}
	}

	p := c.Get("period")
	if p == "" {
		period = 30
	} else {
		period, err = strconv.Atoi(p)
		if err != nil {
			return
		}
	}

	secret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(c.Get("secret"))
	if err != nil {
		return
	}

	a := c.Get("algorithm")
	if a == "" {
		algorithm = SHA1
	} else {
		switch a {
		case "SHA1":
			algorithm = SHA1
		case "SHA256":
			algorithm = SHA256
		case "SHA512":
			algorithm = SHA512
		default:
			err = fmt.Errorf("invalid algo %s", a)
			return
		}
	}

	opts := Opts{
		Timestep:  uint(period),
		Secret:    secret,
		Digits:    uint(digits),
		Algorithm: algorithm,
	}

	if timestamp != "" {
		t, err = strconv.Atoi(timestamp)
		if err != nil {
			return
		}
		opts.CurrentUnixTime = uint64(t)
	}

	code = GenerateTOTP(opts)

	label = u.Path[1:]

	return
}
