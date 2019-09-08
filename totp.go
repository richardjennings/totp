package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math"
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
	// The initial time
	InitialCounterTime uint
	// The shared secret
	Secret []byte
	// Number of Digits required
	Digits uint
	// the algorithm to use
	Algorithm Algo
	// specify the number of timestep increments that are allowed to result in a successful validation.
	DriftBackward uint
	DriftForward  uint
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
		panic("invalid algorithm")
	}
}

// Generate a TOTP
func GenerateTOTP(opts Opts) (code string) {
	t := opts.CurrentUnixTime
	if t == 0 {
		t = uint64(time.Now().Unix())
	}
	// calculate number of timesteps
	steps := uint64(math.Floor(float64(t) / float64(opts.Timestep)))

	return generateHOTP(opts.Algo(), opts.Secret, steps, opts.Digits)
}

func Validate(code string, opts Opts) (valid bool, driftBackwards uint, driftForwards uint) {
	return
}
