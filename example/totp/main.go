package main

import (
	"fmt"
	"github.com/richardjennings/totp/pkg/totp"
)

func main() {
	opts := totp.Opts{
		Timestep:        30,
		Secret:          []byte("12345678901234567890"),
		Digits:          8,
		Algorithm:       totp.SHA1,
		CurrentUnixTime: 59,
	}
	fmt.Println(totp.GenerateTOTP(opts)) // 94287082
}
