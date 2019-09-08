# TOTP 

## About
Implementation of the TOTP Time-Based One-Time Password Algorithm [RFC](https://tools.ietf.org/html/rfc6238) which is an extension of HOTP [RFC](https://tools.ietf.org/html/rfc4226#section-5.4)

## Example

```go
    package main
    
    import (
    	"github.com/richardjennings/totp"
    	"fmt"
    )
    func main() {
    	opts := totp.Opts{
    		Timestep:           30,
    		InitialCounterTime: 0,
    		Secret:             []byte("12345678901234567890"),
    		Digits:             8,
    		Algorithm:          totp.SHA1,
    		CurrentUnixTime:    59,
    	}
    	fmt.Println(totp.GenerateTOTP(opts))
    }
```
```
$ go run main.go
94287082
```	
	