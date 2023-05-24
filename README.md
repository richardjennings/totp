# TOTP 

## Install
```go install github.com/richardjennings/totp```

## About
Implementation of the TOTP Time-Based One-Time Password Algorithm [RFC 6238](https://tools.ietf.org/html/rfc6238) 
which is an extension of HOTP [RFC 4226](https://tools.ietf.org/html/rfc4226) with support for
[Google Authenticator Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) and 
`otpauth-migration` links.

## Features

- [x] Generate TOTP codes and export as `otpauth` QR Code PNG images.
- [x] Generate TOTP codes from Google Authenticator `otpauth-migration` export links.
- [x] Convert Google Authenticator `otpauth-migration` export links into `otpauth` links.
- [x] Generate TOTP codes from `otpauth` links.
- [x] Generate TOTP codes from base32 encoded secrets, e.g. as provided by GitHub
- [ ] Create `otpauth-migration` links from `otpauth` links.
- [ ] Import `otpauth` links into Keychain.
- [ ] Generate TOTP codes from Keychain.

## Usage Examples

Create a TOTP code, `otpauth` link and QR Code PNG image:
```bash
$ totp gen --timestamp 10000 --digits=6 --issuer=myorg --label=totp@myorg --secret=somesecret --qr-png qr.png       
otpauth://totp/totp@myorg?algorithm=SHA1&digits=6&issuer=myorg&period=30&secret=ONXW2ZLTMVRXEZLU
473009
```
![qr.png](qr.png)

Import otpauth links from `otpauth-migration` Google Authenticator backup:
```bash
$ totp otpmigrate --link "otpauth-migration://offline?data=CiUKCnNvbWVzZWNyZXQSCnRvdHBAbXlvcmcaBW15b3JnIAEoATACEAEYASAA"
otpauth://totp/totp@myorg?algorithm=SHA1&digits=6&issuer=myorg&period=30&secret=J5HFQVZSLJGFITKWKJMEKWSMKU
```

Generate a code from an `otpauth` URI:

```bash
$ totp otpauth --timestamp 10000  "otpauth://totp/totp@myorg?algorithm=SHA1&digits=6&issuer=myorg&period=30&secret=ONXW2ZLTMVRXEZLU" 
totp@myorg 473009
```

Generate a code from a GitHub TOTP base32 encoded shared secret
```bash
$ totp gen --secret "thesharedsecret"
otpauth://totp?algorithm=SHA1&digits=6&period=30&secret=thesharedsecret
123456
```

Create a TOTP code programmatically:
```go
    package main
    
    import (
    	"github.com/richardjennings/totp/pkg/totp"
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
    	fmt.Println(totp.GenerateTOTP(opts)) // 94287082
    }
```
