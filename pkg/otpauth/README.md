# About

This package leverages the explanation of the `otpauth-migration` Authenticator format discussed in
https://github.com/google/google-authenticator-android/issues/118 and via blog post
https://alexbakker.me/post/parsing-google-auth-export-qr-code.html

migration.pb.go is generated via 
```
protoc --go_out=paths=source_relative:. pkg/otpauth/migration.proto
```
`option go_package = "github.com/richardjennings/totp/pkg/otpauth";` is added to the original proto spec as per the best 
practice [documented](https://developers.google.com/protocol-buffers/docs/reference/go-generated#package).

