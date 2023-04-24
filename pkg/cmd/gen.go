package cmd

import (
	"encoding/base32"
	"fmt"
	"github.com/richardjennings/totp/pkg/otpauth"
	"github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
	"log"
	"os"
)

var issuer string
var label string
var secret string
var encodedSecret string
var algo string
var digits int
var period int

var pngQr string

func init() {
	genCmd.Flags().StringVarP(&timestamp, "timestamp", "t", "", "Specify a Unix timestamp")
	genCmd.Flags().StringVar(&issuer, "issuer", "", "Issuer")
	genCmd.Flags().StringVar(&label, "label", "", "Label")
	genCmd.Flags().StringVar(&secret, "secret", "", "Secret")
	genCmd.Flags().StringVar(&encodedSecret, "encoded-secret", "", "--encoded-secret=")
	genCmd.Flags().StringVar(&algo, "algorithm", "SHA1", "Algorithm")
	genCmd.Flags().IntVar(&digits, "digits", 6, "Number of digits")
	genCmd.Flags().IntVar(&period, "period", 30, "Period")

	genCmd.Flags().StringVar(&pngQr, "qr-png", "", "qr-png <file>")
	rootCmd.AddCommand(genCmd)
}

var genCmd = &cobra.Command{
	Use: "gen",
	Run: func(cmd *cobra.Command, args []string) {
		var uri otpauth.AuthURI
		var err error
		if encodedSecret == "" {
			encodedSecret = base32.StdEncoding.EncodeToString([]byte(secret))
		}
		uri, err = otpauth.NewAuthURI(label, algo, digits, issuer, encodedSecret, period)
		if err != nil {
			log.Fatalln(err)
		}
		link := uri.URL().String()
		code, err := otpauth.GenerateTOTPFromAuthURI(uri, timestamp)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(link)
		fmt.Println(code)
		if pngQr != "" {
			png, err := qrcode.Encode(link, qrcode.Medium, 256)
			if err != nil {
				log.Fatalln(err)
			}
			if err := os.WriteFile(pngQr, png, 0777); err != nil {
				log.Fatalln(err)
			}
		}

	},
}
