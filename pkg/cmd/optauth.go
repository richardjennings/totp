package cmd

import (
	"fmt"
	"github.com/richardjennings/totp/pkg/otpauth"
	"github.com/spf13/cobra"
	"log"
)

var timestamp string

func init() {
	otpAuth.Flags().StringVarP(&timestamp, "timestamp", "t", "", "Specify a Unix timestamp")
	rootCmd.AddCommand(otpAuth)
}

var otpAuth = &cobra.Command{
	Use:   "otpauth <otpauth://string>",
	Short: "generate a TOTP token from an otpauth:// URI",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		otpAuthUri, err := otpauth.AuthURIFromString(args[0])
		if err != nil {
			log.Fatal(err)
		}
		code, err := otpauth.GenerateTOTPFromAuthURI(otpAuthUri, timestamp)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s %s\n", otpAuthUri.Label, code)
	},
}
