package cmd

import (
	"fmt"
	"github.com/richardjennings/totp/pkg/otpauth"
	"github.com/spf13/cobra"
	"log"
	"net/url"
)

var migrateUri []string
var generateTotp bool

func init() {
	otpMigrate.Flags().StringSliceVarP(&migrateUri, "link", "l", []string{}, "Specify Migration Link")
	otpMigrate.Flags().BoolVar(&generateTotp, "totp", false, "generate totp codes")
	rootCmd.AddCommand(otpMigrate)
}

var otpMigrate = &cobra.Command{
	Use:   "otpmigrate <otpauth-migration://string>",
	Short: "generate otpauth URIs from an optauth-migration URI",
	Run: func(cmd *cobra.Command, args []string) {

		for _, v := range migrateUri {
			m, err := url.Parse(v)
			if err != nil {
				log.Fatal(err)
			}
			mUri, err := otpauth.MigrationURIDecode(m)
			if err != nil {
				log.Fatal(err)
			}
			if generateTotp {
				for _, v := range mUri {
					c, err := otpauth.GenerateTOTPFromAuthURI(v, "")
					if err != nil {
						log.Fatal(err)
					}
					fmt.Printf("%s - %s (%s) \n", c, v.Issuer, v.Label)
				}
			} else {
				fmt.Println(mUri)
			}
		}
	},
}
