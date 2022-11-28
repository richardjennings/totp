package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "totp",
	Short: "Totp is a CLI tool for generating TOTP codes",
	Run: func(cmd *cobra.Command, args []string) {
		cobra.CheckErr(cmd.Help())
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
