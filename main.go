package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const version = "v0.1.0"

func NewApp() *cobra.Command {
	defaultOpts := DefaultOptions()
	var opt Options
	var list bool

	app := &cobra.Command{
		Use:     "dnstrack",
		Short:   "# A dns-query tracking tool written in go",
		Version: version,
		Run: func(cmd *cobra.Command, args []string) {
			if list {
				devices, err := ListAllDevices()
				if err != nil {
					exit(err)
				}
				for _, device := range devices {
					fmt.Println(device.Name)
				}
				return
			}

			dq, err := NewDnsTrack(opt)
			if err != nil {
				exit(err)
			}
			defer dq.Close()
			dq.Start()
		},
		Example: `  # list all the net-devices
  $ dnstrack -l

  # filters google dns server packet attached in lo0 dev and output with json format
  $ dnstrack -s 8.8.8.8 -o j -d '^lo0$'`,
	}

	app.Flags().BoolVarP(&list, "list", "l", false, "list all devices name")
	app.Flags().StringVarP(&opt.Devices, "devices", "d", defaultOpts.Devices, "devices regex pattern filter")
	app.Flags().BoolVarP(&opt.AllDevices, "all-devices", "a", defaultOpts.AllDevices, "listen all devices if present")
	app.Flags().StringVarP(&opt.Server, "server", "s", defaultOpts.Server, "dns server filter")
	app.Flags().StringVarP(&opt.Type, "type", "t", defaultOpts.Type, "dns query type filter [A/AAAA/CNAME/...]")
	app.Flags().StringVarP(&opt.Format, "output-format", "o", defaultOpts.Format, "output format [json(j)|yaml(y)|question(q)|verbose(v)]")

	app.Flags().PrintDefaults()
	return app
}

func exit(err error) {
	fmt.Fprintln(os.Stderr, "Start dnstrack failed:", err.Error())
	os.Exit(1)
}

func main() {
	app := NewApp()
	if err := app.Execute(); err != nil {
		exit(err)
	}
}
