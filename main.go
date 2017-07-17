package main

import (
	"os"

	"github.com/TrilliumIT/docker-saltCert/saltCert"
	"github.com/docker/go-plugins-helpers/volume"
	"github.com/urfave/cli"
)

const (
	version = "0.0.1"
)

func main() {

	app := cli.NewApp()
	app.Name = "docker-saltCert"
	app.Usage = "Docker SaltCert Plugin"
	app.Version = version
	app.Action = Run
	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}

// Run runs the driver
func Run(ctx *cli.Context) error {
	d, err := saltCert.NewDriver()
	if err != nil {
		return err
	}
	h := volume.NewHandler(d)
	h.ServeUnix("saltCert", 0)

	return nil
}
