package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/igorlabworks/terraform-provider-scp/internal/provider"
)

var (
	// version will be set by goreleaser at build time.
	version string = "dev"
)

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/igorlabworks/scp",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
