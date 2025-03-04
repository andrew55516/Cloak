//go:build go1.11
// +build go1.11

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/cbeuw/Cloak/internal/client"
	log "github.com/sirupsen/logrus"
)

var version string

func main() {
	// Should be 127.0.0.1 to listen to a proxy client on this machine
	var localHost string
	// port used by proxy clients to communicate with cloak client
	var localPort string
	// The ip of the proxy server
	var remoteHost string
	// The proxy port,should be 443
	var remotePort string
	var proxyMethod string
	var udp bool
	var config string
	var b64AdminUID string
	var vpnMode bool
	var tcpFastOpen bool

	log_init()

	ssPluginMode := os.Getenv("SS_LOCAL_HOST") != ""

	verbosity := flag.String("verbosity", "info", "verbosity level")
	if ssPluginMode {
		config = os.Getenv("SS_PLUGIN_OPTIONS")
		flag.BoolVar(&vpnMode, "V", false, "ignored.")
		flag.BoolVar(&tcpFastOpen, "fast-open", false, "ignored.")
		flag.Parse() // for verbosity only
	} else {
		flag.StringVar(&localHost, "i", "127.0.0.1", "localHost: Cloak listens to proxy clients on this ip")
		flag.StringVar(&localPort, "l", "1984", "localPort: Cloak listens to proxy clients on this port")
		flag.StringVar(&remoteHost, "s", "", "remoteHost: IP of your proxy server")
		flag.StringVar(&remotePort, "p", "443", "remotePort: proxy port, should be 443")
		flag.BoolVar(&udp, "u", false, "udp: set this flag if the underlying proxy is using UDP protocol")
		flag.StringVar(&config, "c", "ckclient.json", "config: path to the configuration file or options separated with semicolons")
		flag.StringVar(&proxyMethod, "proxy", "", "proxy: the proxy method's name. It must match exactly with the corresponding entry in server's ProxyBook")
		flag.StringVar(&b64AdminUID, "a", "", "adminUID: enter the adminUID to serve the admin api")
		askVersion := flag.Bool("v", false, "Print the version number")
		printUsage := flag.Bool("h", false, "Print this message")

		// commandline arguments overrides json

		flag.Parse()

		if *askVersion {
			fmt.Printf("ck-client %s", version)
			return
		}

		if *printUsage {
			flag.Usage()
			return
		}

		log.Info("Starting standalone mode")
	}

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	lvl, err := log.ParseLevel(*verbosity)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(lvl)

	rawConfig, err := client.ParseConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	if ssPluginMode {
		if rawConfig.ProxyMethod == "" {
			rawConfig.ProxyMethod = "shadowsocks"
		}
		// json takes precedence over environment variables
		// i.e. if json field isn't empty, use that
		if rawConfig.RemoteHost == "" {
			rawConfig.RemoteHost = os.Getenv("SS_REMOTE_HOST")
		}
		if rawConfig.RemotePort == "" {
			rawConfig.RemotePort = os.Getenv("SS_REMOTE_PORT")
		}
		if rawConfig.LocalHost == "" {
			rawConfig.LocalHost = os.Getenv("SS_LOCAL_HOST")
		}
		if rawConfig.LocalPort == "" {
			rawConfig.LocalPort = os.Getenv("SS_LOCAL_PORT")
		}
	} else {
		// commandline argument takes precedence over json
		// if commandline argument is set, use commandline
		flag.Visit(func(f *flag.Flag) {
			// manually set ones
			switch f.Name {
			case "i":
				rawConfig.LocalHost = localHost
			case "l":
				rawConfig.LocalPort = localPort
			case "s":
				rawConfig.RemoteHost = remoteHost
			case "p":
				rawConfig.RemotePort = remotePort
			case "u":
				rawConfig.UDP = udp
			case "proxy":
				rawConfig.ProxyMethod = proxyMethod
			}
		})
		// ones with default values
		if rawConfig.LocalHost == "" {
			rawConfig.LocalHost = localHost
		}
		if rawConfig.LocalPort == "" {
			rawConfig.LocalPort = localPort
		}
		if rawConfig.RemotePort == "" {
			rawConfig.RemotePort = remotePort
		}
	}

	if b64AdminUID != "" {
		adminUID, err := base64.StdEncoding.DecodeString(b64AdminUID)
		if err != nil {
			log.Fatal(err)
		}
		rawConfig.UID = adminUID
	}

	cl := NewCkClient(rawConfig)
	cl.Connect()
}
