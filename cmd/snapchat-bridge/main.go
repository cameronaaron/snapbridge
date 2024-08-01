package main

import (
	"maunium.net/go/mautrix/bridgev2/matrix/mxmain"

	"https://github.com/cameronaaron/snapchat-bridge/pkg/connector"
)

// Information to find out exactly which commit the bridge was built from.
// These are filled at build time with the -X linker flag.
var (
	Tag       = "unknown"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	m := bridgev2.BridgeMain{
		Name:        "snapchat-bridge",
		Description: "A Matrix-Snapchat bridge",
		URL:         "https://github.com/cameronaaron/snapchat-bridge",
		Version:     "1.0.0",
		Connector:   &SnapchatConnector{},
	}
	m.InitVersion(Tag, Commit, BuildTime)
	m.Run()
}
