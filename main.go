package main

import (
	"github.com/cameronaaron/snapchat-bridge/bridge"
	"github.com/cameronaaron/snapchat-bridge/pkg/connector"
)

var (
	Tag       = "v1.0.0"
	Commit    = "commit_hash"
	BuildTime = "2024-07-31T00:00:00Z"
)

func main() {
	m := bridge.BridgeMain{
		Name:        "snapchat-bridge",
		Description: "A Matrix-Snapchat bridge",
		URL:         "https://github.com/cameronaaron/snapchat-bridge",
		Version:     "1.0.0",
		Connector:   &connector.SnapchatConnector{},
	}
	m.InitVersion(Tag, Commit, BuildTime)
	m.Run()
}
