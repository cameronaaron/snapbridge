
#!/bin/sh
GO_LDFLAGS="-s -w -X main.Tag=$(git describe --tags) -X main.Commit=$(git rev-parse HEAD) -X 'main.BuildTime=$(date -Iseconds)'"
go build -ldflags="$GO_LDFLAGS" ./cmd/snapchat-bridge
