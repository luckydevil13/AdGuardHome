Auth disabled
ngtables ipset


go clean -r
go mod tidy
set GO_ENABLED=0
set GOOS=linux
set GOARCH=arm64
go build -ldflags "-s -w"

// GO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w"
//make build-release