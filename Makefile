all:
	CGO_ENABLED=1 go build -tags yara_static -trimpath -ldflags='-s -w -extldflags "-static"' -o uploadscan .
