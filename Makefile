all: linux osx windows

docker: linux Dockerfile
	docker build -t yodawgproxy:$(shell cat VERSION) .

linux: build/linux-amd64/yodawgproxy

osx: build/osx-amd64/yodawgproxy

windows: build/win-amd64/yodawgproxy.exe

# Linux Build
build/linux-amd64/yodawgproxy: main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $@ github.com/exosite/yodawgproxy
# OS X Build
build/osx-amd64/yodawgproxy: main.go
	GOOS=darwin GOARCH=amd64 go build -o $@ github.com/exosite/yodawgproxy
# Windows Build
build/win-amd64/yodawgproxy.exe: main.go
	GOOS=windows GOARCH=amd64 go build -o $@ github.com/exosite/yodawgproxy

clean:
	rm -f build/linux-amd64/yodawgproxy
	rm -f build/osx-amd64/yodawgproxy
	rm -f build/win-amd64/yodawgproxy.exe
	rm -f *~

.PHONY: all clean linux osx windows docker
