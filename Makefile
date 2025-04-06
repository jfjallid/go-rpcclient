all:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o go-rpcclient
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o go-rpcclient.exe

clean:
	rm -f go-rpcclient
	rm -f go-rpcclient.exe
