FLAG := -ldflags "-s -w"

$(shell rm ../goke.bin)

release: FLAG = -ldflags "-s -w"
release: all

debug: FLAG = 
debug: all

all: goke.bin

goke.bin:
	go build $(FLAG) -o goke.bin cmd/*.go

test:
	go test -v -coverprofile /tmp/cover.out objectmodel/*.go
	go test -v -coverprofile /tmp/cover.out ike/*.go
	go test -v -coverprofile /tmp/cover.out gcrypto/*.go

clean:
	rm -f goke.bin

