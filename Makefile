sgx.pb.go: sgx.proto
	protoc --go_out=plugins=grpc:. sgx.proto

install: sgx.pb.go
	go install ./...

all: sgx.pb.go
