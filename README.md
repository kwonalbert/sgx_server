# Go SGX Remote Attestation Server

## Introduction

SGX is a new hardware instruction set and features Intel introduced to
protect the code running in an untrusted environment (e.g., on cloud
infrastructure, like AWS or GCP). One of the fundamental operations of
SGX is "remote attestation" (RA). The goal of RA is to convince
someone that a piece of code that has been vetted before is running on
a device. The RA process is carried out between three parties in SGX:
the enclave, the server (service provider), and the Intel Attestation
Server (IAS). The enclave is the machine that is running the code that
is supposed to be verified, and the server is the machine that wants
to verify that the enclave is running the correct code. IAS helps the
server verify that the enclave is running on a real SGX device, which
in turn guarantees that the claims from the enclave are correct. Intel
has some example code and more detailed explanations of this process
on their [website][ra_sample] if you are interested.

This repository contains a pure Go implementation of the server side
operations in SGX RA.

[ra_sample]: https://software.intel.com/en-us/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example


## Requirements and installation

This code has been tested with Go v1.13. You can install this server
by doing

    go get -u ./...
    go install ./...

This code uses protobufs to define some types that will be shared
between the server and the enclave. There is an included generated
protobuf file (`sgx.pb.go`), so you shouldn't need the compiler. But
if you want to generate it from the proto source, you need [protobuf
compiler][protoc] with the [Go plugin][protobuf] for compiling the
regular protobuf and gRPC services. Please follow the instructions on
the [Go protobuf][protobuf] repository to install them. You also
might want `make` which automatically builds the protobuf and install
the example server, though the `Makefile` is simple enough that you
can just run those commands manually if you'd like.

[protoc]: https://developers.google.com/protocol-buffers/docs/downloads
[protobuf]: https://github.com/golang/protobuf


## Running the sample server

There is a sample server in `cmd/example_server` directory, which gets
installed with installation command above. To run the server, you need
to do two things:

1. Create a configuration file for the server. The configuration file
   is a JSON file containing a few fields. This is documented more
   carefully in `config.go`. Save this file somewhere, e.g.,
   `config.json`.

2. Acquire TLS certificate and key. For testing, you can use a
   self signed cert. Call these files `tls.crt` and `tls.key`.

Now, you can run the server:

    $GOPATH/bin/example_server -config config.json -tlsKey tls.key -tlsPub tls.crt

This runs the server on port 50051 (the default example port for
gRPC). You can override this port via `-port` option.


## Compatible SGX client and enclave

There is no public sample enclave that talks to this server yet, but
this is in the works. In general, the messages in the proto file has
been designed to very closely match the native SGX structures, so it
should just be a matter of translating the SGX structs to proto
messages, and sending it via gRPC calls defined in the proto file.
