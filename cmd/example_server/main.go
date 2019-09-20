package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kwonalbert/sgx_server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	config = flag.String("config", "config.json", "JSON configuration file")
	port   = flag.String("port", "50051", "Port of this server")
	tlsKey = flag.String("tlsKey", "tls_private.pem", "PEM encoded TLS private key of the server")
	tlsPub = flag.String("tlsPub", "tls_public.pem", "PEM encoded TLS public key of the server")
)

type server struct {
	sm sgx_server.SessionManager
}

func (s *server) StartAttestation(ctx context.Context, in *sgx_server.Request) (*sgx_server.Challenge, error) {
	log.Println("Starting attestation")
	return s.sm.NewSession(in)
}

func (s *server) SendMsg1(ctx context.Context, in *sgx_server.Msg1) (*sgx_server.Msg2, error) {
	log.Println("Processing msg1")
	return s.sm.Msg1ToMsg2(in)
}

func (s *server) SendMsg3(ctx context.Context, in *sgx_server.Msg3) (*sgx_server.Msg4, error) {
	log.Println("Processing msg3")
	return s.sm.Msg3ToMsg4(in)
}

func main() {
	flag.Parse()

	creds, err := credentials.NewServerTLSFromFile(*tlsPub, *tlsKey)
	if err != nil {
		log.Fatal("Could not parse the TLS certificates")
	}

	sm := sgx_server.NewSessionManager(sgx_server.ReadConfiguration(*config))

	srv := grpc.NewServer(grpc.Creds(creds))
	lis, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		log.Fatal("Could not listen:", *port, err)
	}

	go func() {
		err = srv.Serve(lis)
		if err != nil && err != grpc.ErrServerStopped {
			log.Fatal("Serve err:", err)
		}
	}()

	sgx_server.RegisterAttestationServer(srv, &server{sm})

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	srv.Stop()
}
