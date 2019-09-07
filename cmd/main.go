package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kwonalbert/sgx_server"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	release = flag.Bool("release", false, "SGX release mode indicator")
	port    = flag.String("port", "50051", "Port of this server")
	spid    = flag.String("spid", "spid", "File containing the SPID")
	mr      = flag.String("mr", "mrenclaves", "Directory containing all valid MRs")
	ltKey   = flag.String("ltKey", "server_private.pem", "PEM encoded long private key of the server")
	iasKey  = flag.String("iasKey", "ias_private.pem", "PEM encoded TLS private key for establishing connection with IAS")
	iasPub  = flag.String("iasPub", "ias_public.pem", "PEM encoded TLS public key for establishing connection with IAS")
	tlsKey  = flag.String("tlsKey", "tls_private.pem", "PEM encoded TLS private key of the server")
	tlsPub  = flag.String("tlsPub", "tls_public.pem", "PEM encoded TLS public key of the server")
)

type server struct {
	sm *sgx_server.SessionManager
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

	ltPriv := sgx_server.LoadPrivateKey(*ltKey, "")

	creds, err := credentials.NewServerTLSFromFile(*tlsPub, *tlsKey)
	if err != nil {
		log.Fatal("Could not parse the TLS certificates")
	}

	mrenclaves := sgx_server.ReadMREnclaves(*mr)
	srv := grpc.NewServer(grpc.Creds(creds))

	sm := sgx_server.NewSessionManager(*release, *iasKey, *iasPub, mrenclaves, sgx_server.ReadSPID(*spid), ltPriv)

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
