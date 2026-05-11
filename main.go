package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/songgao/water"
)

func writeAll(wr io.Writer, buf []byte) error {
	offset := 0
	for offset < len(buf) {
		written, err := wr.Write(buf[offset:])
		if err != nil {
			return err
		}
		offset += written
	}
	return nil
}

func readAll(rd io.Reader, buf []byte) error {
	offset := 0
	for offset < len(buf) {
		bytesRead, err := rd.Read(buf[offset:])
		if err != nil {
			return err
		}
		offset += bytesRead
	}
	return nil
}

// // For debug
// func PrintHex(data []byte) {
// 	for i := 0; i < len(data); i += 16 {
// 		fmt.Printf("%08x: ", i)
// 		end := min(i + 16, len(data))
// 		for j, b := range data[i:end] {
// 			if j > 0 {
// 				fmt.Print(" ")
// 			}
// 			fmt.Printf("%02x", b)
// 		}
// 		fmt.Println()
// 	}
// }

func sender(wg *sync.WaitGroup, no int, iface *water.Interface, wr io.WriteCloser) {
	if wg != nil {
		defer wg.Done()
	}
	defer log.Printf("sender %d: Terminated", no)
	defer wr.Close()

	log.Printf("sender %d: Started", no)

	if err := writeAll(wr, []byte{0x27, 0x20}); err != nil {
		log.Printf("sender %d: Failed to send session ack: %s", no, err)
		return
	}

	packet := new([65536]byte)
	for {
		packetSize, err := iface.Read(packet[:])
		if err != nil {
			log.Printf("sender %d: Failed to read packet from TUN: %s", no, err)
			return
		}

		if err := writeAll(wr, packet[:packetSize]); err != nil {
			log.Printf("sender %d: Failed to send packet: %s", no, err)
			return
		}
	}
}

func receiver(wg *sync.WaitGroup, no int, iface *water.Interface, conn net.Conn, prevConn io.Closer) {
	if wg != nil {
		defer wg.Done()
	}
	defer log.Printf("receiver %d: Terminated", no)
	defer conn.Close()

	log.Printf("receiver %d: Started", no)

	if err := conn.SetReadDeadline(time.Now().Add(time.Second * 30)); err != nil {
		log.Printf("receiver %d: Failed to set read deadline: %s", no, err)
		return
	}

	var sessionStartAck [2]byte
	if err := readAll(conn, sessionStartAck[:]); err != nil {
		log.Printf("receiver %d: Failed to read session ack: %s", no, err)
		return
	}
	if sessionStartAck[0] != 0x27 && sessionStartAck[1] != 0x20 {
		log.Printf("receiver %d: Invalid session ack", no)
		return
	}
	if prevConn != nil {
		if err := prevConn.Close(); err != nil {
			log.Printf("receiver %d: Failed to close the previous client socket: %s", no, err)
		} else {
			log.Printf("receiver %d: Close the previous client socket: %s", no, err)
		}
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("receiver %d: Failed to clear read deadline: %s", no, err)
		return
	}

	var header [8]byte
	packet := new([65536]byte)
	for {
		if err := readAll(conn, header[:]); err != nil {
			log.Printf("receiver %d: Failed to read header: %s", no, err)
			return
		}

		var packetSize int
		switch (header[0] & 0xf0) >> 4 {
		case 4:
			packetSize = int(header[2])<<8 | int(header[3])
		case 6:
			packetSize = 40 + (int(header[4])<<8 | int(header[5]))
		default:
			log.Printf("receiver %d: Invalid packet header", no)
			return
		}

		copy(packet[0:8], header[:])

		if err := readAll(conn, packet[8:packetSize]); err != nil {
			log.Printf("receiver %d: Failed to receive packet: %s", no, err)
			return
		}

		_, err := iface.Write(packet[:packetSize])
		if err != nil {
			log.Printf("receiver %d: Failed to write packet to TUN: %s", no, err)
			// may happen if, for example, the interface is not ready yet.
			// so, no reason to fail
		}
	}
}

func waitWG(wg *sync.WaitGroup, ch chan<- struct{}) {
	wg.Wait()
	ch <- struct{}{}
}

func ipLog(args ...string) error {
	cmdStr := fmt.Sprintf("ip %s", strings.Join(args, " "))
	log.Printf("[#] %s", cmdStr)
	cmd := exec.Command("ip", args...)
	err := cmd.Run()
	if err != nil {
		log.Printf("%s: %s", cmdStr, err)
	}
	return err
}

func listen(bind string) (
	listener net.Listener,
	getRawConn func(net.Conn) (syscall.RawConn, error),
	err error,
) {
	getRawConn = func(conn net.Conn) (syscall.RawConn, error) {
		return conn.(*net.TCPConn).SyscallConn()
	}

	listener, err = net.Listen("tcp", bind)
	return
}

func listenTLS(
	serverKeyPath string,
	serverCertPath string,
	clientCertPath string,
	bind string,
) (
	listener net.Listener,
	getRawConn func(net.Conn) (syscall.RawConn, error),
	err error,
) {
	getRawConn = func(conn net.Conn) (syscall.RawConn, error) {
		return conn.(*tls.Conn).NetConn().(*net.TCPConn).SyscallConn()
	}

	servCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return
	}
	clientCertBytes, err := os.ReadFile(clientCertPath)
	if err != nil {
		return
	}
	clientCertPool := x509.NewCertPool()
	if !clientCertPool.AppendCertsFromPEM(clientCertBytes) {
		err = errors.New("failed to load client cert")
		return
	}

	cfg := tls.Config{
		Certificates: []tls.Certificate{servCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
	}

	listener, err = tls.Listen("tcp", bind, &cfg)
	return
}

func dial(remoteAddr string) (net.Conn, syscall.RawConn, error) {
	tcpConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		return nil, nil, err
	}
	rawConn, err := tcpConn.(*net.TCPConn).SyscallConn()
	if err != nil {
		tcpConn.Close()
		return nil, nil, err
	}
	return tcpConn, rawConn, nil
}

func dialTLS(
	clientKeyPath string,
	clientCertPath string,
	serverCertPath string,
	remoteAddr string,
) (net.Conn, syscall.RawConn, error) {
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, nil, err
	}
	serverCertBytes, err := os.ReadFile(serverCertPath)
	if err != nil {
		return nil, nil, err
	}
	serverCertPool := x509.NewCertPool()
	if !serverCertPool.AppendCertsFromPEM(serverCertBytes) {
		return nil, nil, errors.New("failed to load server cert")
	}

	cfg := tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      serverCertPool,
	}

	tlsConn, err := tls.Dial("tcp", remoteAddr, &cfg)
	if err != nil {
		return nil, nil, err
	}

	rawConn, err := tlsConn.NetConn().(*net.TCPConn).SyscallConn()
	if err != nil {
		return nil, nil, err
	}

	return tlsConn, rawConn, nil
}

func setFwmark(conn syscall.RawConn, fwmark uint32) error {
	var optErr error
	err := conn.Control(func(fd uintptr) {
		optErr = syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(fwmark))
	})
	if err != nil {
		return err
	}
	return optErr
}

type server struct {
	BindAddr       string
	Secure         bool
	ServerCertPath string
	ServerKeyPath  string
	ClientCertPath string
	Iface          *water.Interface
}

func (s *server) run() int {
	var err error
	var listener net.Listener
	if s.Secure {
		listener, _, err = listenTLS(s.ServerKeyPath, s.ServerCertPath, s.ClientCertPath, s.BindAddr)
		if err != nil {
			log.Printf("Failed to listen TLS: %s", err)
			return 1
		}
	} else {
		listener, _, err = listen(s.BindAddr)
		if err != nil {
			log.Printf("Failed to listen plaintext LTS: %s", err)
			return 1
		}
		log.Printf("WARNING: accepting plaintext TCP connections\n")
	}

	var prevConn net.Conn
	var clientNo int
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept: %s", err)
			continue
		}
		log.Printf("Accepted %s", conn.RemoteAddr())

		go sender(nil, clientNo, s.Iface, conn)
		go receiver(nil, clientNo, s.Iface, conn, prevConn)

		prevConn = conn
		clientNo++
	}
}

type client struct {
	Secure         bool
	RemoteAddr     string
	IfaceName      string
	IfaceAddr      string
	ClientCertPath string
	ClientKeyPath  string
	ServerCertPath string
	Fwmark         uint32
	Iface          *water.Interface
	SkipIfSetup    bool
}

func (c *client) run() int {
	var err error
	var conn net.Conn
	var rawConn syscall.RawConn
	if c.Secure {
		conn, rawConn, err = dialTLS(c.ClientKeyPath, c.ClientCertPath, c.ServerCertPath, c.RemoteAddr)
		if err != nil {
			log.Printf("Failed to dial plaintext TCP: %s", err)
			return 1
		}
	} else {
		conn, rawConn, err = dial(c.RemoteAddr)
		if err != nil {
			log.Printf("Failed to dial plaintext TCP: %s", err)
			return 1
		}
		log.Printf("WARNING: dialing plaintext TCP\n")
	}

	log.Printf("Connected to remote host")

	if !c.SkipIfSetup {
		err = setFwmark(rawConn, uint32(c.Fwmark))
		if err != nil {
			log.Printf("Failed to set fwmark: %s", err)
			return 1
		}

		fwmarkStr := strconv.FormatUint(uint64(c.Fwmark), 10)
		if err := ipLog("rule", "add", "not", "fwmark", fwmarkStr, "table", fwmarkStr); err != nil {
			return 1
		}
		defer ipLog("rule", "delete", "table", fwmarkStr)
		if err := ipLog("route", "add", "0.0.0.0/0", "dev", c.IfaceName, "table", fwmarkStr, "table", fwmarkStr); err != nil {
			return 1
		}
	}

	socketClosedCh := make(chan struct{})
	signalCh := make(chan os.Signal, 1)

	var wg sync.WaitGroup
	wg.Add(2)
	go sender(&wg, 0, c.Iface, conn)
	go receiver(&wg, 0, c.Iface, conn, nil)
	go waitWG(&wg, socketClosedCh)

	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-socketClosedCh:
	case <-signalCh:
	}

	// defer stmts executed

	return 0
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s [-l <bind address>] [-c <connect address>] <interface> <net>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\t[--server-key <key path>] [--server-cert <cert path>]\n")
	fmt.Fprintf(os.Stderr, "\t[--client-key <key path>] [--client-cert <cert path>]\n")
	fmt.Fprintf(os.Stderr, "\t[--fwmark <fwmark>]\n")
	fmt.Fprintf(os.Stderr, "\t[--skip-if-setup]\n")
	fmt.Fprintf(os.Stderr, "To run client with TLS, specify -c, --server-cert, --client-key and --client-cert\n")
	fmt.Fprintf(os.Stderr, "To run server with TLS, specify -s, --server-cert, --server-key, and --client-cert\n")
}

func main() {
	// TODO: add IPv6 support

	var bindAddr string
	var remoteAddr string
	var secure bool
	var serverCertPath string
	var serverKeyPath string
	var clientCertPath string
	var clientKeyPath string
	var fwMark int64
	var skipIfSetup bool

	flag.StringVar(&bindAddr, "l", "", "Address to bind")
	flag.StringVar(&remoteAddr, "c", "", "Address to connect")
	flag.BoolVar(&secure, "s", false, "Use TLS")
	flag.StringVar(&serverKeyPath, "server-key", "", "Path to the server key file")
	flag.StringVar(&serverCertPath, "server-cert", "", "Path to the server cert file")
	flag.StringVar(&clientKeyPath, "client-key", "", "Path to the client key file")
	flag.StringVar(&clientCertPath, "client-cert", "", "Path to the client cert file")
	flag.Int64Var(&fwMark, "fwmark", 2720184, "Firewall mark and table id (272018 by default)")
	flag.BoolVar(&skipIfSetup, "skip-if-setup", false, "Skip interface setup (addr, route, fwmark)")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "Invalid usage\n")
		usage()
		os.Exit(1)
	}

	if (len(bindAddr) == 0) == (len(remoteAddr) == 0) {
		fmt.Fprintf(os.Stderr, "Exactly one of the -l, -c flags should be given\n")
		usage()
		os.Exit(1)
	}

	if fwMark < 0 || fwMark > math.MaxUint32 {
		fmt.Fprintf(os.Stderr, "Firewall mark should be a 32-bit unsigned integer\n")
		os.Exit(1)
	}

	ifaceName := flag.Arg(0)
	ifaceAddr := flag.Arg(1)

	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: ifaceName,
		},
	})
	if err != nil {
		log.Fatalf("Failed to create TUN: %s", err)
	}

	if !skipIfSetup {
		if err := ipLog("link", "set", "up", "dev", ifaceName); err != nil {
			os.Exit(1)
		}
		if err := ipLog("address", "add", ifaceAddr, "dev", ifaceName); err != nil {
			os.Exit(1)
		}
	}

	if !secure && (len(serverCertPath) != 0 ||
		len(serverKeyPath) != 0 ||
		len(clientCertPath) != 0 ||
		len(clientKeyPath) != 0) {
		fmt.Fprintf(os.Stderr, "To enable secure mode, pass `-s` flag\n")
		usage()
		os.Exit(1)
	}

	if len(bindAddr) != 0 {
		if secure {
			if len(serverCertPath) == 0 || len(serverKeyPath) == 0 || len(clientCertPath) == 0 {
				fmt.Fprintf(
					os.Stderr,
					"Secured TLS server should be given: server-key, server-cert, client-cert\n",
				)
				usage()
				os.Exit(1)
			}
		}

		s := server{
			BindAddr:       bindAddr,
			Secure:         secure,
			ServerCertPath: serverCertPath,
			ServerKeyPath:  serverKeyPath,
			ClientCertPath: clientCertPath,
			Iface:          iface,
		}
		os.Exit(s.run())
	} else if len(remoteAddr) != 0 {
		if secure {
			if len(clientCertPath) == 0 || len(clientKeyPath) == 0 || len(serverCertPath) == 0 {
				fmt.Fprintf(
					os.Stderr,
					"Secured TLS client should be given: client-key, client-cert, server-cert\n",
				)
				usage()
				os.Exit(1)
			}
		}

		c := client{
			Secure:         secure,
			RemoteAddr:     remoteAddr,
			IfaceName:      ifaceName,
			IfaceAddr:      ifaceAddr,
			ClientCertPath: clientCertPath,
			ClientKeyPath:  clientKeyPath,
			ServerCertPath: serverCertPath,
			Fwmark:         uint32(fwMark),
			Iface:          iface,
			SkipIfSetup:    skipIfSetup,
		}
		os.Exit(c.run())
	}
}
