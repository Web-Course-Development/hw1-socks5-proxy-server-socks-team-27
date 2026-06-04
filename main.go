package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	socksVersion = 0x05

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03

	repSuccess                 = 0x00
	repGeneralFailure          = 0x01
	repHostUnreachable         = 0x04
	repConnectionRefused       = 0x05
	repCommandNotSupported     = 0x07
	repAddressTypeNotSupported = 0x08
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := negotiateAuth(conn); err != nil {
		log.Printf("auth negotiation failed: %v", err)
		return
	}

	targetAddress, replyCode, err := readConnectRequest(conn)
	if err != nil {
		_ = sendReply(conn, replyCode)
		log.Printf("connect request failed: %v", err)
		return
	}

	targetConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		_ = sendReply(conn, mapDialError(err))
		log.Printf("failed to connect to target %s: %v", targetAddress, err)
		return
	}
	defer targetConn.Close()

	if err := sendReply(conn, repSuccess); err != nil {
		log.Printf("failed to send success reply: %v", err)
		return
	}

	relay(conn, targetConn)
}

func negotiateAuth(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	if nMethods == 0 {
		return fmt.Errorf("client sent zero auth methods")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	requireUserPass := os.Getenv("PROXY_USER") != ""

	if requireUserPass {
		if !containsMethod(methods, methodUserPass) {
			_, _ = conn.Write([]byte{socksVersion, methodNoAcceptable})
			return fmt.Errorf("username/password auth required but not offered")
		}

		if _, err := conn.Write([]byte{socksVersion, methodUserPass}); err != nil {
			return err
		}

		return authenticateUserPass(conn)
	}

	if !containsMethod(methods, methodNoAuth) {
		_, _ = conn.Write([]byte{socksVersion, methodNoAcceptable})
		return fmt.Errorf("no-auth method not offered")
	}

	_, err := conn.Write([]byte{socksVersion, methodNoAuth})
	return err
}

func containsMethod(methods []byte, wanted byte) bool {
	for _, method := range methods {
		if method == wanted {
			return true
		}
	}
	return false
}

func authenticateUserPass(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x01 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("unsupported username/password auth version: %d", header[0])
	}

	usernameLength := int(header[1])
	if usernameLength == 0 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("empty username")
	}

	usernameBytes := make([]byte, usernameLength)
	if _, err := io.ReadFull(conn, usernameBytes); err != nil {
		return err
	}

	passwordLengthBuffer := make([]byte, 1)
	if _, err := io.ReadFull(conn, passwordLengthBuffer); err != nil {
		return err
	}

	passwordLength := int(passwordLengthBuffer[0])
	passwordBytes := make([]byte, passwordLength)
	if _, err := io.ReadFull(conn, passwordBytes); err != nil {
		return err
	}

	expectedUsername := os.Getenv("PROXY_USER")
	expectedPassword := os.Getenv("PROXY_PASS")

	if string(usernameBytes) != expectedUsername || string(passwordBytes) != expectedPassword {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid username or password")
	}

	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func readConnectRequest(conn net.Conn) (string, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", repGeneralFailure, err
	}

	if header[0] != socksVersion {
		return "", repGeneralFailure, fmt.Errorf("unsupported SOCKS version in request: %d", header[0])
	}

	if header[1] != cmdConnect {
		return "", repCommandNotSupported, fmt.Errorf("unsupported command: %d", header[1])
	}

	if header[2] != 0x00 {
		return "", repGeneralFailure, fmt.Errorf("invalid reserved byte: %d", header[2])
	}

	addressType := header[3]
	var host string

	switch addressType {
	case atypIPv4:
		ipBytes := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBytes); err != nil {
			return "", repGeneralFailure, err
		}
		host = net.IP(ipBytes).String()

	case atypDomain:
		lengthBuffer := make([]byte, 1)
		if _, err := io.ReadFull(conn, lengthBuffer); err != nil {
			return "", repGeneralFailure, err
		}

		domainLength := int(lengthBuffer[0])
		if domainLength == 0 {
			return "", repGeneralFailure, fmt.Errorf("empty domain name")
		}

		domainBytes := make([]byte, domainLength)
		if _, err := io.ReadFull(conn, domainBytes); err != nil {
			return "", repGeneralFailure, err
		}
		host = string(domainBytes)

	default:
		return "", repAddressTypeNotSupported, fmt.Errorf("unsupported address type: %d", addressType)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", repGeneralFailure, err
	}

	port := binary.BigEndian.Uint16(portBytes)
	targetAddress := net.JoinHostPort(host, strconv.Itoa(int(port)))

	return targetAddress, repSuccess, nil
}

func sendReply(conn net.Conn, replyCode byte) error {
	reply := []byte{
		socksVersion,
		replyCode,
		0x00,
		atypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	_, err := conn.Write(reply)
	return err
}

func mapDialError(err error) byte {
	message := strings.ToLower(err.Error())

	if strings.Contains(message, "refused") {
		return repConnectionRefused
	}

	return repHostUnreachable
}

func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, client)
		closeWrite(target)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, target)
		closeWrite(client)
	}()

	wg.Wait()
}

func closeWrite(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
		return
	}

	_ = conn.Close()
}
