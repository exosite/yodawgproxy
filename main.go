package main

import (
	"io"
	"bufio"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"gopkg.in/yaml.v2"
	proxyproto "github.com/exosite/proxyprotov2"
)

var (
	SNI_REPLACERS = make([]ReplacementFunc, 0)
	HOST_REPLACERS = make([]ReplacementFunc, 0)
)

type ReplacementFunc func(input string) string

type HostReplacement struct {
	From string `yaml:"from"`
	To string `yaml:"to"`
}

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	Backend    string `yaml:"backend"`
	LogLevel string `yaml:"log_level"`
	HostReplacements []HostReplacement `yaml:"host_replacements"`
	SniReplacements []HostReplacement `yaml:"sni_replacements"`
}

type CopyResult struct {
	Err error
}

func copyFromBackend(conn io.Writer, backendConn io.Reader, c chan CopyResult) {
	log.Debugf("Copying data from the backend to the client...")
	var err error = nil
	defer func() {
		c <- CopyResult{
			Err: err,
		}
		log.Debugf("copyFromBackend finished.")
		close(c)
	}()
	_, err = io.Copy(conn, backendConn)
}

func copyToBackend(conn io.Reader, backendConn io.Writer, c chan CopyResult) {
	log.Debugf("Copying data to the backend from the client...")
	var err error = nil
	defer func() {
		c <- CopyResult{
			Err: err,
		}
		log.Debugf("copyToBackend finished.")
		close(c)
	}()
	if len(HOST_REPLACERS) == 0 {
		_, err = io.Copy(backendConn, conn)
	} else {
		log.Debugf("We're doing HTTP!")
		connBuf := bufio.NewReader(conn)
		log.Debugf("Reading HTTP request...")
		var req *http.Request
		req, err = http.ReadRequest(connBuf)
		log.Debugf("Read HTTP request!")
		if err != nil {
			return
		}
		if req.Body != nil {
			defer req.Body.Close()
		}
		host := req.Host
		for _, replacer := range HOST_REPLACERS {
			host = replacer(host)
		}
		req.Host = host
		log.Debugf("Host is now %s", host)
		req.Close = true
		err = req.Write(backendConn)
		if err != nil {
			return
		}
		if connBuf.Buffered() > 0 {
			// This should never happen.
			_, err = io.Copy(backendConn, connBuf)
		}
	}
}

func handleConn(config *Config, logger *log.Entry, conn net.Conn) {
	defer conn.Close()
	backendConn, err := net.Dial("tcp", config.Backend)
	if err != nil {
		logger.Errorf("Failed to connect to backend %s: %s", config.Backend, err.Error())
		return
	}
	defer backendConn.Close()

	proxyInfo, bytesToWrite, err := proxyproto.HandleProxy(conn)
	if err != nil {
		logger.Errorf("Failed to handle proxy protocol: %s", err.Error())
		return
	}

	if bytesToWrite != nil {
		logger.Debugf("Need to write %d bytes after proxy header:", len(bytesToWrite))
		logger.Debugf("%s", string(bytesToWrite))
		backendConn.Write(bytesToWrite)
	}

	if proxyInfo != nil {
		for _, tlv := range proxyInfo.TLVs {
			if tlv.Type() == proxyproto.PP2_TYPE_SSL {
				tls, ok := tlv.(*proxyproto.TlsTLV)
				if !ok {
					logger.Errorf("0x20 TLV isn't TlsTLV!  WTF?")
					return
				}
				if tls.Flags() == 0x0 {
					// If the SSL TLV says no SSL was used, then assume
					// it was an haproxy health check.
					return
				}

				for _, replacer := range SNI_REPLACERS {
					tls.SetSNI(replacer(tls.SNI()))
				}
				logger.Debugf("SNI is now %s", tls.SNI())
			}
		}
		defer logger.Debugf("Finished!")
		logger.Debugf("Got a proxy connection!")
		switch proxyInfo.AddrFamily {
		case proxyproto.ADDR_FAMILY_UNSPEC:
			logger.Debugf("Remote client connection is AF_UNSPEC")
		case proxyproto.ADDR_FAMILY_INET4:
			logger.Debugf("Remote client connection is AF_INET")
		case proxyproto.ADDR_FAMILY_INET6:
			logger.Debugf("Remote client connection is AF_INET6")
		case proxyproto.ADDR_FAMILY_UNIX:
			logger.Debugf("Remote client connection is AF_UNIX")
		default:
			logger.Errorf("Bad address family: %x", proxyInfo.AddrFamily)
			return
		}
		switch proxyInfo.Transport {
		case proxyproto.TRANSPORT_UNSPEC:
			logger.Debugf("Remote client connection is an unknown transport")
		case proxyproto.TRANSPORT_STREAM:
			logger.Debugf("Remote client connection is a stream transport")
		case proxyproto.TRANSPORT_DGRAM:
			logger.Debugf("Remote client connection is a datagram transport")
		default:
			logger.Errorf("Bad transport: %x", proxyInfo.Transport)
			return
		}
		err = proxyInfo.WriteTo(backendConn)
		if err != nil {
			logger.Errorf("Failed to forward proxy protocol header: %s", err.Error())
			return
		}
		logger.Debug("Sent proxy protocol header!")
		addrs, err := proxyInfo.Addrs()
		if err != nil {
			logger.Errorf("Failed to get addresses: %s", err.Error())
		} else {
			if len(addrs) == 0 {
				logger.Debug("No address information!")
			} else {
				logger.Debugf("Source address: %s", addrs[0])
				logger.Debugf("Destination address: %s", addrs[1])
			}
		}
	} else {
		logger.Debugf("Got a non-proxy connection")
		defer logger.Debugf("Finished!")
	}

	fromChan := make(chan CopyResult)
	toChan := make(chan CopyResult)

	go copyToBackend(conn, backendConn, toChan)
	time.Sleep(10 * time.Millisecond)
	go copyFromBackend(conn, backendConn, fromChan)

	fromDone := false
	toDone := false
	cancel := false
	for {

		select {
		case fromErr := <-fromChan:
			// This is stupid.
			fromChan = nil
			fromDone = true
			if fromErr.Err != nil {
				logger.Errorf("Error communicating from backend: %s", fromErr.Err.Error())
				cancel = true
				break
			}
			logger.Debugf("copyFromBackend reported in!")
		case toErr := <-toChan:
			// This is stupid.
			toChan = nil
			toDone = true
			if toErr.Err != nil {
				errStr := toErr.Err.Error()
				// I can't believe I'm doing this.
				if !strings.Contains(errStr, "connection reset by peer") {
					logger.Errorf("Error communicating to backend: %s", errStr)
				}
				cancel = true
				break
			}
			logger.Debugf("copyToBackend reported in!")
		}

		if fromDone && toDone {
			logger.Debugf("Both are done!")
			break
		}
		if cancel {
			logger.Debugf("Bailing out...")
			break
		}
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "yodawgproxy"
	app.Usage = "Proxy your proxy"
	app.Version = "1.0"
	app.Action = runServer
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: "/etc/yodawgproxy.yaml",
			Usage: "Configuration file",
		},
	}
	app.Run(os.Args)
}

func runServer(c *cli.Context) {
	var config Config
	configPath := c.String("config")
	configBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		panic(err)
	}

	switch config.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "panic":
		log.SetLevel(log.PanicLevel)
	default:
		log.SetLevel(log.ErrorLevel)
	}

	for _, sniReplacement := range config.SniReplacements {
		re, err := regexp.Compile(sniReplacement.From)
		if err != nil {
			panic(err)
		}
		replacement := sniReplacement.To
		SNI_REPLACERS = append(SNI_REPLACERS, func(input string) string {
			return re.ReplaceAllString(input, replacement)
		})
	}

	for _, hostReplacement := range config.HostReplacements {
		re, err := regexp.Compile(hostReplacement.From)
		if err != nil {
			panic(err)
		}
		replacement := hostReplacement.To
		HOST_REPLACERS = append(HOST_REPLACERS, func(input string) string {
			return re.ReplaceAllString(input, replacement)
		})
	}

	ln, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		panic(err)
	}

	connId := 0

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Errorf("Failed to accept connection: %s", err.Error())
			continue
		}

		go handleConn(&config, log.WithFields(log.Fields{
			"id": connId,
		}), conn)
		connId++
	}
}
