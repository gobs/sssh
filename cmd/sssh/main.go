package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"github.com/gobs/sssh"
)

func main() {
	proxyAddr := ""
	serviceAddr := "localhost:22"
	username := ""
	password := ""
	privateKey := ""

	flag.StringVar(&proxyAddr, "proxy", proxyAddr, "proxy (socks5)")
	flag.StringVar(&serviceAddr, "addr", serviceAddr, "ssh address")
	flag.StringVar(&username, "user", username, "user name")
	flag.StringVar(&password, "password", password, "user password")
	flag.StringVar(&privateKey, "key", privateKey, "authentication private key")
	flag.Parse()

	options := []sssh.ConnectOption{
		sssh.User(username),
	}

	if password != "" {
		options = append(options, sssh.Password(password))
	}

	if privateKey != "" {
		options = append(options, sssh.PrivateKey(privateKey))
	}

	if proxyAddr != "" {
		options = append(options, sssh.SocksProxy(proxyAddr))
	}

	session, err := sssh.NewSession(serviceAddr, options...)
	if err != nil {
		log.Fatal(err)
	}

	defer session.Close()

	command := strings.Join(flag.Args(), " ")
	log.Println("ssh>", command)
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	if err = session.Run(command); err != nil {
		log.Fatal("run command: ", err)
	}
}
