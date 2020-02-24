package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gobs/sssh"
)

func main() {
	proxyAddr := ""
	socksAddr := ""
	serviceAddr := "localhost:22"
	username := ""
	password := ""
	privateKey := ""

	flag.StringVar(&proxyAddr, "proxy", proxyAddr, "proxy address (ssh)")
	flag.StringVar(&socksAddr, "socks", socksAddr, "proxy address (socks5)")
	flag.StringVar(&serviceAddr, "addr", serviceAddr, "ssh address")
	flag.StringVar(&username, "user", username, "user name")
	flag.StringVar(&password, "password", password, "user password")
	flag.StringVar(&privateKey, "key", privateKey, "authentication private key")
	keyboard := flag.Bool("keyboard", false, "authentication via keyboard/interactive")
	banner := flag.Bool("banner", false, "print remote host banner")
	copy := flag.Bool("cp", false, "copy input file to remote destination")
	flag.Parse()

	options := []sssh.ConnectOption{
		sssh.User(username),
	}

	if password != "" {
		options = append(options, sssh.Password(password))
	}

	if privateKey != "" {
		options = append(options, sssh.PrivateKeyFile(privateKey))
	}

	if *keyboard {
		options = append(options, sssh.KeyboardInteractive(
			func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
				fmt.Println("KeyboardInteractive challenge for", user)
				fmt.Println("Instructions:", instruction)
				for i, q := range questions {
					fmt.Println("Question", i, q, echos[i])
				}
				answers = make([]string, len(questions))
				return
			}))
	}

	if *banner {
		options = append(options, sssh.Banner(func(message string) error {
			fmt.Println(message)
			return nil
		}))
	}

	if socksAddr != "" {
		options = append(options, sssh.SocksProxy(socksAddr))
	}

	if proxyAddr != "" {
		options = append(options, sssh.JumpProxy(proxyAddr, options...))
	}

	if *copy {
		if flag.NArg() != 1 {
			log.Fatal("-cp requires one input file")
		}

		client, err := sssh.NewClient(serviceAddr, options...)
		if err != nil {
			log.Fatal(err)
		}

		if err = sssh.CopyFile(client, flag.Arg(0), flag.Arg(0)); err != nil {
			log.Fatal(err)
		}
	} else if flag.NArg() > 0 {
		session, err := sssh.NewSession(serviceAddr, options...)
		if err != nil {
			log.Fatal(err)
		}

		defer session.Close()

		command := strings.Join(flag.Args(), " ")
		log.Printf("run %q", command)
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		if err = session.Run(command); err != nil {
			log.Fatal("run command: ", err)
		}
	} else {
		client, err := sssh.NewClient(serviceAddr, options...)
		if err != nil {
			log.Fatal(err)
		}

		if err = sssh.Shell(client); err != nil {
			log.Fatal(err)
		}
	}
}
