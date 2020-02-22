// Package sssh (simple ssh) provides a wrapper that simplifies creating
// an ssh session (using golang.org/x/crypto/ssh).
//
// The package supports creating a session, authenticated via username/password
// or username/private key, with optional socks5 proxy or jump proxy.
//
// This is roughly equivalent to an ssh connection with the following options:
//
//  Host hostname
//    ProxyCommand /usr/bin/nc -x proxyserver:port %h %p
//    User username
//    IdentityFile privatekey-file
//
package sssh

import (
	"fmt"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

type sshConfig struct {
	clientConfig *ssh.ClientConfig

	proxyAddress string
	jumpConfig   *sshConfig
}

// ConnectOption is the common type for NewSession options
type ConnectOption func(c *sshConfig) error

// User sets the user name for authentication
func User(user string) ConnectOption {
	return func(c *sshConfig) error {
		c.clientConfig.User = user
		return nil
	}
}

// Password sets the user password for authentication
func Password(password string) ConnectOption {
	return func(c *sshConfig) error {
		c.clientConfig.Auth = append(c.clientConfig.Auth, ssh.Password(password))
		return nil
	}
}

// Timeout sets the connection timeout
func Timeout(t time.Duration) ConnectOption {
	return func(c *sshConfig) error {
		c.clientConfig.Timeout = t
		return nil
	}
}

// PrivateKeyFile sets the private key file for authentication
func PrivateKeyFile(keyFile string) ConnectOption {
	return func(c *sshConfig) error {
		key, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return err
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return err
		}

		c.clientConfig.Auth = append(c.clientConfig.Auth, ssh.PublicKeys(signer))
		return nil
	}
}

// PrivateKey sets the private key for authentication
func PrivateKey(key []byte) ConnectOption {
	return func(c *sshConfig) error {
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return err
		}

		c.clientConfig.Auth = append(c.clientConfig.Auth, ssh.PublicKeys(signer))
		return nil
	}
}

//type KeyboardInteractiveChallenge func(user, instruction string, questions []string, echos []bool) (answers []string, err error)
type KeyboardInteractiveChallenge = ssh.KeyboardInteractiveChallenge

// KeyboardInteractive sets the authentication mode to keyboar/interactive
func KeyboardInteractive(cb KeyboardInteractiveChallenge) ConnectOption {
	return func(c *sshConfig) error {
		c.clientConfig.Auth = append(c.clientConfig.Auth, ssh.KeyboardInteractive(cb))
		return nil
	}
}

// Banner sets the banner callback, called when the remote host sends the banner
func Banner(callback ssh.BannerCallback) ConnectOption {
	return func(c *sshConfig) error {
		c.clientConfig.BannerCallback = callback
		return nil
	}
}

// SocksProxy sets the (socks5) proxy address (host:port)
func SocksProxy(proxy string) ConnectOption {
	return func(c *sshConfig) error {
		c.proxyAddress = proxy
		c.jumpConfig = nil
		return nil
	}
}

func makeConfig(options ...ConnectOption) (*sshConfig, error) {
	config := &sshConfig{
		clientConfig: &ssh.ClientConfig{
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		},
	}

	for _, opt := range options {
		if err := opt(config); err != nil {
			return nil, err
		}
	}

	return config, nil
}

// JumpProxy configures the session to jump through one proxy server
func JumpProxy(proxy string, options ...ConnectOption) ConnectOption {
	return func(c *sshConfig) (err error) {
		c.proxyAddress = ""
		c.jumpConfig, err = makeConfig(options...)
		if c.jumpConfig != nil {
			c.jumpConfig.proxyAddress = proxy
		}
		return
	}
}

// NewSession creats a new ssh session/connection to host (host:port) with the specified options
func NewSession(host string, options ...ConnectOption) (*ssh.Session, error) {
	config, err := makeConfig(options...)
	if err != nil {
		return nil, err
	}

	client, err := sshClient(host, config)
	if err != nil {
		return nil, err
	}

	return client.NewSession()
}

func sshClient(address string, config *sshConfig) (*ssh.Client, error) {
	if config.proxyAddress != "" {
		dialer, err := proxy.SOCKS5("tcp", config.proxyAddress, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}

		conn, err := dialer.Dial("tcp", address)
		if err != nil {
			return nil, err
		}

		c, chans, reqs, err := ssh.NewClientConn(conn, address, config.clientConfig)
		if err != nil {
			return nil, err
		}

		return ssh.NewClient(c, chans, reqs), nil
	} else if config.jumpConfig != nil {
		fmt.Println("jump", config.jumpConfig, address)
		proxy, err := ssh.Dial("tcp", config.jumpConfig.proxyAddress, config.jumpConfig.clientConfig)
		if err != nil {
			return nil, err
		}

		conn, err := proxy.Dial("tcp", address)
		if err != nil {
			return nil, err
		}

		ncc, chans, reqs, err := ssh.NewClientConn(conn, address, config.clientConfig)
		if err != nil {
			return nil, err
		}

		return ssh.NewClient(ncc, chans, reqs), nil
	}

	return ssh.Dial("tcp", address, config.clientConfig)
}
