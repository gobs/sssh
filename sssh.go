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
	"io"
	"io/ioutil"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
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

// NewClient creates a new ssh client/connection to host (host:port) with the specified options
func NewClient(host string, options ...ConnectOption) (*ssh.Client, error) {
	config, err := makeConfig(options...)
	if err != nil {
		return nil, err
	}

	client, err := sshClient(host, config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// NewSession creates a new ssh session/connection to host (host:port) with the specified options
func NewSession(host string, options ...ConnectOption) (*ssh.Session, error) {
	client, err := NewClient(host, options...)
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

var (
	ErrDir           = fmt.Errorf("source is a directory")
	ErrRemote        = fmt.Errorf("remote error")
	ErrRemoteFatal   = fmt.Errorf("remote fatal error")
	ErrRemoteUnknown = fmt.Errorf("remote unknown error")
)

func CopyFile(client *ssh.Client, dest, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}

	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return err
	}

	if stat.IsDir() {
		return ErrDir
	}

	return Copy(client, dest, stat.Name(), stat.Size(), stat.Mode().Perm()&os.ModePerm, f)
}

func Copy(client *ssh.Client, dest, src string, size int64, perm os.FileMode, reader io.Reader) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}

	defer session.Close()

	rin, err := session.StdinPipe()
	if err != nil {
		return err
	}

	defer rin.Close()

	rout, err := session.StdoutPipe()
	if err != nil {
		return err
	}

	checkStatus := func() (err error) {
		var b [256]byte

		if _, err := rout.Read(b[:1]); err != nil {
			return err
		}

		switch b[0] {
		case 0:
			err = nil

		case 1, 2:
			err = ErrRemote
			if b[0] == 2 {
				err = ErrRemoteFatal
			}

			n, _ := rout.Read(b[:])
			if n > 0 {
				fmt.Printf("Error %v: %v", err, string(b[:n]))
			}

		default:
			err = ErrRemoteUnknown
		}

		return
	}

	if err = session.Start("scp -t " + dest); err != nil {
		return err
	}

	cmd := fmt.Sprintf("C%04o %d %s\n", perm, size, src)

	_, err = io.WriteString(rin, cmd)
	if err != nil {
		return err
	}

	if err = checkStatus(); err != nil {
		return err
	}

	if _, err = io.Copy(rin, reader); err != nil {
		return err
	}

	var z [1]byte
	rin.Write(z[:]) // send \0 to finish

	if err = checkStatus(); err != nil {
		return err
	}

	rin.Close()
	return session.Wait()
}

func Shell(client *ssh.Client) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}

	defer session.Close()

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	stdin := int(os.Stdin.Fd())

	if terminal.IsTerminal(stdin) {
		state, err := terminal.MakeRaw(stdin)
		if err != nil {
			return err
		}

		defer terminal.Restore(stdin, state)

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}

		w, h, err := terminal.GetSize(stdin)
		if err != nil {
			return err
		}

		term := os.Getenv("TERM")
		if term == "" {
			term = "vt100"
		}

		if err := session.RequestPty(term, w, h, modes); err != nil {
			return err
		}
	}

	// Start remote shell
	if err := session.Shell(); err != nil {
		return err
	}

	return session.Wait()
}
