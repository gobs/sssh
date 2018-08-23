# sssh (simple ssh)
A wrapper to golang.org/x/crypto/ssh to simplify session creation

This package provides a wrapper that simplifies creating an ssh session.

The package supports creating a session, authenticated via username/password
or username/private key, with optional socks5 proxy.

This is roughly equivalent to an ssh connection with the following options:

    Host hostname
      ProxyCommand /usr/bin/nc -x proxyserver:port %h %p
      User username
      IdentityFile privatekey-file
  
To use, create a new session:

	session, err := sssh.NewSession("somehost:22",
		                        sssh.User(username),
		                        sssh.Password(password))
        if err != nil {
            ...
        }
	defer session.Close()

Then use one of the methods in ssh.Session (https://godoc.org/golang.org/x/crypto/ssh#Session):

	if err = session.Run("ls -l"); err != nil {
		...
	}

Additional documentation is available at https://godoc.org/github.com/gobs/sssh.

A working example is available in the cmd/sssh subfolder.
