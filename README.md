wireproxy
=========

PoC: Wireguard + gVisor userspace network stack + HTTP proxy = :heart:

Built on top of [dumbproxy](https://github.com/Snawoot/dumbproxy).

## Installation

#### Binary download

Pre-built binaries available on [releases](https://github.com/mysteriumnetwork/wireproxy/releases/latest) page.

#### From source

Alternatively, you may install wireproxy from source. Run within source directory

```
make install
```

## Usage

Put wireguard config in [portable format](https://www.wireguard.com/xplatform/#configuration-protocol) into some file:

```
private_key=a040e64ba968053326b6c27a156c7babf55cc05c43e4d88b47dd494cccc52540
public_key=c68ef6b420ef0838ccc4d649e1bb8058e95f848d0be1f3c8c6172fa59c1cfe1b
endpoint=157.90.228.151:26611
allowed_ip=0.0.0.0/0
```

Run application:

```
wireproxy -tun-addr 172.21.123.4 -wgconf p.conf
```

## Authentication

Authentication parameters are passed as URI via `-auth` parameter. Scheme of URI defines authentication metnod and query parameters define parameter values for authentication provider.

* `none` - no authentication. Example: `none://`. This is default.
* `static` - basic authentication for single login and password pair. Example: `static://?username=admin&password=123456`. Parameters:
  * `username` - login.
  * `password` - password.
  * `hidden_domain` - if specified and is not an empty string, proxy will respond with "407 Proxy Authentication Required" only on specified domain. All unauthenticated clients will receive "400 Bad Request" status. This option is useful to prevent DPI active probing from discovering that service is a proxy, hiding proxy authentication prompt when no valid auth header was provided. Hidden domain is used for generating 407 response code to trigger browser authorization request in cases when browser has no prior knowledge proxy authentication is required. In such cases user has to navigate to any hidden domain page via plaintext HTTP, authenticate themselves and then browser will remember authentication.
* `basicfile` - use htpasswd-like file with login and password pairs for authentication. Such file can be created/updated like this: `touch /etc/wireproxy.htpasswd && htpasswd -bBC 10 /etc/wireproxy.htpasswd username password`. `path` parameter in URL for this provider must point to a local file with login and bcrypt-hashed password lines. Example: `basicfile://?path=/etc/wireproxy.htpasswd`.
  * `path` - location of file with login and password pairs. File format is similar to htpasswd files. Each line must be in form `<username>:<bcrypt hash of password>`. Empty lines and lines starting with `#` are ignored.
  * `hidden_domain` - same as in `static` provider
* `cert` - use mutual TLS authentication with client certificates. In order to use this auth provider server must listen sockert in TLS mode (`-cert` and `-key` options) and client CA file must be specified (`-cacert`). Example: `cert://`.

## Synopsis

```
$ ~/go/bin/wireproxy -h
Usage of /home/user/go/bin/wireproxy:
  -auth string
    	auth parameters (default "none://")
  -bind-address string
    	HTTP proxy listen address (default ":8080")
  -cafile string
    	CA file to authenticate clients with certificates
  -cert string
    	enable TLS and use certificate
  -ciphers string
    	colon-separated list of enabled ciphers
  -disable-http2
    	disable HTTP2
  -dns-servers string
    	comma-separated list of DNS server addresses (default "1.1.1.1,1.0.0.1")
  -key string
    	key for TLS certificate
  -list-ciphers
    	list ciphersuites
  -mtu int
    	MTU value (default 1420)
  -timeout duration
    	timeout for network operations (default 10s)
  -tun-addr string
    	comma-separated list of local Wireguard tunnel addresses
  -verbosity int
    	logging verbosity (10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical) (default 20)
  -version
    	show program version and exit
  -wgconf string
    	wg config in portable format (https://www.wireguard.com/xplatform/#configuration-protocol)
```
