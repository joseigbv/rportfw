# rportfw (Remote port forward)

Remote port redirector by reverse connection with proxy support for Windows. Useful in pentesting.

## Features

* Reverse connection through proxy.
* Remote multi port forwarding.
* Basic auth.
* Encryption (optional, rc4).
* Compression zlib (testing).
* Automatic execution of command associated to port when connecting.
* Includes starter tool loader
* Includes auto-install function at startup (--install)

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

rportfw should compile/run on any Win32 (redirector) and UNIX/Linux box (client). You only need a relatively modern C compiler.

### Installing

Download a copy of the project from github:

```
$ git clone https://github.com/joseigbv/rportfw.git
```

Edit 'rportfw.c' and change configuration (optional).

Compile (E.g. MinGW):

```
$ gcc -Wall -s -Os rportfw.c -o rportfw -lwsock32
```

Directives: 
* Run in background: -DDAEMON -mwindows
* Proxy support: -DPROXY
* Auto-download tools: -DLOADER
* Compression (miniz): -DCOMP
* Encrypt (rc4): -DCRYPT rc4.c 
 
### Usage

PENDIENTE ...

## Authors

* **José Ignacio Bravo** - *Initial work* - nacho.bravo@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
