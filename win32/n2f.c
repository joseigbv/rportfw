/*********************************
 * n2f v0.2
 * Redirector fichero <-> socket 
 * (por defecto, n2f.dat <-> :9999)
 *********************************/
 
// librerias
#include <stdio.h>
#include <fcntl.h>
#ifdef WIN32
#include <winsock.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/in.h>
#define O_BINARY 0x00
#endif

// configuracion
#define PATH "n2f.dat"
#define BIND "127.0.0.1"
#define PORT 9999
#define BANNER "n2f v0.1 (C) 2014 Jose Ignacio Bravo"

// otros parametros
#define SZ_SBUF 1024
#define SZ_PATH 128

// aux 
#define ON_ERR(x, msg) if (x) { perror(msg); goto on_error; }

// uso de la herramienta
void usage()
{
	fprintf(stderr, "%s\n", BANNER);
	fprintf(stderr, "usage: n2f {i|o} [file [port]]\n\n");
	exit(-1);
}

// funcion principal
int main (int argc, char *argv[])
{
	int sz, s = -1, b = -1, port, f;
	char sbuf[SZ_SBUF], path[SZ_SBUF], op;
	struct sockaddr_in sa;
	int len = sizeof(struct sockaddr);		
#ifdef WIN32
	WSADATA wsa;

	// inicializamos winsock
	ON_ERR(WSAStartup(0x0101, &wsa), "WSAStartup");
#endif

	// comprobacion argumentos
	if (argc == 1) usage();

	// solo aceptamos input / output
	if ((op = argv[1][0]) != 'i' && op != 'o') usage(); 

	// fichero de entrada como parametro ?
	strncpy(path, argc > 1 ? argv[2] : PATH, SZ_PATH);

	// puerto de escucha ?
	port = (argc > 3) && (port = atoi(argv[3])) ? port : PORT;

	// creamos el socket
	ON_ERR((b = socket(AF_INET, SOCK_STREAM, 0)) == -1, "socket");

	// parametros conexion
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = inet_addr(BIND);

	// configuramos, escucha y esperamos conexion
	ON_ERR(bind(b, (struct sockaddr *) &sa, sizeof(sa)) == -1, "bind");
	ON_ERR(listen(b, 1) == -1, "listen");
	ON_ERR((s = accept(b, (struct sockaddr *) &sa, &len)) == -1, "accept");

	switch (op) {

		// de fichero a socket
		case 'i': 

			ON_ERR((f = open(path, O_RDONLY|O_BINARY)) == -1, "open");

			// leemos hasta fin de fichero
			while ((sz = read(f, sbuf, SZ_SBUF)) > 0)			
				ON_ERR(send(s, sbuf, sz, 0) == -1, "send");
			
			// error en lectura ? 
			ON_ERR(sz == -1, "read");
			
			break; 

		// de socket a fichero 
		case 'o': 

			ON_ERR((f = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 00744)) == -1, "open");

			// leemos hasta fin de fichero
			while ((sz = recv(s, sbuf, SZ_SBUF, 0)) > 0)
				ON_ERR(write(f, sbuf, sz) == -1, "write");
			
			// error ?
			ON_ERR(sz == -1, "recv");

			break;
	}

on_error: 

	// cerramos fichero
	close(f);

#ifdef WIN32

	// cerramos sockets 
	closesocket(s); 
	closesocket(b);

	// cerramos winsock	
	WSACleanup();

	// algun error ?
	return GetLastError();
	
#else

	// cerramos sockets
	close(s);
	close(b);

	// algun error ?
	return errno;
	
#endif
}
