/* Пример, реализующий клиентскую часть эхо-сервера,
   использующего обмен сообщениями по каналу связи, защищенному с помощью протокола sp fiot.
   В качестве транспорта используется tcp.

   Внимание! Используются не экспортируемые функции.

   test-internal-fiot-echo-client.c
*/

 #include <stdio.h>
 #include <errno.h>
 #include <stdlib.h>
 #include <string.h>

#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
 #include <sys/socket.h>
#endif
 #include <arpa/inet.h>
/*
 *  the function

int inet_pton(int af, const char *src, void *dst);

is declared in header file:

#include <arpa/inet.h>

if this is Windows (Vista or later) there is Winsock analog to this ANSI version:

INT WSAAPI InetPton(
  _In_   INT  Family,
  _In_   PCTSTR pszAddrString,
  _Out_  PVOID pAddrBuf
);

try #include <Ws2tcpip.h> add Ws2_32.lib

--4pie0*/


 #include <ak_fiot.h>

 int main( int argc, char *argv[] )
{
  char str[2048];
  struct fiot ctx;
  struct sockaddr_in serv;
  int error = ak_error_ok, sd = -1, done = 1;

 /* проверяем, что определен ip адрес сервера и порт */
  if( argc != 3 ) {
    printf("usage: echo-client server_ip_address server_port\n");
    return EXIT_SUCCESS;
  }

  /* часть первая: создание сокетов */

  /* инициализируем библиотеку на стороне клиента
     вывод сообщений аудита производится в стандартный поток ошибок */
   if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();
  /* устанавливаем максимальный уровень аудита */
   ak_log_set_level( fiot_log_maximum );

  /* выполняем действия, необходимые для соединения с сервером  */
   if(( sd = socket( AF_INET, SOCK_STREAM | SOCK_CLOEXEC , 0)) < 0 )
     return ak_error_message_fmt( -1, __func__,
                                         "wrong socket creation (%s)", strerror( errno ));

   memset( &serv, 0, sizeof( struct sockaddr_in ));
   serv.sin_family = AF_INET;
   serv.sin_port = htons( atoi( argv[2] ));
   if( inet_pton( AF_INET, argv[1], &( serv.sin_addr )) <= 0 )
     return ak_error_message_fmt( -1, __func__,
                                  "wrong server address creation (%s)", strerror( errno ));

   if( connect( sd, (struct sockaddr*) &serv, sizeof( serv )) )
     return ak_error_message_fmt( -1, __func__, "connect error (%s)", strerror( errno ));
   printf("echo-client: server connected on %s:%s\n", argv[1], argv[2] );


  /* часть вторая: аутентификация клиента и выполнение протокола выработки общих ключей */


  /* создаем контекст защищенного соединения */
   if(( error = ak_fiot_context_create( &ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect context creation" );

  /* устанавливаем роль */
   if(( error = ak_fiot_context_set_role( &ctx, client_role )) != ak_error_ok ) goto exit;
  /* устанавливаем идентификатор сервера */
   if(( error = ak_fiot_context_set_user_identifier( &ctx, server_role,
                                                 "serverID", 8 )) != ak_error_ok ) goto exit;
  /* устанавливаем сокет для внешнего (шифрующего) интерфейса */
   if(( error = ak_fiot_context_set_interface_descriptor( &ctx,
                                      encryption_interface, sd )) != ak_error_ok ) goto exit;
  /* здесь реализация протокола */
   if(( error = ak_fiot_context_keys_generation_protocol( &ctx )) != ak_error_ok ) goto exit;
   printf( "echo-client: server authentication is Ok\n" );


  /* часть третья: отправка и получение сообщений */

   while( done ) {
      size_t length;
      message_t mtype = undefined_message;
      ak_uint8 *data = NULL;

      memset( str, 0, sizeof( str ));
      printf("echo-client> "); fgets( str, sizeof( str ), stdin );
      if(( error = ak_fiot_context_write_frame( &ctx, str, strlen( str ),
                                             encrypted_frame, application_data )) != ak_error_ok ) {
        ak_error_message( error, __func__, "write error" );
      } else printf("echo-client: send %zu bytes\n", strlen( str ));
      if(( data = ak_fiot_context_read_frame( &ctx, &length, &mtype )) != NULL ) {
        data[length-1] = 0;
        printf("echo-client: recived [%s, %zu bytes]\n", data, length );
        if( strncmp( (char *)data, "quit", 4 ) == 0 ) done = 0;
      }
    }

  exit:
   ak_fiot_context_destroy( &ctx );
   ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
