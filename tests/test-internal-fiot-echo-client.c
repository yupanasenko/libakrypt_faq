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

 #include <ak_fiot.h>

 int main( int argc, char *argv[] )
{
  char str[2048];
  struct fiot ctx;
  union sock_addr addr;
  int error = ak_error_ok, done = 1;
  ak_socket sock = ak_network_undefined_socket;

 /* проверяем, что определен ip адрес сервера и порт */
  if( argc != 3 ) {
    printf("usage: echo-client server_ip_address server_port\n");
    return EXIT_SUCCESS;
  }
 /* инициализируем библиотеку на стороне клиента
    вывод сообщений аудита производится в стандартный поток ошибок */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();
 /* устанавливаем максимальный уровень аудита */
  ak_log_set_level( fiot_log_maximum );

  /* часть первая: создание сокетов */

  /* выполняем действия, необходимые для соединения с сервером  */
   if(( sock = ak_network_socket( AF_INET, SOCK_STREAM, 0 )) == ak_network_undefined_socket ) {
     ak_error_message( ak_error_get_value(), __func__, "wrong socket creation" );
     return ak_libakrypt_destroy();
   }

   if(( error = ak_network_inet_pton( AF_INET, argv[1], atoi( argv[2] ), &addr )) != ak_error_ok ) {
     ak_network_close( sock );
     ak_error_message_fmt( error, __func__, "wrong assigning binary address to socket" );
     return ak_libakrypt_destroy();
   }

   if(( error = ak_network_connect( sock, &addr )) != ak_error_ok ) {
     ak_network_close( sock );
     ak_error_message_fmt( error, __func__, "wrong server connect" );
     return ak_libakrypt_destroy();
   }
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
                                    encryption_interface, sock )) != ak_error_ok ) goto exit;
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
      } else printf("echo-client: send %u bytes\n", (unsigned int) strlen( str ));
      if(( data = ak_fiot_context_read_frame( &ctx, &length, &mtype )) != NULL ) {
        data[length-1] = 0;
        printf("echo-client: recived [%s, %u bytes]\n", data, (unsigned int) length );
        if( strncmp( (char *)data, "quit", 4 ) == 0 ) done = 0;
      }
    }

  exit:
   ak_fiot_context_destroy( &ctx );
   ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
