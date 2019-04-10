/* Пример, в котором на примере эхо-серера
   иллюстрируется защищенный обмен между потомком и родителем.
   Взаимодействие происходит с использованием сокетов домена unix.

   test-internal-fiot-unix.c
*/

 #include <errno.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <string.h>
 #include <sys/un.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <ak_fiot.h>

 #define SOCK_PATH "echo_socket"

 int client( void );
 int server( void );

 int main( void )
{
 /* инициализируем криптобиблиотеку в корневом процессе */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();
 /* устанавливаем максимальный уровень аудита */
  ak_log_set_level( fiot_log_maximum );

  switch( fork( )) {
   case -1: return EXIT_FAILURE;
   case  0: /*  потомок */
            client(); /* запускаем  */
            break;
   default: /* родитель */
            server(); /* стартуем */
            break;
  }

 return ak_libakrypt_destroy();
}

/* функция реализует простейший эхо-сервер */
 int server( void )
{
  int s, s2;
  socklen_t t, len;
  struct sockaddr_un local, remote;

 /* создаем сокет */
  if(( s = socket( AF_UNIX, SOCK_STREAM, 0 )) == -1 )
    return ak_error_message_fmt( s, __func__, "socket error (%s)", strerror( errno ));

 /* связываем сокет с заданным файлом (сокетом домена unix) */
  local.sun_family = AF_UNIX;
  strcpy( local.sun_path, SOCK_PATH);
  unlink( local.sun_path ); /* удаляем файл, если существует */
  len = (socklen_t)( strlen( local.sun_path ) + sizeof( local.sun_family ));
  if( bind( s, (struct sockaddr *)&local, len ) == -1)
    return ak_error_message_fmt( -1, __func__, "bind error (%s)", strerror( errno ));

 /* переходим в режим прослушивания */
  if( listen( s, 5 ) == -1 )
    return ak_error_message_fmt( -1, __func__, "listen error (%s)", strerror( errno ));

        ssize_t done;
        int error = ak_error_ok;
        struct fiot fctx;

        printf("server: waiting for a connection...\n");
        t = sizeof( remote );
        if(( s2 = accept(s, (struct sockaddr *)&remote, (socklen_t *)&t )) == -1)
           return ak_error_message_fmt( -1, __func__, "accept error (%s)", strerror( errno ));
        printf("server: connected.\n"); fflush( stdout );

       /* в этот момент связь с клиентом установлена,
           обмен данными будем производить по сокету s2 */

       /* создаем контекст защищенного соединения */
        if(( error = ak_fiot_context_create( &fctx )) != ak_error_ok ) goto exit;

       /* устанавливаем роль */
        if(( error = ak_fiot_context_set_role( &fctx, server_role )) != ak_error_ok ) goto full_exit;

       /* устанавливаем идентификатор сервера */
        if(( error = ak_fiot_context_set_user_identifier( &fctx, server_role,
                                                    "serverID", 8 )) != ak_error_ok ) goto full_exit;

       /* устанавливаем сокет для внешнего (шифрующего) интерфейса */
        if(( error = ak_fiot_context_set_gate_descriptor( &fctx,
                                              encryption_gate, s2 )) != ak_error_ok ) goto full_exit;

       /* выполняем процесс получения и возврата последовательностей символов */
        done = 0;
        do {
            size_t length;
            message_t mtype = undefined_message;
            char *data = ak_fiot_context_read_frame( &fctx, &length, &mtype );
            if( data == NULL ) {
              printf("server: timeout"); continue;
            }
            if( strncmp( data, "quit", 4 ) == 0 ) done = 1;
            if( !done )
              if(( error = ak_fiot_context_write_frame( &fctx, NULL,
                                             data, length, encrypted_frame, mtype )) != ak_error_ok )
                ak_error_message( error, __func__, "write error");
        } while (!done);

   full_exit:
    ak_fiot_context_destroy( &fctx );

   exit:
    close(s2);
    close(s);
    printf("server: connection closed\n");

 return ak_error_ok;
}

/* функция реализует клиентскую часть эхо-сервера */
 int client( void  )
{
    socklen_t len;
    int s, error = ak_error_ok;
    struct fiot fctx;
    struct sockaddr_un remote;
    char str[32];

    if(( s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 )
      return ak_error_message_fmt( -1, __func__, "incorrect socket creation (%s)", strerror( errno ));

    printf("client: trying to connect...\n");

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, SOCK_PATH);
    len = (socklen_t)( strlen( remote.sun_path ) + sizeof( remote.sun_family ));
    if( connect(s, (struct sockaddr *)&remote, len) == -1)
      return ak_error_message_fmt( -1, __func__, "incorrect connect (%s)", strerror( errno ));

    printf("client: connected.\n"); fflush( stdout );

       /* в этот момент связь с сервером установлена,
           обмен данными будем производить по сокету s */

       /* создаем контекст защищенного соединения */
        if(( error = ak_fiot_context_create( &fctx )) != ak_error_ok ) goto exit;

       /* устанавливаем роль */
        if(( error = ak_fiot_context_set_role( &fctx, client_role )) != ak_error_ok ) goto full_exit;

       /* устанавливаем сокет для внешнего (шифрующего) интерфейса */
        if(( error = ak_fiot_context_set_gate_descriptor( &fctx,
                                              encryption_gate, s )) != ak_error_ok ) goto full_exit;
        while(1) {

         size_t length;
         message_t mtype = undefined_message;
         char *data = NULL;

         memset( str, 0, sizeof( str ));
         printf("client> "); fgets( str, 31, stdin );
         if(( error = ak_fiot_context_write_frame( &fctx, NULL, str, strlen( str ),
                                             encrypted_frame, application_data )) != ak_error_ok ) {
           ak_error_message( error, __func__, "write error" );
         } else printf("client: (send %lu bytes)\n", strlen( str ));
         if(( data = ak_fiot_context_read_frame( &fctx, &length, &mtype )) != NULL ) {
           data[length-1] = 0;
           printf("  echo: %s (recv: %lu bytes, type: %x)\n", data, length, mtype );
         }
    }

   full_exit:
    ak_fiot_context_destroy( &fctx );

   exit:
    close(s);
  return 0;
}
