/* Пример, иллюстрирующий защищенный обмен между потомком и родителем,
   использующий сокеты домена unix.

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
 /* инициализируем криптобиблиотеку в процессе сервера */
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
  char str[100];
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


        int error = ak_error_ok;
        ssize_t done, n;
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
            n = recv( s2, str, sizeof( str ), 0 );
            if (n <= 0) {
                if (n < 0) perror("recv");
                done = 1;
            }
            if( strncmp( str, "quit", 4 ) == 0 ) done = 1;
            if (!done)
                if( send( s2, str, (size_t)n, 0 ) < 0) {
                    perror("send");
                    done = 1;
                }
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
    ssize_t t;
    socklen_t len;
    int s, error = ak_error_ok;
    struct fiot fctx;
    struct sockaddr_un remote;
    char str[100];

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


    while(printf("> "), fgets(str, 100, stdin ), !feof(stdin)) {
        if (send(s, str, strlen(str), 0) == -1) {
            perror("send");
            exit(1);
        }

        // fctx.header_offset = 11; /* восемь байт для стандартного заголовка + 3 байта - мусор */
        ak_fiot_context_send_frame( &fctx, NULL, str, strlen( str ),
                                                                encrypted_frame, application_data );

        if(( t=recv( s, str, 100, 0 )) > 0 ) {
            str[t] = '\0';
            printf("echo> %s\n", str);
        } else {
            if (t < 0) perror("recv");
            else printf("client: server closed connection\n");
            exit(1);
        }
    }

   full_exit:
    ak_fiot_context_destroy( &fctx );

   exit:
    close(s);
  return 0;
}
