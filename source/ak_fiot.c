/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_fiot.с                                                                                 */
/*  - содержит реализацию функций инициализации и настройки контекста защищенного взаимодействия.  */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif
#ifdef LIBAKRYPT_HAVE_ERRNO_H
 #include <errno.h>
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSELECT_H
 #include <sys/select.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
 /* заголовок нужен длял реализации функции shutdown */
 #include <sys/socket.h>
#endif
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 #include <winsock2.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_fiot.h>
 #include <ak_parameters.h>

/* ----------------------------------------------------------------------------------------------- */
 #define named_restriction_count     (11)
 #define ak_fiot_class     ( base_class )

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Множество всех допустимых ограничений защищенного взаимодействия. */
 const static struct named_restriction {
  /*! \brief Ограничения на значения параметров. */
   crypto_restriction_t restriction;
  /*! \brief Константа,  связанная со множеством значений параметров. */
   key_mechanism_t keymech;
 } crypto_restrictions[ named_restriction_count ] =  {
    { { 16384, 8192, 65535, 255 }, baseKeyMechanismMagma },
    { { 16384, 65536, 65535, 255 }, baseKeyMechanismKuznechik },
    { { 1500, 2048, 65535, 255 }, shortKCMechanismMagma },
    { { 1500, 65536, 65535, 255 },  shortKCMechanismKuznechik },
    { { 16384, 256, 65535, 65535 }, longKCMechanismMagma },
    { { 16384, 4096, 65535, 255 }, longKCMechanismKuznechik },
    { { 1500, 32, 65535, 65535 },  shortKAMechanismMagma },
    { { 1500, 256, 65535, 65535 }, shortKAMechanismKuznechik },
    { { 16384, 4, 65535, 65535 }, longKAMechanismMagma },
    { { 16384, 64, 65535, 65535 }, longKAMechanismKuznechik },
    { { 0, 0, 0, 0 }, undefinedKeyMechanism },
};


/* ----------------------------------------------------------------------------------------------- */
/*           група функций, реализующих передачу/прием данных по каналам связи                     */
/* ----------------------------------------------------------------------------------------------- */
 volatile sig_atomic_t __io_canceled;

// static inline void io_init( void ) { __io_canceled = 0; }
// static inline void io_cancel( void ) { __io_canceled = 1; }

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция-обертка, отправляющая в канал связи произвольный массив данных заданной длины.
    \param fd Дескриптор файла (сокет) в который производится запись.
    \param buffer Указатель на область памяти, которая отправляется в канал связи
    \param length Размер области памяти в байтах.
    \return Функция возвращает количество отправленных в канал данных.                             */
/* ----------------------------------------------------------------------------------------------- */
 static ssize_t ak_fiot_context_write_ptr( ak_socket fd, char *buffer, ssize_t length )
{
    register ssize_t w, t = 0;

    while ( !__io_canceled && length > 0 ) {
      if(( w = send( fd, buffer, ( size_t )length, 0 )) < 0 ) {
         if( errno == EINTR || errno == EAGAIN ) continue;
         return ak_error_write_data;
      }
      if( !w ) return 0;
      length -= w; buffer += w; t += w;
    }
  return t;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция-обертка, получающая из канала связи произвольный массив данных заданной длины.
    \param fd Дескриптор файла (сокет) в который производится запись.
    \param buffer Указатель на область памяти, в которую помещаются полученные данные
    \param length Размер области памяти в байтах.
    \return Функция возвращает количество полученных данных.                                       */
/* ----------------------------------------------------------------------------------------------- */
 static ssize_t ak_fiot_context_read_ptr( ak_socket fd, char *buffer, ssize_t length )
{
    register ssize_t w, t = 0;

    while( !__io_canceled && length > 0 ) {
      if(( w = recv( fd, buffer, (size_t) length, 0 )) < 0 ) {
        if( errno == EINTR || errno == EAGAIN ) continue;
        return ak_error_set_value( ak_error_read_data );
      }
      if( !w ) return 0;
      length -= w; buffer += w; t += w;
    }
 return t;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция ожидает данные в течение заданного временного интревала.
    По истечении времени, если данные не получены, возвращается ошибка.

    \param fctx Контекст защищенного соединения.
    \param gate Интерфейс, на котором ожидаются данные.
    \param buffer Указатель на область памяти, в которую помещаются полученные данные
    \param length Размер области памяти в байтах.
    \return Функция возвращает количество полученных данных.                                       */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_fiot_context_read_ptr_timeout( ak_fiot fctx, gate_t gate,
                                                                 ak_pointer buffer, ssize_t length )
{
    int fd = -1;
#ifdef LIBAKRYPT_HAVE_SYSSELECT_H
    fd_set fdset;
    struct timeval tv;
#endif
    if( gate == encryption_gate ) fd = fctx->enc_gate;
      else fd = fctx->plain_gate;

#ifdef LIBAKRYPT_HAVE_SYSSELECT_H
    tv.tv_usec =0; tv.tv_sec = fctx->timeout;

    FD_ZERO( &fdset );
    FD_SET( fd, &fdset );
    if( select( fd+1, &fdset, NULL, NULL, &tv ) <= 0 )
      return ak_error_set_value( ak_error_read_data );
#endif

 return fctx->read( fd, buffer, length );
}

/* ----------------------------------------------------------------------------------------------- */
/*                    функции для работы с контектами протокола sp fiot                            */
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot. Под контекст должна быть
    заранее выделена память.

    \return Функция возвращает ноль в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 static int fiot_context_create_common( ak_fiot fctx )
{
   if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to fiot context" );
  /* максимальный размер буффера для хранения передаваемых/получаемых данных */
    fctx->inframe_size = fctx->oframe_size = fiot_frame_size;

  /* выделяем память под буффера, выравненную по границе 8 байт. */
   if(( fctx->oframe = ak_libakrypt_aligned_malloc( fctx->oframe_size )) == NULL ) {
     return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
   }
   memset( fctx->oframe, 0, fctx->oframe_size );

   if(( fctx->inframe = ak_libakrypt_aligned_malloc( fctx->inframe_size )) == NULL ) {
     free( fctx->oframe );
     return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
   }
   memset( fctx->inframe, 0, fctx->inframe_size );

  /* смещение зашифровываемых данных от начала фрейма (для базового заголовка). */
    fctx->header_offset = fiot_frame_header_offset;

  /* роль участника взаимодействия изначально не определена */
    fctx->role = undefined_role;

  /* текущее состояние контекста зависит от роли участника взаимодействия. */
    fctx->state = undefined_state;

  /* используемый набор криптографических механизмов согласуется в ходе выполнения проткола. */
    fctx->mechanism = not_set_mechanism;

  /* криптографические ограничения зависят от используемого алгоритма шифрования информации,
     и должны устанавливаться при выборе криптографических механизмов. */
   fctx->restriction = crypto_restrictions[named_restriction_count-1].restriction;

  /* значения счетчиков */
   fctx->lcounter = fctx->mcounter = fctx->ncounter = 0;

  /* устанавливаем таймаут ожидания входящих пакетов (в секундах) */
   fctx->timeout = 3;

  /* дескрипторы сокетов */
   fctx->enc_gate = fctx->plain_gate = undefined_gate;

  /* устанавливаем функции чтения и записи по-умолчанию */
   fctx->write = ak_fiot_context_read_ptr;
   fctx->write = ak_fiot_context_write_ptr;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot.

    \return Функция возвращает ноль в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 static int fiot_context_destroy_common( ak_fiot fctx )
{
   if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to fiot context" );
  /* закрываем связанные сокеты */
   if( fctx->enc_gate != -1 ) {
#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
     shutdown( fctx->enc_gate, SHUT_RDWR );
#else
  #ifdef LIBAKRYPT_HAVE_WINDOWS_H
     shutdown( fctx->enc_gate, SD_BOTH );
  #endif
#endif
     close( fctx->enc_gate );
     fctx->enc_gate = -1;
   }
   if( fctx->plain_gate != -1 ) {
#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
     shutdown( fctx->plain_gate, SHUT_RDWR );
#else
  #ifdef LIBAKRYPT_HAVE_WINDOWS_H
     shutdown( fctx->plain_gate, SD_BOTH );
  #endif
#endif

     close( fctx->plain_gate );
     fctx->plain_gate = -1;
   }

  if( fctx->inframe != NULL ) free( fctx->inframe );
  if( fctx->oframe != NULL ) free( fctx->oframe );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot.

    \return Функция возвращает ноль в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_create( ak_fiot fctx )
{
  int error = ak_error_ok;

 /*! \todo const may be deleted later */
  ak_uint8 const_key[32] = {
    0x12, 0x34, 0x56, 0x78, 0x0a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0xa1, 0xa1, 0xa2, 0xa2, 0xa3, 0xa3, 0xa4, 0xa4 };

  /* инициализируем заголовок струкуры */
   memset( fctx, 0, sizeof( struct fiot ));
   if(( error = fiot_context_create_common( fctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "common part of fiot context incorrect creation");

  /* инициализируем буфферы для хранения идентификаторов участников взаимодействия */
   if(( error = ak_buffer_create( &fctx->client_id )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of clientID buffer");
     ak_fiot_context_destroy( fctx );
     return error;
   }
   if(( error = ak_buffer_create( &fctx->server_id )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of clientID buffer");
     ak_fiot_context_destroy( fctx );
     return error;
   }

//   /* инициализируем буфферы для хранения идентификаторов ключей аутентификации */
//   if(( error = ak_buffer_create( &actx->epskID )) != fiot_error_ok ) {
//     fiot_error( error, __func__, "incorrect creation of clientID buffer");
//     fiot_delete(( fiot_t )actx );
//     return NULL;
//   }
//   if(( error = ak_buffer_create( &actx->ipskID )) != fiot_error_ok ) {
//     fiot_error( error, __func__, "incorrect creation of clientID buffer");
//     fiot_delete(( fiot_t )actx );
//     return NULL;
//   }

  /* инициализируем генераторы */
   if(( error = ak_random_context_create_lcg( &fctx->plain_rnd )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of plain random generator");
     ak_fiot_context_destroy( fctx );
     return error;
   }
#ifdef _WIN32
   if(( error = ak_random_context_create_winrtl( &fctx->crypto_rnd )) != ak_error_ok ) {
#else
   if(( error = ak_random_context_create_urandom( &fctx->crypto_rnd )) != ak_error_ok ) {
#endif
     ak_error_message( error, __func__, "incorrect creation of crypto random generator");
     ak_fiot_context_destroy( fctx );
     return error;
   }

  /* параметры эллиптической кривой по умолчанию (важны для забывчивого клиента) */
   if(( error = ak_fiot_context_set_curve( fctx,
                                tc26_gost3410_2012_256_paramsetA )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect elliptic curve parameters");
     ak_fiot_context_destroy( fctx );
     return error;
   }

//  /* инициализируем контекст хеширования сообщений */
//   if(( error = ak_hash_context_create_streebog512( &actx->comp )) != fiot_error_ok ) {
//     fiot_error( error, __func__, "incorrect elliptic curve parameters");
//     fiot_delete(( fiot_t )actx );
//     return NULL;
//   }

  /* следующие ключевые контексты инициализируются в ходе выполнения протокола:

     esfk, isfk, ecfk, icfk, epsk
     (поскольку конкретные виды алгоритмов пока еще не известны)

     остальные поля структуры инициализированы нулем в значения по-умолчанию  */

  /**/

  /*! \todo нижеследующий фрагмент это костыль, который должен быть удален
     после корректной реализации протокола выработки ключей */

   fctx->ecfk = malloc( sizeof( struct bckey ));
   ak_bckey_context_create_kuznechik( fctx->ecfk );
   ak_bckey_context_set_key( fctx->ecfk, const_key, 32, ak_true );

   fctx->esfk = malloc( sizeof( struct bckey ));
   ak_bckey_context_create_kuznechik( fctx->esfk );
   ak_bckey_context_set_key( fctx->esfk, const_key, 32, ak_true );

   fctx->icfk = malloc( sizeof( struct mac ));
   ak_mac_context_create_oid( fctx->icfk, ak_oid_context_find_by_name("omac-magma"));
   ak_mac_context_set_key( fctx->icfk, const_key, 32, ak_true );

   fctx->isfk = malloc( sizeof( struct mac ));
   ak_mac_context_create_oid( fctx->isfk, ak_oid_context_find_by_name("omac-magma"));
   ak_mac_context_set_key( fctx->isfk, const_key, 32, ak_true );

   fctx->epsk = NULL;
   fctx->restriction = crypto_restrictions[1].restriction;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot.

    \return Функция возвращает ноль в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_destroy( ak_fiot fctx )
{
  int error = ak_error_ok;

 /* уничтожение буфферов с идентификаторами */
  if(( error = ak_buffer_destroy( &fctx->client_id )) != ak_error_ok )
    ak_error_message( error, __func__, "incrorrect destroying of clientID buffer" );
  if(( error = ak_buffer_destroy( &fctx->server_id )) != ak_error_ok )
    ak_error_message( error, __func__, "incrorrect destroying of serverID buffer" );

//  if(( error = ak_buffer_destroy( &actx->epskID )) != fiot_error_ok )
//    fiot_error( error, __func__, "incrorrect destroying of epskID buffer" );
//  if(( error = ak_buffer_destroy( &actx->ipskID )) != fiot_error_ok )
//    fiot_error( error, __func__, "incrorrect destroying of ipskID buffer" );

 /* освобождаем генераторы */
  if(( error = ak_random_context_destroy( &fctx->plain_rnd )) != ak_error_ok )
    ak_error_message( error, __func__, "incrorrect destroying of plain random generator" );
  if(( error = ak_random_context_destroy( &fctx->crypto_rnd )) != ak_error_ok )
    ak_error_message( error, __func__, "incrorrect destroying of crypto random generator" );


 /* освобождаем ключевую информацию */
  fctx->ecfk = ak_bckey_context_delete( fctx->ecfk );
  fctx->esfk = ak_bckey_context_delete( fctx->esfk );

  fctx->icfk = ak_mac_context_delete( fctx->icfk );
  fctx->isfk = ak_mac_context_delete( fctx->isfk );


 /* освобождаем базовую часть */
  if(( error = fiot_context_destroy_common( fctx )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect common part destroying of fiot context" );

 /* обнуляем значения и освобождаем память */
  memset( fctx, 0, sizeof( struct fiot ));

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx указатель на контекст защищенного взаимодействия
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_fiot_context_delete( ak_pointer ctx )
{
  if( ctx != NULL ) {
      ak_fiot_context_destroy(( ak_fiot ) ctx );
      free( ctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to fiot context" );
 return NULL;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция возвращает значение, которым ограничена длина данных, передаваемых или
    принимаемых из канала связи. Эта величина определяет максимальный размер памяти,
    выделенной при содании контекста, для хранения данных.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param fb Тип буффера, для которого запрашивается размер.

    \return Функция возвращает ноль (!) в случае ошибки. При этом устанавливается код ошибки,
    который можно узнать с помощью вызова функции ak_error_get_value().
    В случае успеха возвращается текущее значение длины фрейма, связанного с данным контектстом.   */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_fiot_context_get_frame_size( ak_fiot fctx, frame_buffer_t fb )
{
  if( fctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to fiot context" );
    return 0;
  }
  switch( fb ) {
    case inframe: return fctx->inframe_size;
    case oframe: return fctx->oframe_size;
  }
  ak_error_message( fiot_error_frame_buffer_type, __func__ , "incorrect frame buffer type" );
  return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция предназначена для увеличения размера буффера после выполнения протокола
    выработки общих ключей, а также для возможности подстроиться под длины входящих фреймов.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param fb Тип буффера, для которого устанавливается размер.
    \param framesize Новая длина фрейма (в октетах). Новая длина должна принимать значения
    в интервале от \ref fiot_min_frame_size до \ref fiot_max_frame_size.

    \note Значение framesize задает максимально возможную длину.
    Это длина фрейма, инкапсуриуемого в канальный протокол, т.е это значение должно быть
    меньше, чем текущее значение MTU. Величина, на которую фрейм должен быть меньше,
    зависит от длины заголовка используемого канального протокола.

    \return Функция возвращает ноль в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_frame_size( ak_fiot fctx, frame_buffer_t fb, size_t framesize )
{
  char *ptr = NULL;
  size_t newsize = framesize;

   if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to fiot context" );
   if( newsize < fiot_min_frame_size ) newsize = fiot_min_frame_size;
   if( newsize > fiot_max_frame_size ) newsize = fiot_max_frame_size;

   switch( fb ) {
     case inframe:
        if( newsize == fctx->inframe_size ) return ak_error_ok;
        if( fctx->inframe == NULL ) ak_error_message( ak_error_null_pointer, __func__,
                                        "using null pointer to inframe buffer in fiot context" );
       /* выделяем новую память */
        if(( ptr = ak_libakrypt_aligned_malloc( newsize )) == NULL )
          return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
        memset( ptr, 0, newsize );
       /* копируем хранящиеся в буффере данные и удаляем старую память */
        memcpy( ptr, fctx->inframe, ak_min( fctx->inframe_size, newsize ));
        free( fctx->inframe );
        fctx->inframe = ptr;
        fctx->inframe_size = newsize;
        return ak_error_ok;

     case oframe:
        if( newsize == fctx->oframe_size ) return ak_error_ok;
        if( fctx->oframe == NULL ) ak_error_message( ak_error_null_pointer, __func__,
                                         "using null pointer to oframe buffer in fiot context" );
       /* выделяем новую память */
        if(( ptr = ak_libakrypt_aligned_malloc( newsize )) == NULL )
          return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
        memset( ptr, 0, newsize );
       /* копируем хранящиеся в буффере данные и удаляем старую память */
        memcpy( ptr, fctx->oframe, ak_min( fctx->oframe_size, newsize ));
        free( fctx->oframe );
        fctx->oframe = ptr;
        fctx->oframe_size = newsize;
        return ak_error_ok;
   }

 return ak_error_message( fiot_error_frame_buffer_type, __func__ , "incorrect frame buffer type" );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Одновременно с установкой роли участника защищенного взаимодействия
    инициализируется внутреннее стостояние контекста
     - для клиента устанавливается состояние \ref rts_client_hello
     - для сервера устанавливается состояние \ref wait_client_hello

    \param fctx Контекст защищенного соединения протокола sp fiot.
    \param role Константа, определяющая роль участника защищенного взаимодействия.

    \return В случае успеха, функция возвращает \ref ak_error_ok.
    В случае ошибки возвращается отрицательное целое число, содержащее код ошибки.                 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_role( ak_fiot fctx, role_t role )
{
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to fiot context" );
  if( role == undefined_role ) return ak_error_message( fiot_error_wrong_role, __func__,
                                                           "using wrong value of protocol role" );
  switch( role ) {
    case client_role: fctx->role = client_role;
                      fctx->state = rts_client_hello;
                      break;
    case server_role: fctx->role = server_role;
                      fctx->state = wait_client_hello;
                      break;
    default: return ak_error_message( fiot_error_wrong_role, __func__,
                                                       "assigning wrong value of protocol role" );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot.

    \return Функция возвращает значение роли контекста защищенного взаимодействия.
    В случае ошибки возвращается значение \ref undefinedRole.                                      */
/* ----------------------------------------------------------------------------------------------- */
 role_t ak_fiot_context_get_role( ak_fiot fctx )
{
  if( fctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to fiot context" );
    return undefined_role;
  }
 return fctx->role;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения протокола sp fiot.

    \return Функция возвращает значение текущее состояние контекста защищенного взаимодействия.
    В случае ошибки возвращается значение \ref undefined_state.                                     */
/* ----------------------------------------------------------------------------------------------- */
 context_state_t ak_fiot_context_get_state( ak_fiot fctx )
{
  if( fctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to fiot context" );
    return undefined_state;
  }
 return fctx->state;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \param role Роль того участника, кому присваивается идентификатор.
    \param in Указатель на данные, являющиеся идентификатором сервера.
    \param size Размер данных, в байтах.

    \return Функция возвращает ноль в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_user_identifier( ak_fiot fctx, role_t role, void *in, const size_t size )
{
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using a null pointer to fiot context" );
  if( size < 1 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                       "using an identifier with wrong length" );
  switch( role ) {
    case client_role: return ak_buffer_set_ptr( &fctx->client_id, in, size, ak_true );
    case server_role: return ak_buffer_set_ptr( &fctx->server_id, in, size, ak_true );
    default:
       return ak_error_message( fiot_error_wrong_role, __func__, "using incorrect role of user");
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \param role Роль того участника, для которого получается идентификатор.
    \param out Указатель на область памяти, в которую помещается результат.
    \param maxlen Максимальный размер доступной памяти (в октетах)

    \return  Возвращается количество записанных октетов. В случае возникновения ошибки возвращается
    отрицательное число - код ошибки                                                               */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_fiot_context_get_user_identifier( ak_fiot fctx, role_t role, void *out, const size_t maxlen )
{
  size_t len = 0;
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using a null pointer to fiot context" );
  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to output memory" );
  if( maxlen < 1 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                         "using incorrect value of memory size" );

  switch( role ) {
    case client_role:
       memcpy( out, fctx->client_id.data, len = ak_min( maxlen, fctx->client_id.size ));
       return (ssize_t) len;
    case server_role:
       memcpy( out, fctx->server_id.data, len = ak_min( maxlen, fctx->server_id.size ));
       return (ssize_t) len;
    default:
     return ak_error_message( fiot_error_wrong_role, __func__,
                                                       "using a wrong role of user indentifier" );
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \param id Идентификатор эллиптической кривой.

    \return Функция возвращает \ref ak_error_ok в случае успеха. В противном случае возвращается
    отрицательное целое число, содержащее код ошибки.                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_curve( ak_fiot fctx, elliptic_curve_t id )
{
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using a null pointer to fiot context" );
  switch( id ) {
    case tc26_gost3410_2012_256_paramsetA:
          fctx->curve = ( ak_wcurve )( &id_tc26_gost_3410_2012_256_paramSetA );
          break;
    case tc26_gost3410_2012_512_paramsetA:
          fctx->curve = ( ak_wcurve )( &id_tc26_gost_3410_2012_512_paramSetA );
          break;
    case tc26_gost3410_2012_512_paramsetB:
          fctx->curve = ( ak_wcurve )( &id_tc26_gost_3410_2012_512_paramSetB );
          break;
    case tc26_gost3410_2012_512_paramsetC:
          fctx->curve = ( ak_wcurve )( &id_tc26_gost_3410_2012_512_paramSetC );
          break;

    case rfc4357_gost3410_2001_paramsetA:
          fctx->curve = ( ak_wcurve )( &id_rfc4357_gost_3410_2001_paramSetA );
          break;
    case rfc4357_gost3410_2001_paramsetB:
          fctx->curve = ( ak_wcurve )( &id_rfc4357_gost_3410_2001_paramSetB );
          break;
    case rfc4357_gost3410_2001_paramsetC:
          fctx->curve = ( ak_wcurve )( &id_rfc4357_gost_3410_2001_paramSetC );
          break;
    default: return ak_error_message( fiot_error_unknown_paramset,
                                          __func__, "using unknown paramset for elliptic curve" );
  }
  fctx->curve_id = id;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \return Функция возвращает установленный идентификатор эллиптической кривой.                   */
/* ----------------------------------------------------------------------------------------------- */
 elliptic_curve_t ak_fiot_context_get_curve( ak_fiot fctx )
{
  if( fctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to fiot context" );
    return unknown_paramset;
   }
 return fctx->curve_id;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \param gate Заданный интерфейс контекста защищенного взаимодейтсвия.
    \param descriptor Значение дескриптора открытого сокета (пайпа, файла и .д.),
    связываемое с заданным интерфейсом контекста.

    \return В случае успеха функция возвращает \ref ak_error_ok.
    В случае возникновения ошибки возвращается ее код                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_set_gate_descriptor( ak_fiot fctx, gate_t gate, ak_socket descriptor )
{
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using a null pointer to fiot context" );
  switch( gate ) {
    case encryption_gate: fctx->enc_gate = descriptor; return ak_error_ok;
    case plain_gate: fctx->plain_gate = descriptor; return ak_error_ok;
  default:  return ak_error_message( fiot_error_wrong_gate, __func__,
                                                            "using a wrong value of gate type" );
  }
 return fiot_error_wrong_gate;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param fctx Контекст защищенного соединения.
    \param gate Заданный интерфейс контекста защищенного взаимодейтсвия.
    \return Функция возвращает значение установленного дескриптора.
    В случае возникновения ошибки возвращается ее код                                              */
/* ----------------------------------------------------------------------------------------------- */
 ak_socket ak_fiot_context_get_gate_descriptor( ak_fiot fctx , gate_t gate )
{
  if( fctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using a null pointer to fiot context" );
  switch( gate ) {
    case encryption_gate: return fctx->enc_gate;
    case plain_gate: return fctx->plain_gate;
  default:  return ak_error_message( fiot_error_wrong_gate, __func__,
                                                            "using a wrong value of gate type" );
  }
 return fiot_error_wrong_gate;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-internal-fiot-context.c                                                          */
/*! \example test-internal-fiot-unix.c                                                             */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_fiot.c  */
/* ----------------------------------------------------------------------------------------------- */
