/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_hmac.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_skey.h>

 #include <errno.h>
 #include <fcntl.h>
 #ifndef _WIN32
  #include <unistd.h>
 #endif
 #include <sys/stat.h>

/* ----------------------------------------------------------------------------------------------- */
/*! @param hkey Инициализируемый контекст алгоритма выработки имитовставки
    @param ctx Контекст алгоритма хеширования, используемого для выработки значения функции
    \b Внимание. Инициализируемый контекст становится владельцем контекста функции хеширования ctx
    и удаляет его самостоятельно.

    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_key_create( ak_hmac_key hkey, ak_hash ctx )
{
  ak_oid oid = NULL;
  int error = ak_error_ok;

  if( hkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to hmac context" );
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                   "using null pointer to hash function context" );

 /* проверяем допустимость хэш-функции и, заодно, получаем OID алгоритма выработки имитовставки */
  if( memcmp( ak_oid_get_name( ctx->oid ), "streebog256", 11 ) == 0 )
    oid = ak_oids_find_by_name( "hmac-streebog256" );
  if( memcmp( ak_oid_get_name( ctx->oid ), "streebog512", 11 ) == 0 )
    oid = ak_oids_find_by_name( "hmac-streebog512" );
  if( memcmp( ak_oid_get_name( ctx->oid ), "gosthash94", 10 ) == 0 )
    oid = ak_oids_find_by_name( "hmac-gosthash94" );
  if( oid == NULL ) return ak_error_message( ak_error_undefined_function, __func__ ,
                                                               "using unsupported hash function" );

 /* согласно Р 50.1.113-2016 мы всегда создаем ключ K* имеющий длину 512 бит (64 байта) */
  if(( error = ak_skey_create( &hkey->key, ctx->bsize )) != ak_error_ok )
                        return ak_error_message( error, __func__, "wrong creation of secret key" );

 /* присваиваем указатель на контекст хеширования */
  hkey->ctx = ctx;
 /* присваиваем найденный ранее OID */
  hkey->key.oid = oid;

 /* определеяем указатели на методы */
  hkey->key.set_mask = ak_skey_set_mask_xor;
  hkey->key.remask = ak_skey_remask_xor;
  hkey->key.set_icode = ak_skey_set_icode_xor;
  hkey->key.check_icode = ak_skey_check_icode_xor;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Контекст алгоритма хеширования, используемого для выработки значения функции.
    \b Внимание. Создаваемый контекст становится владельцем контекста функции хеширования ctx
    и удаляет его самостоятельно.

    @return В случае успеха функция возвращает указатель на созданный контекст. В противном случае
    возвращается NULL. Код возникшей ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_hmac_key ak_hmac_key_new( ak_hash ctx )
{
  int error = ak_error_ok;
  ak_hmac_key hkey = NULL;

  if(( hkey = ( ak_hmac_key ) malloc( sizeof( struct hmac_key ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "incorrect memory allocation" );
    return NULL;
  }
  if(( error = ak_hmac_key_create( hkey, ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of hmac key context" );
    return( hkey = ak_hmac_key_delete( hkey ));
  }
 return hkey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hkey Контекст очищаемого ключа алгоритма выработки имитовставки HMAC
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_key_destroy( ak_hmac_key hkey )
{
  int error = ak_error_ok;
  if( hkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
  if(( error = ak_skey_destroy( &hkey->key )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wronf deleting a secret key" );
  }
  if( hkey->ctx != NULL ) hkey->ctx = ak_hash_delete( hkey->ctx );
    else ak_error_message( ak_error_null_pointer, __func__,
                                                          "using a null pointer to hash context" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hkey Контекст удаляемого ключа алгоритма выработки имитовставки HMAC
    @return Функция всегда возвращает NULL. В случае возникновения ошибки, ее код может быть получен
    с помощью вызова функции ak_error_get_value().                                                 */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_hmac_key_delete( ak_pointer hkey )
{
  if( hkey != NULL ) {
    ak_hmac_key_destroy( hkey );
    free( hkey );
  } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to hmac key context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Контекст алгоритма хеширования, используемого для выработки значения функции.
    \b Внимание. Создаваемый контекст становится владельцем контекста функции хеширования ctx
    и удаляет его самостоятельно.
    @param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    Данные всегда копируются во внутреннюю память контекста алгоритма.
    @param size Размер данных, на которые указывает ptr (размер в байтах)
    @return В случае успеха функция возвращает указатель на созданный контекст. В противном случае
    возвращается NULL. Код возникшей ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_hmac_key ak_hmac_key_new_ptr( ak_hash ctx, const ak_pointer ptr, const size_t size )
{
  int error = ak_error_ok;
  ak_hmac_key hkey = NULL;

  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to secret key" );
    return NULL;
  }
  if( size > ctx->bsize ) {
    ak_error_message( ak_error_wrong_length, __func__, "the secret key length is wrong" );
    return NULL;
  }
 /* создаем контекст */
  if(( hkey = ak_hmac_key_new( ctx )) == NULL ) {
    ak_error_message( error = ak_error_get_value(), __func__,
                                                        "wrong creation of hmac key context" );
    return NULL;
  }
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_assign_ptr( &hkey->key, ptr, size, ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect assigning of key data" );
    return ( hkey = ak_hmac_key_delete( hkey ));
  }
 /* инициализируем начальное состояние */
  if(( error = ak_hmac_key_clean( hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "invalid cleanin a hmac key context ");
    return ( hkey = ak_hmac_key_delete( hkey ));
  }
 return hkey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hkey Контекст очищаемого ключа алгоритма выработки имитовставки HMAC
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_key_clean( ak_hmac_key hkey )
{
  int error = ak_error_ok;
  size_t idx = 0, count = 0;

  if( hkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using a null pointer to hmac context" );
 /* инициализируем начальное состояние контекста хеширования */
  if(( error = ak_hash_clean( hkey->ctx )) != ak_error_ok ) {
    return ak_error_message( error, __func__, "wrong cleaning of hash function context" );
  }

  count = hkey->key.key.size >> 3;
  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= 0x3636363636363636LL;
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= ((ak_uint64 *)hkey->key.mask.data)[idx];
  }
  error = ak_hash_update( hkey->ctx, hkey->key.key.data, hkey->ctx->bsize );
  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= ((ak_uint64 *)hkey->key.mask.data)[idx];
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= 0x3636363636363636LL;
  }
  hkey->key.remask( &hkey->key );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_key_update( ak_hmac_key hkey, const ak_pointer data, const size_t size )
{
  if( hkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using a null pointer to hmac context" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                      "using zero length for authenticated data" );
  if( size%hkey->ctx->bsize ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                  "using data with wrong length" );
  return ak_hash_update( hkey->ctx, data, size );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hmac_key_finalize( ak_hmac_key hkey, const ak_pointer data,
                                                               const size_t size, ak_pointer out )
{
  ak_hash ctx2 = NULL;
  ak_buffer temp = NULL, result = NULL;
  size_t idx = 0, count = 0;

  if( hkey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to hmac context" );
    return NULL;
  }
  if( size >= hkey->ctx->bsize ) {
    ak_error_message( ak_error_zero_length, __func__ , "using wrong length for authenticated data" );
    return NULL;
  }

 /* обрабатываем хвост предыдущих данных */
  result = ak_hash_finalize( hkey->ctx, data, size, NULL );

  ctx2 = ak_hash_new_oid( hkey->ctx->oid );
  ak_hash_clean( ctx2 ); // от еще ддыра )))

  count = hkey->key.key.size >> 3;
  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= 0x5C5C5C5C5C5C5C5CLL;
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= ((ak_uint64 *)hkey->key.mask.data)[idx];
  }
  ak_hash_update( ctx2, hkey->key.key.data, hkey->key.key.size );
  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= ((ak_uint64 *)hkey->key.mask.data)[idx];
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= 0x5C5C5C5C5C5C5C5CLL;
  }
  hkey->key.remask( &hkey->key );

  if( ctx2->bsize == result->size ) {
    ak_hash_update( ctx2, result->data, result->size );
    temp = ak_hash_finalize( ctx2, NULL, 0, out );
  } else temp = ak_hash_finalize( ctx2, result->data, result->size, out );
  ctx2 = ak_hash_delete( ctx2 );

  result = ak_buffer_delete( result );
 return temp;
}

/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hmac_key_get_code_size( ak_hmac_key hkey )
{
  if( hkey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to hmac key context" );
    return 0;
  }
 return hkey->ctx->hsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет имитовставку по алгоритму HMAC от заданной области памяти на которую
    указывает in. Размер памяти задается в байтах в переменной size. Результат вычислений помещается
    в область памяти, на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param hkey Контекст ключа алгоритма вычисления имитовставки HMAC, должен быть отличен от NULL.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен рещультат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_hmac_key_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений.                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hmac_key_data( ak_hmac_key hkey, const ak_pointer in,
                                                                 const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  ak_buffer result = NULL;
  size_t quot = 0, offset = 0;

  if( hkey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to hmac key context" );
    return NULL;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to input data" );
    return NULL;
  }

 /* вычищаем результаты предыдущих вычислений */
  if(( error = ak_hmac_key_clean( hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of hmac key context" );
    return NULL;
  }
 /* вычисляем фрагмент,длина которого кратна длине блока входных данных для хеш-функции */
  quot = size/hkey->ctx->bsize;
  offset = quot*hkey->ctx->bsize;
  /* вызываем, если длина сообщения не менее одного полного блока */
  if( quot > 0 )
    if(( error = ak_hmac_key_update( hkey, in, offset )) != ak_error_ok ) {
      ak_error_message( error, __func__ , "wrong caclucation of hmac function" );
      return NULL;
    }
  /* обрабатываем хвост */
  result = ak_hmac_key_finalize( hkey, (unsigned char *)in + offset, size - offset, out );
  /* очищаем за собой данные, содержащиеся в контексте функции хеширования */
  hkey->ctx->clean( hkey->ctx );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  Функция вычисляет имитовставку по алгоритму HMAC от файла, имя которого задается переменной
     filename. Результат вычислений помещается в область памяти,
     на которую указывает out. Если out равен NULL, то функция создает новый буффер
     (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
     буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

     @param hkey Контекст ключа алгоритма вычисления имитовставки HMAC, должен быть отличен от NULL.
     @param filename Указатель на строку, в которой содержится имя файла.
     @param out Область памяти, куда будет помещен рещультат. Память должна быть заранее выделена.
     Размер выделяемой памяти может быть определен с помощью вызова ak_hash_get_code_size().
     Указатель out может принимать значение NULL.

     @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
     возвращается указатель на буффер, содержащий результат вычислений.                            */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hmac_key_file( ak_hmac_key hkey, const char* filename, ak_pointer out )
{
  int fd = 0;
  struct stat st;
  ak_uint64 len = 0;
  ak_uint8 *localbuffer; /* место для локального считывания информации */
  ak_uint32 block_size = 4096; /* оптимальная длина блока для Windows пока не ясна */
  ak_buffer result = NULL;

 /* выполняем необходимые проверки */
  if( hkey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to hmac key context" );
    return NULL;
  }
  if( filename == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a file name" );
    return NULL;
  }
  if(( fd = open( filename, O_RDONLY | O_BINARY )) < 0 ) {
    ak_error_message( ak_error_open_file, strerror( errno ), __func__ );
    return NULL;
  }
  if( fstat( fd, &st ) ) {
    close( fd );
    ak_error_message( ak_error_access_file, strerror( errno ), __func__ );
    return NULL;
  }

 /* для файла нулевой длины результатом будет хеш от нулевого вектора */
  if( !st.st_size ) return ak_hmac_key_data( hkey, "", 0, out );
 /* готовим область для хранения данных */
  #ifdef _WIN32
    block_size = ak_max( 4096, hkey->ctx->bsize );
  #else
    block_size = ak_max( st.st_blksize, hkey->ctx->bsize );
  #endif
 /* здесь мы выделяем локальный буффер для считывания/обработки данных */
  if((localbuffer = ( ak_uint8 * ) malloc( block_size )) == NULL ) {
    close( fd );
    ak_error_message( ak_error_out_of_memory, __func__ , "out of memory" );
    return NULL;
  }
 /* теперь обрабатываем файл с данными */
  ak_hmac_key_clean( hkey );
  read_label: len = read( fd, localbuffer, block_size );
  if( len == block_size ) {
    ak_hmac_key_update( hkey, localbuffer, block_size ); /* добавляем считанные данные */
    goto read_label;
  } else {
          ak_uint64 qcnt = len / hkey->ctx->bsize,
                    tail = len - qcnt*hkey->ctx->bsize;
                    if( qcnt ) ak_hmac_key_update( hkey, localbuffer, qcnt*hkey->ctx->bsize );
                    result = ak_hmac_key_finalize( hkey, localbuffer + qcnt*hkey->ctx->bsize, tail, out );
         }

 /* очищаем за собой данные, содержащиеся в контексте */
  hkey->ctx->clean( hkey->ctx );
 /* закрываем данные */
  close(fd);
  free( localbuffer );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_hmac_key_test_streebog( void )
{
  ak_uint8 key[32] = {
   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };

  ak_uint8 data[16] = {
   0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00
  };

  ak_uint8 R256[32] = {
   0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
   0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9
  };

  ak_uint8 R512[64] = {
   0xa5, 0x9b, 0xab, 0x22, 0xec, 0xae, 0x19, 0xc6, 0x5f, 0xbd, 0xe6, 0xe5, 0xf4, 0xe9, 0xf5, 0xd8,
   0x54, 0x9d, 0x31, 0xf0, 0x37, 0xf9, 0xdf, 0x9b, 0x90, 0x55, 0x00, 0xe1, 0x71, 0x92, 0x3a, 0x77,
   0x3d, 0x5f, 0x15, 0x30, 0xf2, 0xed, 0x7e, 0x96, 0x4c, 0xb2, 0xee, 0xdc, 0x29, 0xe9, 0xad, 0x2f,
   0x3a, 0xfe, 0x93, 0xb2, 0x81, 0x4f, 0x79, 0xf5, 0x00, 0x0f, 0xfc, 0x03, 0x66, 0xc2, 0x51, 0xe6
  };

  char *str = NULL;
  ak_buffer buff = NULL;
  ak_hmac_key hkey = NULL;
  ak_bool result = ak_true;
  int audit = ak_log_get_level();

 /* HMAC на основе Стрибог 256 */
  if(( hkey = ak_hmac_key_new_ptr( ak_hash_new_streebog256(), key, 32 )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong creation of hmac key context" );
    return ak_false;
  }
  if(( buff = ak_hmac_key_data( hkey, data, 16, NULL )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong evaluation of hmac function" );
    result = ak_false;
    goto lab_exit;
  }
  if( memcmp( buff->data, R256, buff->size ) != 0 ) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                     "wrong test for HMAC-Streebog256 from R 50.1.113-2016" );
    ak_log_set_message( str = ak_buffer_to_hexstr( buff )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R256, 32, ak_false )); free( str );
    result = ak_false;
    goto lab_exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                     "test for HMAC-Streebog256 from R 50.1.113-2016 is Ok" );
  buff = ak_buffer_delete( buff );
  hkey = ak_hmac_key_delete( hkey );

  /* HMAC на основе Стрибог 512 */
   if(( hkey = ak_hmac_key_new_ptr( ak_hash_new_streebog512(), key, 32 )) == NULL ) {
     ak_error_message( ak_error_get_value(), __func__ , "wrong creation of hmac key context" );
     return ak_false;
   }
   if(( buff = ak_hmac_key_data( hkey, data, 16, NULL )) == NULL ) {
     ak_error_message( ak_error_get_value(), __func__ , "wrong evaluation of hmac function" );
     result = ak_false;
     goto lab_exit;
   }
   if( memcmp( buff->data, R512, buff->size ) != 0 ) {
     ak_error_message( ak_error_not_equal_data, __func__ ,
                                      "wrong test for HMAC-Streebog512 from R 50.1.113-2016" );
     ak_log_set_message( str = ak_buffer_to_hexstr( buff )); free( str );
     ak_log_set_message( str = ak_ptr_to_hexstr( R512, 64, ak_false )); free( str );
     result = ak_false;
     goto lab_exit;
   }
   if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                      "test for HMAC-Streebog512 from R 50.1.113-2016 is Ok" );
 lab_exit:
  buff = ak_buffer_delete( buff );
  hkey = ak_hmac_key_delete( hkey );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-hmac-key.c
    \example example-hmac-key-file.c                                                               */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hmac.c  */
/* ----------------------------------------------------------------------------------------------- */
