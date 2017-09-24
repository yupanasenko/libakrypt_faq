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
 #include <ak_hmac.h>
 #include <ak_tools.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx контекст ключа алгоритма hmac.
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_key_create_streebog256( ak_hmac_key hctx )
{
 int error = ak_error_ok;

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_create_streebog256( &hctx->ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "invalid creation of hash function context");

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_create( &hctx->key, hctx->ctx.bsize, 8 )) != ak_error_ok ) {
     ak_hash_destroy( &hctx->ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* доопределяем поля секретного ключа */
   if(( hctx->key.oid = ak_handle_get_context(
                        ak_oid_find_by_name( "hmac-streebog256" ), oid_engine )) == NULL ) {
     error = ak_error_get_value();
     ak_hash_destroy( &hctx->ctx );
     ak_skey_destroy( &hctx->key );
     return ak_error_message( error, __func__, "internal OID search error");
   }

  /* устанавливаем ресурс ключа */
   hctx->key.resource.counter = ak_libakrypt_get_hmac_key_counter_resource();

  /* hctx->key.data не изменяется */
  /* также мы используем методы секретного ключа, установленные по-умолчанию */
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx контекст ключа алгоритма hmac.
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_key_create_streebog512( ak_hmac_key hctx )
{
 int error = ak_error_ok;

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_create_streebog512( &hctx->ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "invalid creation of hash function context");

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_create( &hctx->key, hctx->ctx.bsize, 8 )) != ak_error_ok ) {
     ak_hash_destroy( &hctx->ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* доопределяем поля секретного ключа */
   if(( hctx->key.oid = ak_handle_get_context(
                        ak_oid_find_by_name( "hmac-streebog512" ), oid_engine )) == NULL ) {
     error = ak_error_get_value();
     ak_hash_destroy( &hctx->ctx );
     ak_skey_destroy( &hctx->key );
     return ak_error_message( error, __func__, "internal OID search error");
   }

  /* устанавливаем ресурс ключа */
   hctx->key.resource.counter = ak_libakrypt_get_hmac_key_counter_resource();

  /* hctx->key.data не изменяется */
  /* также мы используем методы секретного ключа, установленные по-умолчанию */
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx контекст ключа алгоритма hmac.
    @param handle дескриптор таблиц замен алгоритма хеширования ГОСТ Р 34.11-94
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_key_create_gosthash94( ak_hmac_key hctx, ak_handle handle )
{
 int error = ak_error_ok;

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_create_gosthash94( &hctx->ctx, handle )) != ak_error_ok )
     return ak_error_message( error, __func__, "invalid creation of hash function context");

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_create( &hctx->key, hctx->ctx.bsize, 8 )) != ak_error_ok ) {
     ak_hash_destroy( &hctx->ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* доопределяем поля секретного ключа */
   if(( hctx->key.oid = ak_handle_get_context(
                        ak_oid_find_by_name( "hmac-gosthash94" ), oid_engine )) == NULL ) {
     error = ak_error_get_value();
     ak_hash_destroy( &hctx->ctx );
     ak_skey_destroy( &hctx->key );
     return ak_error_message( error, __func__, "internal OID search error");
   }

  /* устанавливаем ресурс ключа */
   hctx->key.resource.counter = ak_libakrypt_get_hmac_key_counter_resource();

  /* hctx->key.data не изменяется */
  /* также мы используем методы секретного ключа, установленные по-умолчанию */
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx контекст ключа алгоритма hmac
    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_key_destroy( ak_hmac_key hctx )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                 "destroying a null pointer to hmac key context" );
  if(( error = ak_skey_destroy( &hctx->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect destroying secret key of hmac" );
  if(( error = ak_hash_destroy( &hctx->ctx )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect destroying hash function context of hmac" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx контекст ключа алгоритма hmac
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_hmac_key_delete( ak_pointer hctx )
{
  if( hctx != NULL ) {
      ak_hmac_key_destroy(( ak_hmac_key ) hctx );
      free( hctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                       "using null pointer to hmac key context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст ключа алгоритма hmac.
    @param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    Данные всегда копируются во внутреннюю память контекста алгоритма.

    Поскольку длина ключа алгоритма hmac всегда совпадает с длиной блока обрабатываемых данных
    используемой функции хеширования, то
     - в случае, если длина ключевых данных меньше, чем длина блока обрабатываемых данных,
     то недостающие байты заполняются нулями (согласно Р 50.1.113-2016);
     - в случае, если длина ключевых данных больше, чем длина блока обрабатываемых данных,
    то есть \f$ K = K_1 || K_2 \f$, где \f$ |K_1| = \text{\texttt{ hctx->ctx.bsize }} \f$,
    то в качестве ключа используются значение \f$  K_1 \oplus Hash( K_1 || K_2 ) \f$,
    длина которого в точности совпадает с длиной блока хешируемых данных.

    @param size Размер данных, на которые указывает ptr (размер в байтах)
    @return В случае успеха функция возвращает указатель на созданный контекст. В противном случае
    возвращается NULL. Код возникшей ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_key_assign_ptr( ak_hmac_key hctx, const ak_pointer ptr, const size_t size )
{
  int error = ak_error_ok;

  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
  if( ptr == NULL ) return  ak_error_message( ak_error_null_pointer, __func__,
                                                    "using a null pointer to constant key value" );
 /* присваиваем ключевой буффер */
  if(( error =
      ak_skey_assign_ptr( &hctx->key, ptr, ak_min( size, hctx->ctx.bsize ), ak_true )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning of key data" );

  if( size > hctx->ctx.bsize ) {
    size_t i = 0;
    ak_buffer buffer = ak_hash_ptr_context( &hctx->ctx, ptr, size, NULL );
    if( buffer == NULL ) return ak_error_message( ak_error_get_value(), __func__ ,
                                                                      "wrong hashing a long key" );
      else {
        for( i = 0; i < hctx->ctx.hsize; i++ )
           ((char *)hctx->key.key.data)[i] ^= ((char *)buffer->data)[i];
        error = ak_buffer_wipe( buffer, &hctx->key.generator );
        buffer = ak_buffer_delete( buffer );
      }
  }

 /* инициализируем начальное состояние */
  if(( error = ak_hmac_key_clean( hctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid cleaning a hmac key context ");

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx контекст ключа алгоритма hmac
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_key_clean( ak_hmac_key hctx )
{
  int error = ak_error_ok;
  size_t idx = 0, count = 0;

  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );

 /* инициализируем начальное состояние контекста хеширования */
  if(( error = hctx->ctx.clean( &hctx->ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of hash function context" );

 /* цикл по количеству 8-ми байтных блоков в ключе */
  count = hctx->key.key.size >> 3;
  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= 0x3636363636363636LL;
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= ((ak_uint64 *)hctx->key.mask.data)[idx];
  }
  if(( error =
         hctx->ctx.update( &hctx->ctx, hctx->key.key.data, hctx->key.key.size )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid 1st step iteration for hmac key context" );

  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= ((ak_uint64 *)hctx->key.mask.data)[idx];
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= 0x3636363636363636LL;
  }
  hctx->key.remask( &hctx->key );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx контекст ключа алгоритма hmac
    @param data указатель на обрабатываемые данные
    @param size длина обрабатываемых данных (в байтах); длина должна быть кратна длине блока
    обрабатываемых данных используемой функции хеширования
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_key_update( ak_hmac_key hctx, const ak_pointer data, const size_t size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                      "using zero length for authenticated data" );
  if( size%hctx->ctx.bsize ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                  "using data with wrong length" );
  return hctx->ctx.update( &hctx->ctx, data, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx контекст ключа алгоритма hmac
    @param data блок входных данных; длина блока должна быть менее, чем блина блока
           обрабатываемых данных для используемой функции хеширования
    @param size длина блока обрабатываемых данных
    @param out указатель на область памяти, куда будет помещен результат; если out равен NULL,
           то создается новый буффер, в который помещается результат.
    @return если out равен NULL, то возвращается указатель на созданный буффер. В противном случае
           возвращается NULL. В случае возникновения ошибки возывращается NULL. Код ошибки может
           быть получен c помощью вызова функции ak_error_get_value().                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hmac_key_finalize( ak_hmac_key hctx, const ak_pointer data,
                                                               const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  ak_buffer result = NULL;
  size_t idx = 0, count = 0;
  const unsigned int temporary_size = 128;
  ak_uint8 temporary[temporary_size]; /* буфер для хранения промежуточных результатов */

 /* выполняем проверки */
  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to hmac context" );
    return NULL;
  }
  if( hctx->ctx.hsize > 64 ) { /* ограничение в связи с константным размером временного буффера */
    ak_error_message( ak_error_wrong_length, __func__, "using a hash context with large code size" );
    return NULL;
  }
  if( size >= hctx->ctx.bsize ) {
    ak_error_message( ak_error_zero_length, __func__ , "using wrong length for authenticated data" );
    return NULL;
  }

 /* обрабатываем хвост предыдущих данных */
  memset( temporary, 0, temporary_size );
  hctx->ctx.finalize( &hctx->ctx, data, size, temporary );
  if(( error = ak_error_get_value( )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong updating of finalized data" );
    return NULL;
  }

 /* возвращаем контекст хеширования в начальное состояние */
  if(( error = hctx->ctx.clean( &hctx->ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong cleaning of hash function context" );
    return NULL;
  }

 /* цикл по количеству 8-ми байтных блоков в ключе */
  count = hctx->key.key.size >> 3;
  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= 0x5C5C5C5C5C5C5C5CLL;
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= ((ak_uint64 *)hctx->key.mask.data)[idx];
  }
  if(( error =
         hctx->ctx.update( &hctx->ctx, hctx->key.key.data, hctx->key.key.size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "invalid 2nd step iteration for hmac key context" );
    return NULL;
  }

  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= ((ak_uint64 *)hctx->key.mask.data)[idx];
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= 0x5C5C5C5C5C5C5C5CLL;
  }
  hctx->key.remask( &hctx->key );

 /* последний update/finalize и возврат результата */
  if( hctx->ctx.bsize == hctx->ctx.hsize ) {
    hctx->ctx.update( &hctx->ctx, temporary, hctx->ctx.hsize );
    result = hctx->ctx.finalize( &hctx->ctx, NULL, 0, out );
  } else result = hctx->ctx.finalize( &hctx->ctx, temporary, hctx->ctx.hsize, out );

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет имитовставку по алгоритму HMAC от заданной области памяти на которую
    указывает in. Размер памяти задается в байтах в переменной size. Результат вычислений помещается
    в область памяти, на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param hctx Контекст ключа алгоритма вычисления имитовставки HMAC, должен быть отличен от NULL.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен рещультат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_hmac_key_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений.                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hmac_key_ptr_context( ak_hmac_key hctx, const ak_pointer in,
                                                                 const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  ak_buffer result = NULL;
  size_t quot = 0, offset = 0;

  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to hmac key context" );
    return NULL;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to input data" );
    return NULL;
  }

 /* вычищаем результаты предыдущих вычислений */
  if(( error = ak_hmac_key_clean( hctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of hmac key context" );
    return NULL;
  }

 /* вычисляем фрагмент, длина которого кратна длине блока входных данных для хеш-функции */
  quot = size/hctx->ctx.bsize;
  offset = quot*hctx->ctx.bsize;
  /* вызываем, если длина сообщения не менее одного полного блока */
  if( quot > 0 )
    if(( error = ak_hmac_key_update( hctx, in, offset )) != ak_error_ok ) {
      ak_error_message( error, __func__ , "wrong caclucation of hmac function" );
      return NULL;
    }

  /* обрабатываем хвост */
  result = ak_hmac_key_finalize( hctx, (unsigned char *)in + offset, size - offset, out );
  /* очищаем за собой данные, содержащиеся в контексте функции хеширования */
  hctx->ctx.clean( &hctx->ctx );
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
  ak_uint8 out[64];
  struct hmac_key hkey;
  int error = ak_error_ok;
  ak_bool result = ak_true;
  int audit = ak_log_get_level();

 /* 1. тестируем HMAC на основе Стрибог 256 */
  if(( error = ak_hmac_key_create_streebog256( &hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of hmac-streebog256 key context" );
    return ak_false;
  }
  if(( error = ak_hmac_key_assign_ptr( &hkey, key, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_hmac_key_ptr_context( &hkey, data, 16, out );
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of hmac code" );
    result = ak_false;
    goto lab_exit;
  }
  if( !ak_ptr_is_equal( out, R256, 32 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                     "wrong test for hmac-streebog256 from R 50.1.113-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 32, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R256, 32, ak_false )); free( str );
    result = ak_false;
    goto lab_exit;
  }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                     "test for hmac-streebog256 from R 50.1.113-2016 is Ok" );
  ak_hmac_key_destroy( &hkey );

 /* 2. тестируем HMAC на основе Стрибог 512 */
  if(( error = ak_hmac_key_create_streebog512( &hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of hmac-streebog512 key context" );
    return ak_false;
  }
  if(( error = ak_hmac_key_assign_ptr( &hkey, key, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_hmac_key_ptr_context( &hkey, data, 16, out );
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of hmac code" );
    result = ak_false;
    goto lab_exit;
  }
  if( !ak_ptr_is_equal( out, R512, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                     "wrong test for hmac-streebog512 from R 50.1.113-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 64, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R512, 64, ak_false )); free( str );
    result = ak_false;
    goto lab_exit;
  }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                     "test for hmac-streebog512 from R 50.1.113-2016 is Ok" );
 lab_exit:
  ak_hmac_key_destroy( &hkey );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hmac.c  */
/* ----------------------------------------------------------------------------------------------- */
