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
/*   ak_bckey.c                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_skey.h>

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
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= 0x3636363636363636LL;
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= ((ak_uint64 *)hkey->key.mask.data)[idx];
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
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "using zero length for authenticated data" );
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
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= 0x5C5C5C5C5C5C5C5CLL;
     ((ak_uint64 *)hkey->key.key.data)[idx] ^= ((ak_uint64 *)hkey->key.mask.data)[idx];
  }
  hkey->key.remask( &hkey->key );

  temp = ak_hash_finalize( ctx2, result->data, result->size, out );
  ctx2 = ak_hash_delete( ctx2 );

  result = ak_buffer_delete( result );
 return temp;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hmac.c  */
/* ----------------------------------------------------------------------------------------------- */
