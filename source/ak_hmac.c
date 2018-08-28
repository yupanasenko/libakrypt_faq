/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hmac.с                                                                                 */
/*  - содержит реализацию семейства ключевых алгоритмов хеширования HMAC.                          */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hmac.h>
 #include <ak_tools.h>

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @param oid Идентификатор алгоритма HMAC - ключевой функции хеширования.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_create_oid( ak_hmac hctx, ak_oid oid )
{
  ak_oid hashoid = NULL;
  int error = ak_error_ok;

 /* выполняем проверку */
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to hash function OID" );
 /* проверяем, что OID от бесключевой функции хеширования */
  if( oid->engine != hmac_function )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );

 /* получаем oid бесключевой функции хеширования */
  if(( hashoid = ak_oid_context_find_by_name( oid->name+5 )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__ ,
                                                   "incorrect searching of hash fuction oid" );
 /* проверяем, что производящая функция определена */
  if( hashoid->func.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                        "using hash function oid with undefined constructor" );
 /* инициализируем контекст функции хеширования */
  if(( error =
           (( ak_function_hash_create *)hashoid->func.create )( &hctx->ctx )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__,
                                   "invalid creation of %s hash function context", oid->name );

 /* инициализируем контекст секретного ключа */
  if(( error = ak_skey_context_create( &hctx->key, hctx->ctx.bsize, 8 )) != ak_error_ok ) {
    ak_hash_context_destroy( &hctx->ctx );
    return ak_error_message( error, __func__, "wrong creation of secret key" );
  }

 /* доопределяем oid ключа */
  hctx->key.oid = oid;

 /* устанавливаем ресурс ключа */
  hctx->key.resource.counter = ak_libakrypt_get_option( "hmac_key_count_resource" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_create_streebog256( ak_hmac hctx )
{ return ak_hmac_context_create_oid( hctx, ak_oid_context_find_by_name( "hmac-streebog256" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_create_streebog512( ak_hmac hctx )
{ return ak_hmac_context_create_oid( hctx, ak_oid_context_find_by_name( "hmac-streebog512" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_create_gosthash94( ak_hmac hctx )
{ return ak_hmac_context_create_oid( hctx, ak_oid_context_find_by_name( "hmac-gosthash94" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_destroy( ak_hmac hctx )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
  if(( error = ak_hash_context_destroy( &hctx->ctx )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of hash context" );
  if((  error = ak_skey_context_destroy( &hctx->key )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of secret key context" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_hmac_context_delete( ak_pointer hctx )
{
  if( hctx != NULL ) {
      ak_hmac_context_destroy(( ak_hmac ) hctx );
      free( hctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to hmac context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    К моменту вызова функции контекст должен быть инициализирован.
    @param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    @param size Размер данных, на которые указывает `ptr` (размер в байтах).
    Если величина `size` меньше, чем размер выделенной памяти под секретный ключ, то копируется
    только `size` байт (остальные заполняются нулями). Если `size` больше, чем количество выделенной памяти
    под ключ, то копируются только младшие байты, в количестве `key.size` байт.

    @param cflag Флаг передачи владения укзателем `ptr`. Если `cflag` ложен (принимает значение `ak_false`),
    то физического копирования данных не происходит: внутренний буфер лишь указывает на размещенные
    в другом месте данные, но не владеет ими. Если `cflag` истиннен (принимает значение `ak_true`),
    то происходит выделение памяти и копирование данных в эту память (размножение данных).

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_set_key( ak_hmac hctx, const ak_pointer ptr,
                                                            const size_t size, const ak_bool cflag )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
  if(( error = ak_skey_context_set_key( &hctx->key, ptr, size, cflag )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_clean( ak_pointer ctx )
{
  int error = ak_error_ok;
  size_t idx = 0, len = 0;
  ak_hmac hctx = ( ak_hmac ) ctx;
  ak_uint8 buffer[128]; /* буффер для хранения промежуточных значений */

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
 /* проверяем наличие ключа и его ресурс */
  if( !((hctx->key.flags)&skey_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );

  if( hctx->key.resource.counter <= 1 ) return ak_error_message( ak_error_resource_counter,
                                            __func__, "using hmac key context with low resource" );
                      /* нам надо два раза использовать ключ => ресурс должен быть не менее двух */
  if( hctx->ctx.bsize > sizeof( buffer )) return ak_error_message( ak_error_wrong_length,
                                            __func__, "using hash function with huge block size" );

 /* инициализируем начальное состояние контекста хеширования */
  if(( error = hctx->ctx.clean( &hctx->ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of hash function context" );

 /* формируем значение первоначального буффера */
  len = ak_min( hctx->ctx.bsize, hctx->key.key.size );
  memset( buffer, 0, hctx->ctx.bsize );
  for( idx = 0; idx < len; idx++ ) {
     buffer[idx] = ((ak_uint8 *)hctx->key.key.data)[idx] ^ 0x36;
     buffer[idx] ^= ((ak_uint8 *)hctx->key.mask.data)[idx];
  }
  for( ; idx < hctx->ctx.bsize; idx++ ) buffer[idx] = 0x36;
  if(( error =
         hctx->ctx.update( &hctx->ctx, buffer, hctx->ctx.bsize )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid 1st step iteration for hmac key context" );

 /* перемаскируем ключ и меняем его ресурс */
  hctx->key.set_mask( &hctx->key );
  hctx->key.resource.counter--; /* мы использовали ключ один раз */

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_hmac.с */
/* ----------------------------------------------------------------------------------------------- */
