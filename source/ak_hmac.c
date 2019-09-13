/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hmac.с                                                                                 */
/*  - содержит реализацию семейства ключевых алгоритмов хеширования HMAC.                          */
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

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hmac.h>
 #include <ak_tools.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Очистка контекста алгоритма hmac.
    \param ctx Контекст алгоритма HMAC выработки имитовставки.
    \return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_hmac_context_internal_clean( ak_pointer ctx )
{
  int error = ak_error_ok;
  ak_hmac hctx = ( ak_hmac ) ctx;
  size_t idx = 0, jdx = 0, len = 0;
  ak_uint8 buffer[64]; /* буффер для хранения промежуточных значений */

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
 /* проверяем наличие ключа и его ресурс */
  if( !((hctx->key.flags)&skey_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );

  if( hctx->key.resource.value.counter <= 1 ) return ak_error_message( ak_error_low_key_resource,
                                            __func__, "using hmac key context with low resource" );
                      /* нам надо два раза использовать ключ => ресурс должен быть не менее двух */
  if( hctx->mctx.bsize > sizeof( buffer )) return ak_error_message( ak_error_wrong_length,
                                            __func__, "using hash function with huge block size" );

 /* фомируем маскированное значение ключа */
  len = ak_min( hctx->mctx.bsize, jdx = hctx->key.key_size );
  for( idx = 0; idx < len; idx++, jdx++ ) {
     buffer[idx] = hctx->key.key[idx] ^ 0x36;
     buffer[idx] ^= hctx->key.key[jdx];
  }
  for( ; idx < hctx->mctx.bsize; idx++ ) buffer[idx] = 0x36;

 /* инициализируем начальное состояние контекста хеширования */
  if(( error = ak_hash_context_clean( &hctx->ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of hash function context" );

 /* обновляем состояние контекста хеширования */
  if(( error = ak_hash_context_update( &hctx->ctx, buffer, hctx->mctx.bsize )) != ak_error_ok )
    ak_error_message( error, __func__, "invalid 1st step iteration for hmac key context" );

 /* очищаем буффер */
  ak_ptr_context_wipe( buffer, sizeof( buffer ), &hctx->key.generator );

 /* перемаскируем ключ и меняем его ресурс */
  hctx->key.set_mask( &hctx->key );
  hctx->key.resource.value.counter--; /* мы использовали ключ один раз */

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Обновление состояния контекста сжимающего отображения.
    \param ctx Контекст алгоритма HMAC выработки имитовставки.
    \param data Указатель на обрабатываемые данные.
    \param size Длина обрабатываемых данных (в байтах); длина должна быть кратна длине блока
    обрабатываемых данных используемой функции хеширования
    \return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_hmac_context_internal_update( ak_pointer ctx, const ak_pointer in, const size_t size )
{
  ak_hmac hctx = ( ak_hmac ) ctx;

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                      "using zero length for authenticated data" );
  if( size%hctx->mctx.bsize ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                  "using data with wrong length" );
 /* проверяем наличие ключа и его ресурс */
  if( !((hctx->key.flags)&skey_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );
  if( hctx->key.resource.value.counter <= 0 ) return ak_error_message( ak_error_low_key_resource,
                                            __func__, "using hmac key context with low resource" );

  return ak_hash_context_update( &hctx->ctx, in, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Обновление состояния и вычисление результата применения сжимающего отображения.
    \param ctx Контекст алгоритма HMAC выработки имитовставки.
    \param data Блок входных данных; длина блока должна быть менее, чем блина блока
           обрабатываемых данных для используемой функции хеширования
    \param size Длина блока обрабатываемых данных
    \param out Указатель на область памяти, куда будет помещен результат.
    \return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_hmac_context_internal_finalize( ak_pointer ctx,
                    const ak_pointer in, const size_t size, ak_pointer out, const size_t out_size )
{
  int error = ak_error_ok;
  ak_hmac hctx = ( ak_hmac ) ctx;
  size_t idx = 0, jdx = 0, len = 0;
  ak_uint8 temporary[128]; /* первый буффер для хранения промежуточных значений */
  ak_uint8 keybuffer[128]; /* второй буффер для хранения промежуточных значений */

 /* выполняем проверки */
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using a null pointer to hmac context" );
 /* ограничение в связи с константным размером временного буффера */
  if( hctx->ctx.data.sctx.hsize > sizeof( temporary ))
    return ak_error_message( ak_error_wrong_length,
                      __func__, "using a hash context with unsupported huge integrity code size" );
  if( size >= hctx->mctx.bsize ) return ak_error_message( ak_error_zero_length,
                                          __func__ , "using wrong length for authenticated data" );
 /* проверяем наличие ключа (ресурс проверен при вызове clean) */
  if( !((hctx->key.flags)&skey_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );
 /* обрабатываем хвост предыдущих данных */
  memset( temporary, 0, sizeof( temporary ));
  if(( error = ak_hash_context_finalize( &hctx->ctx, in, size, temporary,
                                                            sizeof( temporary ))) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong updating of finalized data" );

 /* фомируем маскированное значение ключа */
  len = ak_min( hctx->mctx.bsize, jdx = hctx->key.key_size );
  for( idx = 0; idx < len; idx++ , jdx++ ) {
     keybuffer[idx] = hctx->key.key[idx] ^ 0x5C;
     keybuffer[idx] ^= hctx->key.key[jdx];
  }
  for( ; idx < hctx->mctx.bsize; idx++ ) keybuffer[idx] = 0x5C;

 /* возвращаем контекст хеширования в начальное состояние */
  if(( error = ak_hash_context_clean( &hctx->ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of hash function context" );

 /* обновляем состояние контекста хеширования */
  if(( error = ak_hash_context_update( &hctx->ctx, keybuffer, hctx->mctx.bsize )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid 1st step iteration for hmac key context" );

 /* очищаем буффер */
  ak_ptr_context_wipe( keybuffer, sizeof( keybuffer ), &hctx->key.generator );

 /* ресурс ключа */
  hctx->key.set_mask( &hctx->key );
  hctx->key.resource.value.counter--; /* мы использовали ключ один раз */

 /* последний update/finalize и возврат результата */
  error = ak_hash_context_finalize( &hctx->ctx, temporary,
                                                        hctx->ctx.data.sctx.hsize, out, out_size );
 /* очищаем контекст функции хеширования, ключ не трогаем */
  ak_hash_context_clean( &hctx->ctx );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \param oid Идентификатор алгоритма HMAC - ключевой функции хеширования.
    \return В случае успешного завершения функция возвращает \ref ak_error_ok. В случае
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
 /* проверяем, что OID от правильного алгоритма выработки */
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
  if(( error = (( ak_function_hash_context_create *)hashoid->func.create )
                                                                  ( &hctx->ctx )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__,
                                   "invalid creation of %s hash function context", hashoid->name );
 /* инициализируем контекст сжимающего отображения */
  if(( error = ak_mac_context_create(
                 &hctx->mctx, /* контекст */
                 hctx->ctx.mctx.bsize, /* размер входного блока совпадает с блоком хеш-функции */
                 hctx, /* указатель на объек, которым будут оперировать функции */
                 ak_hmac_context_internal_clean,
                 ak_hmac_context_internal_update,
                 ak_hmac_context_internal_finalize )) != ak_error_ok ) {
    ak_hmac_context_destroy( hctx );
    return ak_error_message( error, __func__, "invalid creation of mac function context" );
  }

 /* инициализируем контекст секретного ключа */
  if(( error = ak_skey_context_create( &hctx->key, hctx->ctx.mctx.bsize )) != ak_error_ok ) {
    ak_hmac_context_destroy( hctx );
    return ak_error_message( error, __func__, "wrong creation of secret key context" );
  }
 /* доопределяем oid ключа */
  hctx->key.oid = oid;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_create_streebog256( ak_hmac hctx )
{ return ak_hmac_context_create_oid( hctx, ak_oid_context_find_by_name( "hmac-streebog256" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_create_streebog512( ak_hmac hctx )
{ return ak_hmac_context_create_oid( hctx, ak_oid_context_find_by_name( "hmac-streebog512" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_destroy( ak_hmac hctx )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hmac context" );
  if(( error = ak_hash_context_destroy( &hctx->ctx )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of hash context" );
  if(( error = ak_skey_context_destroy( &hctx->key )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of secret key context" );
  if(( error = ak_mac_context_destroy( &hctx->mctx )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of mac context" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
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
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    К моменту вызова функции контекст должен быть инициализирован.
    \param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    \param size Размер данных, на которые указывает `ptr` (размер в байтах).
    Если величина `size` меньше, чем размер выделенной памяти под секретный ключ, то копируется
    только `size` байт (остальные заполняются нулями). Если `size` больше, чем количество выделенной памяти
    под ключ, то в качестве ключа используется хэш-код от `ptr`.

    \return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_set_key( ak_hmac hctx, const ak_pointer ptr, const size_t size )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hmac context" );
 /* вспоминаем, что если ключ длиннее, чем длина входного блока хэш-функции, то в качестве
                                                                      ключа используется его хэш */
  if( size > hctx->mctx.bsize ) {
    ak_uint8 out[64];
    size_t stag = ak_hash_context_get_tag_size( &hctx->ctx );

    if(( stag == 0 ) || ( stag > 64 ))
      return ak_error_message( ak_error_wrong_length, __func__ ,
                                   "using hash function with incorrect length of integrity code" );
   /* вычисляем хэш от заданного значения */
    memset( out, 0, sizeof( out ));
    if(( error = ak_hash_context_ptr( &hctx->ctx, ptr, size, out, sizeof( out ))) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect calculation of integrity code" );

    if(( error = ak_skey_context_set_key( &hctx->key, out, stag )) != ak_error_ok )
      return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );
    ak_ptr_context_wipe( out, sizeof( out ), &hctx->key.generator );

  } else { /* здесь ключ используется в явном виде */
      if(( error = ak_skey_context_set_key( &hctx->key, ptr, size )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );
  }

 /* устанавливаем ресурс ключа */
  if(( error = ak_skey_context_set_resource( &hctx->key,
                          key_using_resource, "hmac_key_count_resource", 0, 0 )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect assigning \"hmac_key_count_resource\" option" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу случайное (псевдо-случайное) значение, размер которого определяется
    размером секретного ключа. Способ выработки ключевого значения определяется используемым
    генератором случайных (псевдо-случайных) чисел.

    \param hctx Контекст алгоритма HMAC выработки имитовставки. К моменту вызова функции контекст
    должен быть инициализирован.
    \param generator Контекст генератора псевдо-случайных чисел.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_set_key_random( ak_hmac hctx, ak_random generator )
{
  int error = ak_error_ok;
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
  if(( error = ak_skey_context_set_key_random( &hctx->key, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

 /* устанавливаем ресурс ключа */
  if(( error = ak_skey_context_set_resource( &hctx->key,
                          key_using_resource, "hmac_key_count_resource", 0, 0 )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect assigning \"hmac_key_count_resource\" option" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_clean( ak_hmac hctx )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "cleaning null pointer to hash context" );
 return ak_mac_context_clean( &hctx->mctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \param in Указатель на входные данные для которых вычисляется хеш-код.
    \param size Размер входных данных в байтах. Размер может принимать произвольное,
    натуральное значение.

    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_update( ak_hmac hctx, const ak_pointer in, const size_t size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "updating null pointer to hmac context" );
 return ak_mac_context_update( &hctx->mctx, in, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \param in Указатель на входные данные для которых вычисляется хеш-код.
    \param size Размер входных данных в байтах.
    \param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize и может
    быть определен с помощью вызова функции ak_hash_context_get_tag_size().
    \param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    \return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_finalize( ak_hmac hctx, const ak_pointer in, const size_t size,
                                                           ak_pointer out, const size_t out_size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "finalizing null pointer to hmac context" );
 return ak_mac_context_finalize( &hctx->mctx, in, size, out, out_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \param in Указатель на входные данные для которых вычисляется хеш-код.
    \param size Размер входных данных в байтах.
    \param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize и может
    быть определен с помощью вызова функции ak_hash_context_get_tag_size().
    \param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    \return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_ptr( ak_hmac hctx, const ak_pointer in, const size_t size,
                                                           ak_pointer out, const size_t out_size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hmac context" );
 return ak_mac_context_ptr( &hctx->mctx, in, size, out, out_size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \param filename Имя файла, для котрого вычисляется имитовставка.
    \param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть не менее значения поля hsize и может
    быть определен с помощью вызова функции ak_hash_context_get_tag_size().
    \param out_size Размер области памяти (в октетах), в которую будет помещен результат.

    \return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_file( ak_hmac hctx, const char * filename,
                                                           ak_pointer out, const size_t out_size )
{
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to hash context" );
 return ak_mac_context_file( &hctx->mctx, filename, out, out_size );
}


/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return Функция возвращает длину имитовставки в октетах. В случае возникновения ошибки,
    возвращается ноль. Код ошибки может быть получен с помощью вызова функции ak_error_get_value().*/
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hmac_context_get_tag_size( ak_hmac hctx )
{
  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to hash context" );
    return 0;
  }

 return hctx->ctx.data.sctx.hsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param hctx Контекст алгоритма HMAC выработки имитовставки.
    \return Функция возвращает длину блока в октетах. В случае возникновения ошибки,
    возвращается ноль. Код ошибки может быть получен с помощью вызова функции ak_error_get_value().*/
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hmac_context_get_block_size( ak_hmac hctx )
{
  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to hash context" );
    return 0;
  }

 return hctx->mctx.bsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*                            функции для тестирования алгоритма hmac                              */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_hmac_test_streebog( void )
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

  struct hmac hkey;
  char *str = NULL;
  ak_uint8 out[64];
  int error = ak_error_ok;
  bool_t result = ak_true;
  int audit = ak_log_get_level();

 /* 1. тестируем HMAC на основе Стрибог 256 */
  if(( error = ak_hmac_context_create_streebog256( &hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of hmac-streebog256 key context" );
    return ak_false;
  }
  if(( error = ak_hmac_context_set_key( &hkey, key, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_hmac_context_ptr( &hkey, data, 16, out, sizeof( out ));
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
  ak_hmac_context_destroy( &hkey );

 /* 2. тестируем HMAC на основе Стрибог 512 */
  if(( error = ak_hmac_context_create_streebog512( &hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of hmac-streebog512 key context" );
    return ak_false;
  }
  if(( error = ak_hmac_context_set_key( &hkey, key, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_hmac_context_ptr( &hkey, data, 16, out, sizeof( out ));
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
  ak_hmac_context_destroy( &hkey );
 return result;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hmac.c  */
/* ----------------------------------------------------------------------------------------------- */
