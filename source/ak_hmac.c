/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hmac.с                                                                                 */
/*  - содержит реализацию семейства ключевых алгоритмов хеширования HMAC.                          */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>
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
/*! @param ctx Контекст алгоритма HMAC выработки имитовставки.
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

 /* обновляем состояние контекста хеширования */
  if(( error = hctx->ctx.update( &hctx->ctx, buffer, hctx->ctx.bsize )) != ak_error_ok )
    ak_error_message( error, __func__, "invalid 1st step iteration for hmac key context" );

 /* очищаем буффер */
  ak_ptr_wipe( buffer, sizeof( buffer ), &hctx->key.generator, ak_true );

 /* перемаскируем ключ и меняем его ресурс */
  hctx->key.set_mask( &hctx->key );
  hctx->key.resource.counter--; /* мы использовали ключ один раз */

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Контекст алгоритма HMAC выработки имитовставки.
    @param data Указатель на обрабатываемые данные.
    @param size Длина обрабатываемых данных (в байтах); длина должна быть кратна длине блока
    обрабатываемых данных используемой функции хеширования
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_update( ak_pointer ctx, const ak_pointer data, const size_t size )
{
  ak_hmac hctx = ( ak_hmac ) ctx;

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                      "using zero length for authenticated data" );
  if( size%hctx->ctx.bsize ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                  "using data with wrong length" );
 /* проверяем наличие ключа и его ресурс */
  if( !((hctx->key.flags)&skey_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );
  if( hctx->key.resource.counter <= 0 ) return ak_error_message( ak_error_resource_counter,
                                            __func__, "using hmac key context with low resource" );

  return hctx->ctx.update( &hctx->ctx, data, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Контекст алгоритма HMAC выработки имитовставки.
    @param data блок входных данных; длина блока должна быть менее, чем блина блока
           обрабатываемых данных для используемой функции хеширования
    @param size длина блока обрабатываемых данных
    @param out указатель на область памяти, куда будет помещен результат; если out равен NULL,
           то создается новый буффер, в который помещается результат.
    @return если out равен NULL, то возвращается указатель на созданный буффер. В противном случае
           возвращается NULL. В случае возникновения ошибки возывращается NULL. Код ошибки может
           быть получен c помощью вызова функции ak_error_get_value().                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hmac_context_finalize( ak_pointer ctx, const ak_pointer data,
                                                               const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  size_t idx = 0, len = 0;
  ak_hmac hctx = ( ak_hmac ) ctx;
  ak_buffer result = NULL;
  ak_uint8 temporary[128]; /* первый буффер для хранения промежуточных значений */
  ak_uint8 keybuffer[128]; /* второй буффер для хранения промежуточных значений */

 /* выполняем проверки */
  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to hmac context" );
    return NULL;
  }
 /* ограничение в связи с константным размером временного буффера */
  if( hctx->ctx.hsize > sizeof( temporary )) {
    ak_error_message( ak_error_wrong_length,
                   __func__, "using a hash context with unsupported huge integrity code size" );
    return NULL;
  }
  if( size >= hctx->ctx.bsize ) {
    ak_error_message( ak_error_zero_length,
                                       __func__ , "using wrong length for authenticated data" );
    return NULL;
  }
 /* проверяем наличие ключа (ресурс проверен при вызове clean) */
  if( !((hctx->key.flags)&skey_flag_set_key )) {
    ak_error_message( ak_error_key_value, __func__ , "using hmac key with unassigned value" );
    return NULL;
  }

 /* обрабатываем хвост предыдущих данных */
  memset( temporary, 0, sizeof( temporary ));
  error = ak_error_ok;
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

 /* формируем значение первоначального буффера */
  len = ak_min( hctx->ctx.bsize, hctx->key.key.size );
  memset( keybuffer, 0, hctx->ctx.bsize );
  for( idx = 0; idx < len; idx++ ) {
     keybuffer[idx] = ((ak_uint8 *)hctx->key.key.data)[idx] ^ 0x5C;
     keybuffer[idx] ^= ((ak_uint8 *)hctx->key.mask.data)[idx];
  }
  for( ; idx < hctx->ctx.bsize; idx++ ) keybuffer[idx] = 0x5C;

 /* обновляем состояние контекста хеширования */
  if(( error = hctx->ctx.update( &hctx->ctx, keybuffer, hctx->ctx.bsize )) != ak_error_ok )
    ak_error_message( error, __func__, "invalid 1st step iteration for hmac key context" );

 /* очищаем буффер */
  ak_ptr_wipe( keybuffer, sizeof( keybuffer ), &hctx->key.generator, ak_true );
 /* ресурс ключа */
  hctx->key.set_mask( &hctx->key );
  hctx->key.resource.counter--; /* мы использовали ключ один раз */

 /* последний update/finalize и возврат результата */
  if( hctx->ctx.bsize == hctx->ctx.hsize ) {
    hctx->ctx.update( &hctx->ctx, temporary, hctx->ctx.hsize );
    result = hctx->ctx.finalize( &hctx->ctx, NULL, 0, out );
  } else result = hctx->ctx.finalize( &hctx->ctx, temporary, hctx->ctx.hsize, out );

 /* очищаем контекст функции хеширования, ключ не трогаем */
  hctx->ctx.clean( &hctx->ctx );

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет имитовставку от заданной области памяти на которую указывает in. Размер памяти
    задается в байтах в переменной size. Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    \b Внимание. После завершения вычислений контекст функции хеширования инициалищируется
    в начальное состояние.

    @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_hash_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hmac_context_ptr( ak_hmac hctx, const ak_pointer in, const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  size_t quot = 0, offset = 0;

  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to hmac context" );
    return NULL;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to data" );
    return NULL;
  }

  /* вычищаем результаты предыдущих вычислений */
  if(( error = ak_hmac_context_clean( hctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect cleaning hmac context" );
    return NULL;
  }
  quot = size/hctx->ctx.bsize;
  offset = quot*hctx->ctx.bsize;

  /* вызываем, если длина сообщения не менее одного полного блока */
  if( quot > 0 )
    if(( error = ak_hmac_context_update( hctx, in, offset )) != ak_error_ok ) {
      ak_error_message( error, __func__ , "incorrect updating hmac context" );
      return NULL;
    }

  /* обрабатываем хвост и возвращаем результат */
 return ak_hmac_context_finalize( hctx, (ak_uint8 *)in + offset, size - offset, out );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает указатель на
    созданный буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param hctx Контекст алгоритма HMAC выработки имитовставки.
    @param filename Имя файла, для которого вычисляется значение хеш-кода.
    @param out Область памяти, куда будет помещен результат.
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hmac_context_file( ak_hmac ctx, const char *filename, ak_pointer out )
{
  struct mac ictx;
  int error = ak_error_ok;
  ak_buffer result = NULL;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to hmac context" );
    return NULL;
  }

  if(( error = ak_mac_context_create_hmac( &ictx, ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of mac context" );
    return NULL;
  }

  result = ak_mac_context_file( &ictx, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect integrity code calculation" );

  ak_mac_context_destroy( &ictx );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                            функции для тестирования алгоритма hmac                              */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_hmac_test_streebog( void )
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
  ak_bool result = ak_true;
  int audit = ak_log_get_level();

 /* 1. тестируем HMAC на основе Стрибог 256 */
  if(( error = ak_hmac_context_create_streebog256( &hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of hmac-streebog256 key context" );
    return ak_false;
  }
  if(( error = ak_hmac_context_set_key( &hkey, key, 32, ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_hmac_context_ptr( &hkey, data, 16, out );
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
  if(( error = ak_hmac_context_set_key( &hkey, key, 32, ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_hmac_context_ptr( &hkey, data, 16, out );
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
/*                                                                                       ak_hmac.с */
/* ----------------------------------------------------------------------------------------------- */
