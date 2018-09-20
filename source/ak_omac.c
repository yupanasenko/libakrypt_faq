/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_omac.с                                                                                 */
/*  - содержит реализацию алгоритма выработки имитовставки согласно ГОСТ Р 34.13-2015.             */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>

/* ----------------------------------------------------------------------------------------------- */
/*! @param gkey Контекст алгоритма выработки имитовставки.
    @param oid Идентификатор алгоритма выработки имитовставки в соответствии с ГОСТ Р 34.13-2015.
    @return В случае успешного завершения функция возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_omac_context_create_oid( ak_omac gkey, ak_oid oid )
{
  ak_oid bcoid = NULL;
  int error = ak_error_ok;

 /* выполняем проверку */
  if( gkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to omac context" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to omac function OID" );
 /* проверяем, что OID от правильного алгоритма выработки имитовставки */
  if( oid->engine != omac_function )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );

 /* получаем oid алгоритма блочного шифрования */
  if(( bcoid = ak_oid_context_find_by_name( oid->name+5 )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__ ,
                                                   "incorrect searching of block cipher oid" );
 /* проверяем, что производящая функция определена */
  if( bcoid->func.create == NULL )
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                         "using block cipher oid with undefined constructor" );
 /* инициализируем контекст ключа алгоритма блочного шифрования */
  if(( error =
           (( ak_function_bckey_create *)bcoid->func.create )( &gkey->bkey )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__,
                                  "invalid creation of %s block cipher context", bcoid->name );
 /* доопределяем oid ключа */
  gkey->bkey.key.oid = ak_oid_context_find_by_name( "omac-magma" );

 /* инициализируем структуру буффера для хранения промежуточных значений
    при этом длина буффера полагается равной нулю. */
  if(( error = ak_buffer_create_size( &gkey->yaout, gkey->bkey.bsize )) != ak_error_ok ) {
    ak_bckey_context_destroy( &gkey->bkey );
    return ak_error_message( error, __func__, "wrong creation a temporary buffer" );
  }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param gkey Контекст алгоритма выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_omac_context_create_magma( ak_omac gkey )
{ return ak_omac_context_create_oid( gkey, ak_oid_context_find_by_name( "omac-magma" )); }

/* ----------------------------------------------------------------------------------------------- */
/*! @param gkey Контекст алгоритма выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_omac_context_create_kuznechik( ak_omac gkey )
{ return ak_omac_context_create_oid( gkey, ak_oid_context_find_by_name( "omac-kuznechik" )); }


/* ----------------------------------------------------------------------------------------------- */
/*! @param gkey Контекст алгоритма выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_omac_context_destroy( ak_omac gkey )
{
  int error = ak_error_ok;

  if( gkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to hmac context" );
  if(( error = ak_buffer_destroy( &gkey->yaout )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of internal buffer" );
  if(( error = ak_bckey_context_destroy( &gkey->bkey )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying of block cipher key" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param gkey Контекст алгоритма выработки имитовставки.
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_omac_context_delete( ak_pointer gkey )
{
  if( gkey != NULL ) {
      ak_omac_context_destroy(( ak_omac ) gkey );
      free( gkey );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to omac context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param gkey Контекст алгоритма выработки имитовставки.
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
 int ak_omac_context_set_key( ak_omac gkey, const ak_pointer ptr,
                                                            const size_t size, const ak_bool cflag )
{
  int error = ak_error_ok;
  if( gkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to omac context" );
  if(( error = ak_bckey_context_set_key( &gkey->bkey, ptr, size, cflag )) != ak_error_ok )
        return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

  ak_omac_context_clean( gkey );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу случайное (псевдо-случайное) значение, размер которого определяется
    размером секретного ключа. Способ выработки ключевого значения определяется используемым
    генератором случайных (псевдо-случайных) чисел.

    @param gkey Контекст алгоритма выработки имитовставки.
    К моменту вызова функции контекст должен быть инициализирован.
    @param generator контекст генератора псевдо-случайных чисел.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_omac_context_set_key_random( ak_omac gkey, ak_random generator )
{
  int error = ak_error_ok;
  if( gkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to omac context" );
  if(( error = ak_bckey_context_set_key_random( &gkey->bkey, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

  ak_omac_context_clean( gkey );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу значение, выработанное из заданного пароля при помощи
    алгоритма PBKDF2, описанного  в рекомендациях по стандартизации Р 50.1.111-2016.
    Пароль должен быть непустой строкой символов в формате utf8.

    Количество итераций алгоритма PBKDF2 определяется опцией библиотеки `pbkdf2_iteration_count`,
    значение которой может быть опредедено с помощью вызова функции ak_libakrypt_get_option().

    @param gkey Контекст алгоритма выработки имитовставки.
    К моменту вызова функции контекст должен быть инициализирован.
    @param pass Пароль, представленный в виде строки символов.
    @param pass_size Длина пароля в байтах.
    @param salt Случайная последовательность, представленная в виде строки символов.
    @param salt_size Длина случайной последовательности в байтах.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_omac_context_set_key_from_password( ak_omac gkey,
                                                const ak_pointer pass, const size_t pass_size,
                                                     const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;
  if( gkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to omac context" );
  if(( error = ak_bckey_context_set_key_from_password( &gkey->bkey,
                                          pass, pass_size, salt, salt_size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning a secret key value" );

  ak_omac_context_clean( gkey );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr Контекст алгоритма выработки имитовставки.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_omac_context_clean( ak_pointer ptr )
{
  ak_omac gkey = ( ak_omac ) ptr;

  if( gkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to omac context" );
  if( gkey->yaout.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using non initialized internal buffer" );
  memset( gkey->yaout.data, 0, gkey->yaout.size );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr Контекст алгоритма выработки имитовставки.
    @param data Указатель на обрабатываемые данные.
    @param size Длина обрабатываемых данных (в байтах); длина должна быть кратна длине блока
    обрабатываемых данных используемой функции хеширования
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_omac_context_update( ak_pointer ptr, const ak_pointer data, const size_t size )
{
  ak_omac gkey = ( ak_omac ) ptr;
  ak_int64 i, blocks = 0;
  ak_uint64 *inptr = (ak_uint64 *)data, *yaptr = NULL;

  if( gkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to omac key context" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                      "using zero length for authenticated data" );
  if( size%gkey->bkey.bsize ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                  "using data with wrong length" );
 /* проверяем наличие ключа */
  if( !((gkey->bkey.key.flags)&skey_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using omac key with unassigned value" );
 /* проверяем ресурс ключа */
  blocks = (ak_int64)size/gkey->bkey.bsize;
  if( gkey->bkey.key.resource.counter <= blocks + 2 ) /* плюс два вызова на финализацию */
    return ak_error_message( ak_error_low_key_resource,
                                            __func__, "using omac key context with low resource" );
  else gkey->bkey.key.resource.counter -= blocks;

 /* основной цикл */
  yaptr = (ak_uint64 *)gkey->yaout.data;
  if( gkey->bkey.bsize == 16 ) { /* здесь длина блока равна 128 бита */
    for( i = 0; i < blocks; i++, inptr += 2 ) {
       yaptr[0] ^= inptr[0];
       yaptr[1] ^= inptr[1];
       gkey->bkey.encrypt( &gkey->bkey.key, yaptr, yaptr );
    }
  }
  if( gkey->bkey.bsize == 8 ) { /* здесь длина блока равна 64 бита */
    for( i = 0; i < blocks; i++, inptr++ ) {
       yaptr[0] ^= inptr[0];
       gkey->bkey.encrypt( &gkey->bkey.key, yaptr, yaptr );
    }
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr Контекст алгоритма выработки имитовставки.
    @param data Блок входных данных; длина блока должна быть менее, чем блина блока
           обрабатываемых данных (блока блочного шифра: не более 7 для Магмы и 15 для Кузнечика).
    @param size Длина блока обрабатываемых данных
    @param out Указатель на область памяти, куда будет помещен результат; если out равен NULL,
           то создается новый буффер, в который помещается результат.
    @return Если out равен NULL, то возвращается указатель на созданный буффер. В противном случае
           возвращается NULL. В случае возникновения ошибки возывращается NULL. Код ошибки может
           быть получен c помощью вызова функции ak_error_get_value().                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_omac_context_finalize( ak_pointer ptr, const ak_pointer data,
                                                               const size_t size, ak_pointer out )
{
  size_t i = 0;
  ak_pointer pout = NULL;
  ak_buffer result = NULL;
  ak_omac gkey = ( ak_omac ) ptr;
  ak_uint64 *yaptr = NULL, akey[2], eval[2], one64[2] = { 0x2, 0x0 };

  if( gkey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to omac key context" );
    return NULL;
  }
  if( size >= gkey->bkey.bsize ) {
    ak_error_message( ak_error_zero_length,
                                          __func__ , "using wrong length for authenticated data" );
    return NULL;
  }
 /* проверяем наличие ключа */
  if( !((gkey->bkey.key.flags)&skey_flag_set_key )) {
    ak_error_message( ak_error_key_value, __func__ , "using omac key with unassigned value" );
    return NULL;
  }
 /* проверяем ресурс ключа */
  if( gkey->bkey.key.resource.counter < 2 ) {
    ak_error_message( ak_error_low_key_resource,
                                            __func__, "using omac key context with low resource" );
    return NULL;
  } else gkey->bkey.key.resource.counter -= 2;

 /* готовим временные переменные */
  memset( akey, 0, sizeof( akey ));
  memset( eval, 0, sizeof( eval ));
  yaptr = (ak_uint64 *)gkey->yaout.data;

 /* вырабатываем первичный ключ */
  gkey->bkey.encrypt( &gkey->bkey.key, akey, akey );
  if( gkey->bkey.bsize == 16 ) ak_gf128_mul( akey, akey, one64 );
   else ak_gf64_mul( akey, akey, one64 );

 /* обрабатываем последний блок данных */
  if(( size == 0 ) || ( data == NULL )) { /* блок полный */
    gkey->bkey.decrypt( &gkey->bkey.key, yaptr, eval ); /* исходные данные (yaout) не испорчены
                                              и могут быть накоплены далее путем вызова update() */
  } else { /* неполный блок */
           memcpy( eval, gkey->yaout.data, gkey->yaout.size );
           for( i = 0; i < size; i++ ) ((ak_uint8 *)eval)[i] ^= ((ak_uint8 *)data)[i];
           if( gkey->bkey.bsize == 16 ) ak_gf128_mul( akey, akey, one64 );
             else ak_gf64_mul( akey, akey, one64 );
           ((ak_uint8 *)akey)[size] ^= 0x80;
  }
  akey[0] ^= eval[0]; akey[1] ^= eval[1];
  gkey->bkey.encrypt( &gkey->bkey.key, akey, akey );

 /* определяем указатель на область памяти, в которую будет помещен результат вычислений */
  if( out != NULL ) pout = out;
   else {
     if(( result = ak_buffer_new_size( gkey->bkey.bsize )) != NULL ) pout = result->data;
      else ak_error_message( ak_error_get_value( ), __func__ , "wrong creation of result buffer" );
   }
 /* копируем нужную часть результирующего массива или выдаем сообщение об ошибке */
  if( pout != NULL ) memcpy( pout, akey, gkey->bkey.bsize );
    else ak_error_message( ak_error_out_of_memory, __func__ ,
                                                 "incorrect memory allocation for result buffer" );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет имитовставку от заданной области памяти на которую указывает in. Размер памяти
    задается в байтах в переменной size. Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    \b Внимание. После завершения вычислений контекст функции хеширования инициализируется
    в начальное состояние.

    @param gkey Контекст алгоритма выработки имитовставки.
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
 ak_buffer ak_omac_context_ptr( ak_omac gkey, const ak_pointer in, const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  ak_buffer result = NULL;

  if( gkey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to omac key context" );
    return NULL;
  }
  result = ak_bckey_context_omac( &gkey->bkey, in, size, out );
  if(( error = ak_error_get_value()) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect omac calculation" );

  ak_omac_context_clean( gkey );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает указатель на
    созданный буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param gkey Контекст алгоритма выработки имитовставки.
    @param filename Имя файла, для которого вычисляется значение хеш-кода.
    @param out Область памяти, куда будет помещен результат.
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_omac_context_file( ak_omac gkey, const char *filename, ak_pointer out )
{
  struct mac ictx;
  int error = ak_error_ok;
  ak_buffer result = NULL;

  if( gkey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to hmac context" );
    return NULL;
  }

  if(( error = ak_mac_context_create_omac( &ictx, gkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of mac context" );
    return NULL;
  }

  result = ak_mac_context_file( &ictx, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect integrity code calculation" );

  ak_mac_context_destroy( &ictx );
 return result;
}

/*! -----------------------------------------------------------------------------------------------
    \example test-internal-omac01.c                                                                 */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_omac.c  */
/* ----------------------------------------------------------------------------------------------- */

