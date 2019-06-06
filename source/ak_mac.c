/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_mac.с                                                                                  */
/*  - содержит реализацию функций итерационного сжатия.                                            */
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
 #include <ak_mac.h>
 #include <ak_tools.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст структуры struct mac в значения, определяемые
    заданным контекстом hctx функции хеширования.
    При этом, владение контекстом hctx не происходит (в частности не происходит его удаление).

    @param ictx Указатель на структуру struct mac.
    @param hctx Контекст бесключевой функции хеширования; контекст должен быть
    предварительно инициализирован.
    @return В случае успеха возвращается \ref ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_create_hash( ak_mac ictx, ak_hash hctx )
{
  char oid[32];
  int error = ak_error_ok;

 /* вначале, необходимые проверки */
  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to mac context" );
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to hash context" );
  if(( hctx->update == NULL ) || ( hctx->finalize == NULL ) || ( hctx->clean == NULL ))
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                                           "using non initialized hash context" );
 /* теперь собственно инициализация */
  if(( ictx->data = (ak_uint8 *) malloc( ictx->bsize = hctx->bsize )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                     "wrong memory alllocation for a new temporary data buffer" );
  } else memset( ictx->data, 0, hctx->bsize );
  ictx->length = 0;

 /* устанавливаем значения и полей и методы из контекста функции хеширования */
  ictx->engine = hash_function;
  ictx->ctx = hctx;
  ictx->hsize = hctx->hsize;
  ictx->clean = hctx->clean;
  ictx->update = hctx->update;
  ictx->finalize = hctx->finalize;
  ictx->free = NULL;

 /* формируем oid алгоритма, добавляя приставку mac к его имени */
  ak_snprintf( oid, sizeof( oid ), "mac-%s", hctx->oid->name );
  if(( ictx->oid = ak_oid_context_find_by_name( oid )) == NULL ) {
    error = ak_error_get_value();
    ak_mac_context_destroy( ictx );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст структуры struct mac в значения, определяемые
    заданным контекстом hctx ключевой функции хеширования HMAC.
    При этом, владение контекстом hctx не происходит (в частности не происходит его удаление).

    @param ictx Указатель на структуру struct mac.
    @param hctx Контекст ключевой функции хеширования HMAC; контекст должен быть
    предварительно инициализирован.
    @return В случае успеха возвращается \ref ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_create_hmac( ak_mac ictx, ak_hmac hctx )
{
  char oid[32];
  int error = ak_error_ok;

 /* вначале, необходимые проверки */
  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to mac context" );
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to hmac context" );
 /* теперь собственно инициализация */
  if(( ictx->data = (ak_uint8 *) malloc( ictx->bsize = hctx->ctx.bsize )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                     "wrong memory alllocation for a new temporary data buffer" );
  } else memset( ictx->data, 0, hctx->ctx.bsize );
  ictx->length = 0;

 /* устанавливаем значения и полей и методы из контекста функции хеширования */
  ictx->engine = hmac_function;
  ictx->ctx = hctx;
  ictx->hsize = hctx->ctx.hsize;
  ictx->clean = ak_hmac_context_clean;
  ictx->update = ak_hmac_context_update;
  ictx->finalize = ak_hmac_context_finalize;
  ictx->free = NULL;

 /* формируем oid алгоритма, добавляя приставку mac к его имени */
  ak_snprintf( oid, sizeof( oid ), "mac-%s", hctx->key.oid->name );
  if(( ictx->oid = ak_oid_context_find_by_name( oid )) == NULL ) {
    error = ak_error_get_value();
    ak_mac_context_destroy( ictx );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст структуры struct mac в значения, определяемые
    заданным контекстом octx ключевой функции хеширования HMAC.
    При этом, владение контекстом hctx не происходит (в частности не происходит его удаление).

    @param ictx Указатель на структуру struct mac.
    @param octx Контекст ключевой функции хеширования ГОСТ Р 34.13-2015; контекст должен быть
    предварительно инициализирован.
    @return В случае успеха возвращается \ref ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_create_omac( ak_mac ictx, ak_omac octx )
{
  char oid[32];
  int error = ak_error_ok;

 /* вначале, необходимые проверки */
  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to mac context" );
  if( octx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to omac context" );
 /* теперь собственно инициализация */
  if(( ictx->data = (ak_uint8 *) malloc( ictx->bsize = octx->bkey.bsize )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                     "wrong memory alllocation for a new temporary data buffer" );
  } else memset( ictx->data, 0, octx->bkey.bsize );
  ictx->length = 0;

 /* устанавливаем значения и полей и методы из контекста функции хеширования */
  ictx->engine = omac_function;
  ictx->ctx = octx;
  ictx->hsize = ictx->bsize; /* длина вызода совпадает с длиной входа */
  ictx->clean = ak_omac_context_clean;
  ictx->update = ak_omac_context_update;
  ictx->finalize = ak_omac_context_finalize;
  ictx->free = NULL;

 /* формируем oid алгоритма, добавляя приставку mac к его имени */
  ak_snprintf( oid, sizeof( oid ), "mac-%s", octx->bkey.key.oid->name );
  if(( ictx->oid = ak_oid_context_find_by_name( oid )) == NULL ) {
    error = ak_error_get_value();
    ak_mac_context_destroy( ictx );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст структуры struct mac в значения, определяемые
    заданным контекстом `mctx` алгоритма выработки имитовставки MGM.
    При этом, владение контекстом `mctx` не происходит (в частности не происходит его удаление).

    @param ictx Указатель на структуру struct mac.
    @param mctx Контекст алгоритма выработки имитовставки MGM; контекст должен быть
    предварительно инициализирован.
    @return В случае успеха возвращается \ref ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_create_mgm( ak_mac ictx, ak_mgm mctx )
{
  char oid[32];
  int error = ak_error_ok;

 /* вначале, необходимые проверки */
  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to mac context" );
  if( mctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to mgm context" );
 /* теперь собственно инициализация */
  if(( ictx->data = (ak_uint8 *) malloc( ictx->bsize = mctx->bkey.bsize )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                     "wrong memory alllocation for a new temporary data buffer" );
  } else memset( ictx->data, 0, mctx->bkey.bsize );
  ictx->length = 0;

 /* устанавливаем значения и полей и методы из контекста функции хеширования */
  ictx->engine = mgm_function;
  ictx->ctx = mctx;
  ictx->hsize = ictx->bsize; /* длина вызода совпадает с длиной входа */
  ictx->clean = ak_mgm_context_clean;
  ictx->update = ak_mgm_context_update;
  ictx->finalize = ak_mgm_context_finalize;
  ictx->free = NULL;

 /* формируем oid алгоритма, добавляя приставку mac к его имени */
  ak_snprintf( oid, sizeof( oid ), "mac-%s", mctx->bkey.key.oid->name );
  if(( ictx->oid = ak_oid_context_find_by_name( oid )) == NULL ) {
    error = ak_error_get_value();
    ak_mac_context_destroy( ictx );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_mac_context_create_oid_common( ak_mac ictx, ak_oid oid, size_t size,
                                                                   ak_function_mac_create *create )
{
  ak_pointer ctx = NULL;
  int error = ak_error_ok;

  /* выделяем память */
   if(( ctx = malloc( size )) == NULL )
     return ak_error_message( ak_error_out_of_memory, __func__ ,
                                           "incorrect memory allocation for mac internal context" );
  /* инициализируем контекст функции хеширования */
   if(( error = (( ak_function_create_object *)oid->func.create )( ctx )) != ak_error_ok ) {
     ctx = (( ak_function_free_object *) oid->func.delete )( ctx );
     return ak_error_message( error, __func__, "incorrect initialization of mac internal context" );
   }
  /* инициализируем контекст сжимающего отображения */
   if(( error = create( ictx, ctx )) != ak_error_ok ) {
     ctx = (( ak_function_free_object *) oid->func.delete )( ctx );
     return ak_error_message( error, __func__, "incorrect initialization of mac internal context" );
   }
  /* на-последок, устанавливаем функцию освобождения контекста хеширования */
   ictx->free = ( ak_function_free_object *) oid->func.delete;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст структуры struct mac. При этом
    для инициализации может использоваться идентификатор
    - алгоритма бесключевого хеширования,
    - алгоритма HMAC,
    - алгоритма выработки имитовставки ГОСТ Р 34.10-2013,
    - алгоритма выработки имитовставки MGM.

    @param ictx Указатель на структуру struct mac.
    @param oid Идентификатор криптографического алгоритма
    @return В случае успеха возвращается \ref ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_create_oid( ak_mac ictx, ak_oid oid )
{
  int error = ak_error_ok;

 /* вначале, необходимые проверки */
  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to mac context" );
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__, "using oid with wrong mode" );

 /* теперь разбираем тип алгоритма */
  switch( oid->engine ) {
    case hash_function: /* создаем бесключевую функцию хеширования */
      if(( error = ak_mac_context_create_oid_common( ictx, oid, sizeof( struct hash ),
                         (ak_function_mac_create*) ak_mac_context_create_hash )) != ak_error_ok )
        return ak_error_message_fmt( error, __func__,
            "incorrect initialization of mac function context with %s hash function", oid->name );
    break;

    case hmac_function: /* создаем ключевую функцию хеширования HMAC */
      if(( error = ak_mac_context_create_oid_common( ictx, oid, sizeof( struct hmac ),
                         (ak_function_mac_create*) ak_mac_context_create_hmac )) != ak_error_ok )
        return ak_error_message_fmt( error, __func__,
            "incorrect initialization of mac function context with %s hmac function", oid->name );
    break;

    case omac_function: /* создаем функцию выработки имитовставки ГОСТ Р 34.13-2015. */
      if(( error = ak_mac_context_create_oid_common( ictx, oid, sizeof( struct omac ),
                         (ak_function_mac_create*) ak_mac_context_create_omac )) != ak_error_ok )
        return ak_error_message_fmt( error, __func__,
            "incorrect initialization of mac function context with %s omac function", oid->name );
    break;

    case mgm_function: /* создаем функцию выработки имитовставки на основе алгоритма MGM. */
      if(( error = ak_mac_context_create_oid_common( ictx, oid, sizeof( struct mgm ),
                         (ak_function_mac_create*) ak_mac_context_create_mgm )) != ak_error_ok )
        return ak_error_message_fmt( error, __func__,
            "incorrect initialization of mac function context with %s omac function", oid->name );
    break;

    default:
          return ak_error_message( ak_error_oid_engine, __func__, "using oid with wrong engine" );
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция уничтожает контекст сжимающего отображения.

  @param ictx Указатель на структуру struct mac.
  @return В случае успеха возвращается \ref ak_error_ok (ноль). В случае возникновения ошибки
  возвращается ее код.                                                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_destroy( ak_mac ictx )
{
  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "destroying null pointer to compress context" );
  if( ictx->data != NULL ) free( ictx->data );
  if( ictx->free != NULL ) ictx->free( ictx->ctx );

  ictx->length =        0;
  ictx->ctx =        NULL;
  ictx->hsize =         0;
  ictx->bsize =         0;
  ictx->clean =      NULL;
  ictx->update =     NULL;
  ictx->finalize =   NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Указатель на структуру struct mac.
    @return Функция всегда возвращает NULL. В случае необходимости, код ошибки может быть получен
    с помощью вызова функции ak_error_get_value().                                                 */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_mac_context_delete( ak_pointer ctx )
{
  if( ctx != NULL ) {
      ak_mac_context_destroy(( ak_mac ) ctx );
      free( ctx );
     } else
         ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to mac context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Указатель на структуру struct mac.
    @return Функция \ref ak_true если присвоение ключа допустимо,
    в противном случае возвращается \ref ak_false.                                                 */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_mac_context_is_iv_settable( ak_mac ictx )
{
   switch( ictx->engine )
  {
    case mgm_function: return ak_true;
    default: return ak_false;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ictx Указатель на контекст сжимающего отображения (структуру struct mac).
    К моменту вызова функции контекст должен быть инициализирован.
    @param iv Указатель на данные, которые будут интерпретироваться в качестве
    инициализационного вектора.
    @param size Размер данных, на которые указывает `iv` (размер в байтах).

    \b Примечание. Большинство алгоритмов выработки имитовставки не требуют наличия
    инициализационного вектора. Для таких алгоритмов функция будет возвращать ошибку.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_set_iv( ak_mac ictx, const ak_pointer iv, const size_t size )
{
  int error = ak_error_ok;
  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to null mac context" );
   switch( ictx->engine )
  {
    case mgm_function:
      error = ak_mgm_context_set_iv(( ak_mgm )ictx->ctx, iv, size );
      break;
    default: return ak_error_message( ak_error_key_usage, __func__,
                                           "using an initial vector for non-specified algorithm" );
  }
  if( error != ak_error_ok ) ak_error_message( error, __func__ ,
                                                         "incorrect assigning an initial vector" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Указатель на структуру struct mac.
    @return Функция \ref ak_true если присвоение ключа допустимо,
    в противном случае возвращается \ref ak_false.                                                 */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_mac_context_is_key_settable( ak_mac ictx )
{
   switch( ictx->engine )
  {
    case hmac_function:
    case omac_function:
    case mgm_function: return ak_true;
    default: return ak_false;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ictx Указатель на контекст сжимающего отображения (структуру struct mac).
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
 int ak_mac_context_set_key( ak_mac ictx, const ak_pointer ptr,
                                                           const size_t size , const bool_t cflag )
{
  int error = ak_error_ok;
  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to null mac context" );
   switch( ictx->engine )
  {
    case hmac_function:
      error = ak_hmac_context_set_key(( ak_hmac )ictx->ctx, ptr, size, cflag );
      break;
    case omac_function:
      error = ak_omac_context_set_key(( ak_omac )ictx->ctx, ptr, size, cflag );
      break;
    case mgm_function:
      error = ak_mgm_context_set_key(( ak_mgm )ictx->ctx, ptr, size, cflag );
      break;
    default: return ak_error_message( ak_error_key_usage, __func__,
                                                           "using a key for non-key mac context" );
  }
  if( error != ak_error_ok ) ak_error_message( error, __func__ ,
                                                        "incorrect assigning a secret key value" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_mac_context_get_oid( ak_mac ictx )
{
  if( ictx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to null mac context" );
    return NULL;
  }
 return ictx->oid;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ictx Указатель на структуру struct mac.
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_clean( ak_mac ictx )
{
  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to null mac context" );
  if( ictx->clean == NULL ) return ak_error_message( ak_error_undefined_function, __func__ ,
                                                             "using an undefined clean function" );
  if( ictx->data != NULL ) memset( ictx->data, 0, ictx->bsize );
  ictx->length = 0;
  ictx->clean( ictx->ctx );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ictx Указатель на структуру struct mac.
    @param in Сжимаемые данные
    @param size Размер сжимаемых данных в байтах. Данное значение может
    быть произвольным, в том числе равным нулю и/или не кратным длине блока обрабатываемых данных
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_update( ak_mac ictx, const ak_pointer in, const size_t size )
{
  ak_uint8 *ptrin = (ak_uint8 *) in;
  size_t quot = 0, offset = 0, newsize = size;

  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to null mac context" );
  if( ictx->update == NULL ) return ak_error_message( ak_error_undefined_function, __func__ ,
                                                            "using an undefined update function" );
 /* в начале проверяем, есть ли данные во временном буфере */
  if( ictx->length != 0 ) {
   /* если новых данных мало, то добавляем во временный буффер и выходим */
    if(( ictx->length + newsize ) < ictx->bsize ) {
       memcpy( ictx->data + ictx->length, ptrin, newsize );
       ictx->length += newsize;
       return ak_error_ok;
    }
   /* дополняем буффер до длины, кратной bsize */
    offset = ictx->bsize - ictx->length;
    memcpy( ictx->data + ictx->length, ptrin, offset );

   /* обновляем значение контекста функции и очищаем временный буффер */
    ictx->update( ictx->ctx, ictx->data, ictx->bsize );
    memset( ictx->data, 0, ictx->bsize );
    ictx->length = 0;
    ptrin += offset;
    newsize -= offset;
  }

 /* теперь обрабатываем входные данные с пустым временным буффером */
  if( newsize != 0 ) {
    quot = newsize/ictx->bsize;
    offset = quot*ictx->bsize;
   /* обрабатываем часть, кратную величине bsize */
    if( quot > 0 ) ictx->update( ictx->ctx, ptrin, offset );
   /* хвост оставляем на следующий раз */
    if( offset < newsize ) {
      ictx->length = newsize - offset;
      memcpy( ictx->data, ptrin + offset, ictx->length );
    }
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Конечный результат применения сжимающего отображения помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    Внутренняя структура, хранящая промежуточные данные, не очищается. Это позволят повторно вызывать
    функцию finalize к текущему состоянию.

    @param ictx Указатель на структуру struct mac.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть равен значению поля hsize.
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_mac_context_finalize( ak_mac ictx,
                                            const ak_pointer in, const size_t size, ak_pointer out )
{
  if( ictx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to null mac context" );
    return NULL;
  }
  if( ictx->finalize == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ ,
                                                           "using an undefined finalize function" );
    return NULL;
  }

 /* начинаем с того, что обрабатываем все переданные данные */
  ak_mac_context_update( ictx, in, size );
 /* потом обрабатываем хвост, оставшийся во временном буффере, и выходим */
 return ictx->finalize( ictx->ctx, ictx->data, ictx->length, out );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает результат сжимающего отображения в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param ictx Указатель на структуру struct mac.
    @param in Указатель на входные данные для которых вычисляется контрольная сумма
    (имитовставка или хэш-код).
    @param size Размер входных данных в байтах. Если длина равна нулю, то возвращается результат
    применения преобразования к нулевому вектору (константа).
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти должен быть равен значению поля hsize.
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_mac_context_ptr( ak_mac ictx, const ak_pointer in, const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  size_t tail = 0;

  if( ictx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to null mac context" );
    return NULL;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to data" );
    return NULL;
  }

  if(( error = ak_mac_context_clean( ictx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect cleaning of mac context" );
    return NULL;
  }
  if( !size ) return ak_mac_context_finalize( ictx, "", 0, out );

  tail = size%ictx->bsize; /* определяем хвост */
  if(( error = ak_mac_context_update( ictx, in, size - tail )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect updating of mac context" );
    return NULL;
  }
  if( tail ) return ak_mac_context_finalize( ictx, (ak_uint8 *)in + size - tail, tail, out );
   else return ak_mac_context_finalize( ictx, "", 0, out );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет результат сжимающего отображения для заданного файла и помещает
    его в область памяти, на которую указывает out. Если out равен NULL, то функция создает новый
    буффер (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель
    на буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param ictx указатель на структуру struct mac.
    @param filename имя сжимаемого файла
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_compress_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_mac_context_file( ak_mac ictx, const char* filename, ak_pointer out )
{
  int error = ak_error_ok;
  size_t len = 0;
  struct file file;
  ak_uint8 *localbuffer; /* место для локального считывания информации */
  size_t block_size = 4096; /* оптимальная длина блока для Windows пока не ясна */
  ak_buffer result = NULL;

 /* выполняем необходимые проверки */
  if( ictx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to mac context" );
    return NULL;
  }
  if( filename == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to filename" );
    return NULL;
  }
  if(( error = ak_file_open_to_read( &file, filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "incorrect access to file %s", filename );
    return NULL;
  }

 /* для файла нулевой длины результатом будет хеш от нулевого вектора */
  ak_mac_context_clean( ictx );
  if( !file.size ) return ak_mac_context_finalize( ictx, "", 0, out );

 /* готовим область для хранения данных */
  block_size = ak_max( ( size_t )file.blksize, ictx->bsize );
 /* здесь мы выделяем локальный буффер для считывания/обработки данных */
  if((localbuffer = ( ak_uint8 * ) ak_libakrypt_aligned_malloc( block_size )) == NULL ) {
    ak_file_close( &file );
    ak_error_message( ak_error_out_of_memory, __func__ , "memory allocation error for local buffer" );
    return NULL;
  }
 /* теперь обрабатываем файл с данными */
  read_label: len = ( size_t ) ak_file_read( &file, localbuffer, block_size );
  if( len == block_size ) {
    ak_mac_context_update( ictx, localbuffer, block_size ); /* добавляем считанные данные */
    goto read_label;
  } else {
           size_t qcnt = len / ictx->bsize,
                  tail = len - qcnt*ictx->bsize;
           if( qcnt ) ak_mac_context_update( ictx, localbuffer, qcnt*ictx->bsize );
           result = ak_mac_context_finalize( ictx, localbuffer + qcnt*ictx->bsize, tail, out );
         }
 /* очищаем за собой данные, содержащиеся в контексте */
  ak_mac_context_clean( ictx );
 /* закрываем данные */
  ak_file_close( &file );
  free( localbuffer );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Функция используется в протокольных реализациях для
    вычисления значений секретных ключей, зависящих, как от случайных данных, вырабатываемых в
    ходе проткола, так и от заранее распределенных ключей.

    \param uctx Контекст, значение которого обновляется. Как правило, это контекст
    функции хеширования.

    \param kctx Контекст, содержащий в себе секретный ключ, значением которого обновляется
    первый контекст. Как правило, это контекст предварительно распределенного ключа.
    \return В случае успеха функуия вохвращает \re ak_error_ok (ноль). В противном случае,
    функция возвращает код ошибки.                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_update_mac_context_key( ak_mac uctx, ak_mac kctx )
{
  ak_skey skey = NULL;

  if( uctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using a null pointer to updated mac context" );
  if( kctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                "using a null pointer to secret key mac context" );
 /* получаем указатель на секретный ключ */
  switch( kctx->engine ) {
    case hmac_function: skey = ( ak_skey )( &(( ak_hmac )kctx->ctx)->key );
      break;
    case omac_function: skey = ( ak_skey )( &(( ak_omac )kctx->ctx)->bkey.key );
      break;
    case mgm_function: skey = ( ak_skey )( &(( ak_mgm )( kctx->ctx ))->bkey.key );
      break;
    default: return ak_error_message( ak_error_oid_engine, __func__,
                                            "using an unsupported engine for secret key context" );
  }
 return ak_skey_context_mac_context_update( skey, uctx );
}

/* ----------------------------------------------------------------------------------------------- */
/*                        реализация функций внешнего интерфейса                                   */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция принимает на вход строку с именем или идентификатором алгоритма бесключевого
    хэширования или алгоритма вычисления имитовставки,
    и возвращает дескриптор созданного контекста.

    @param ni Имя или идентификатор (строка, содержащая числа с точками) алгоритма
    бесключевого хэширования или вычисления имитовставки. В качестве допустимых имен могут
    выступать те, для которых поле `engine` принимает значения:
     - \ref hash_function
     - \ref hmac_function
     - \ref omac_function
     - \ref mgm_function
     - \ref mac_function
    @param description Строка символов, описывающая создаваемый контекст.
    Может принимать значение NULL.

    @return В случае успеха функция возвращает дескриптор созданного контекста.
    В случае возникновения ошибки возвращается значение \ref ak_error_wrong_handle.                */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_mac_new_oid( const char *ni, const char *description )
{
  ak_mac ctx = NULL;
  int error = ak_error_ok;
  ak_oid oid = ak_oid_context_find_by_ni( ni );

 /* проверяем входной параметр */
  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect value of name/identifier" );
    return ak_error_wrong_handle;
  }
  if( oid->engine == mac_function ) /* по oid однозначно получаем указатель на конструктор */
    return ((ak_function_mac_new_oid *)oid->func.create)( description );

 /* выделяем память и создаем контекст алгоритма итерационного сжатия */
  if(( ctx = malloc( sizeof( struct mac ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "incorrect memory allocation" );
    return ak_error_wrong_handle;
  }
 /* инициализируем контекст */
  if(( error = ak_mac_context_create_oid( ctx, oid )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of mac function context" );
    if( ctx != NULL ) free( ctx );
    return ak_error_wrong_handle;
  }
 /* помещаем контекст в менеджер контекстов и возвращаем полученный дескриптор */
 return ak_libakrypt_add_context( ctx , mac_function , description );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_mac_new_streebog256( const char *description )
{
 return ak_mac_new_oid( "streebog256", description );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_mac_new_streebog512( const char *description )
{
 return ak_mac_new_oid( "streebog512", description );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_mac_new_hmac_streebog256( const char *description )
{
 return ak_mac_new_oid( "hmac-streebog256", description );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_mac_new_hmac_streebog512( const char *description )
{
 return ak_mac_new_oid( "hmac-streebog512", description );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_mac_new_omac_magma( const char *description )
{
 return ak_mac_new_oid( "omac-magma", description );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_mac_new_omac_kuznechik( const char *description )
{
 return ak_mac_new_oid( "omac-kuznechik", description );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_mac_new_mgm_magma( const char *description )
{
 return ak_mac_new_oid( "mgm-magma", description );
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_mac_new_mgm_kuznechik( const char *description )
{
 return ak_mac_new_oid( "mgm-kuznechik", description );
}

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup mac_functions
 *  В данной группе собраны функции внешнего интерфейса, предназначенные для
 *  вычисления итеративных сжимающих отображений, к которым относятся как бесключевые
 *  функции хеширования, так и алгоритмы выработки имитовставки.
 *
 *  Далее тра-ляля и тру-ляля :)
 */

/* ----------------------------------------------------------------------------------------------- */
/*                              функции для тестирования                                           */
/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx Контекст бесключевой функции хеширования. Должен быть инициализирован.
    \param create Функция создания контекста struct mac
    \param data Указатель на сжимаемую область памяти.
    \param size Длина памяти (в байтах).
    \param out Область памяти, куда помещается результат.
    \param generator Контекст генератора псевдо-случайных чисел. Должен быть инициализирован.
    \return Функция возвращает код ошибки.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_mac_test_context_functions_random( ak_pointer ctx, ak_function_mac_create *create,
                                 ak_pointer data, size_t size, ak_pointer out, ak_random generator )
{
  struct mac ictx;
  size_t offset = 0;
  int error = ak_error_ok;

 /* инициализируем контекст итерационного сжатия путем указания ссылки
                                    на объект бесключевого хеширования */
  if(( error = create( &ictx, ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of compress context");

 /* теперь обрабатываем данные последовательными фрагментами случайной длины */
  ak_mac_context_clean( &ictx );
  while( offset < size ) {
    size_t len;
    ak_random_context_random( generator, &len, sizeof( size_t ));
    len %= 256;
    if( offset + len >= size ) len = size - offset;

   /* обновляем внутреннее состояние */
    ak_mac_context_update( &ictx, ((ak_uint8 *)data)+offset, len );
    offset += len;
  }
  ak_mac_context_finalize( &ictx, NULL, 0, out ); /* получаем окончательное значение */

 /* очищаем объекты */
  ak_mac_context_destroy( &ictx );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция проверяет эквивалентность выработки значений всех доступных функций бесключевого
    хеширования с помощью прямого вычисления для данных с известной длиной и с помощью класса
    \ref mac для случайной траектории вычислений.                                             */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_mac_test_hash_functions( void )
{
  struct hash ctx;
  ak_oid oid = NULL;
  ak_uint8 data[4096];
  int error = ak_error_ok;
  struct random generator;
  int audit = ak_log_get_level();

 /* создаем генератор и вырабатываем необходимое количество псевдослучайных данных */
  if(( error = ak_random_context_create_xorshift32( &generator )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of random generator context" );
    return ak_false;
  }
  if(( error = ak_random_context_random( &generator, data, sizeof( data ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of random data");
    goto label_exit;
  }

 /* перебираем все oid в поисках доступных алгоритмов хеширования */
  oid = ak_oid_context_find_by_engine( hash_function );
  while( oid != NULL ) {
    if( oid->mode == algorithm ) {
      ak_uint8 out[128];

      memset( out, 0, 128 );
      if(( error = ak_hash_context_create_oid( &ctx, oid )) == ak_error_ok ) {
         if( ctx.hsize <= 64 ) {
           ak_hash_context_ptr( &ctx, data, sizeof( data ), out );
           if(( error = ak_mac_test_context_functions_random( &ctx,
                                 ( ak_function_mac_create *)ak_mac_context_create_hash,
                                 data, sizeof( data ), out+64, &generator )) == ak_error_ok ) {
             /* здесь данные вычислены и принимается решение о совпадении значений */
              if( ak_ptr_is_equal( out, out+64, ctx.hsize )) {
                if( audit >= ak_log_maximum )
                  ak_error_message_fmt( ak_error_ok, __func__ ,
                                        "mac realization of \"%s\" is Ok", ctx.oid->name );
                } else {
                   char *str = NULL;
                   ak_error_message_fmt( error = ak_error_not_equal_data, __func__ ,
                               "different values for %s and mac function", ctx.oid->name );
                   ak_log_set_message(( str = ak_ptr_to_hexstr( out, ctx.hsize, ak_false ))); free( str );
                   ak_log_set_message(( str = ak_ptr_to_hexstr( out+64, ctx.hsize, ak_false ))); free( str );
                  }
           }
         }
         ak_hash_context_destroy( &ctx );
      } /* конец if context_create */
    } /* конец if алгоритм */
   /* выполняем поиск следующего */
    if( error == ak_error_ok ) oid = ak_oid_context_findnext_by_engine( oid, hash_function );
     else oid = NULL;
  }

 /* очищаем и уничтожаем вспомогательные данные */
  label_exit: memset( data, 0, sizeof( data ));
  ak_random_context_destroy( &generator );
  if( error != ak_error_ok ) return ak_false;

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 static ak_uint64 testkey[4] = { 0x00LL, 0x01LL, 0x02LL, 0x03LL };

/* ----------------------------------------------------------------------------------------------- */
/*! Функция проверяет эквивалентность выработки значений всех доступных ключевыйх функций
    хеширования семейства HMAC с помощью прямого вычисления для данных с известной длиной и
    с помощью класса \ref mac для случайной траектории вычислений.                                 */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_mac_test_hmac_functions( void )
{
  struct hmac ctx;
  ak_oid oid = NULL;
  ak_uint8 data[4096];
  int error = ak_error_ok;
  struct random generator;
  int audit = ak_log_get_level();

 /* создаем генератор и вырабатываем необходимое количество псевдослучайных данных */
  if(( error = ak_random_context_create_xorshift32( &generator )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of random generator context" );
    return ak_false;
  }
  if(( error = ak_random_context_random( &generator, data, sizeof( data ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of random data");
    goto label_exit;
  }

 /* перебираем все oid в поисках алгоритмов hmac */
  oid = ak_oid_context_find_by_engine( hmac_function );
  while( oid != NULL ) {
    if( oid->mode == algorithm ) {
      ak_uint8 out[128];

      memset( out, 0, 128 );
      if(( error = ak_hmac_context_create_oid( &ctx, oid )) == ak_error_ok ) {
         if( ctx.ctx.hsize <= 64 ) {
           ak_hmac_context_set_key( &ctx, testkey, 32, ak_true );
           ak_hmac_context_ptr( &ctx, data, sizeof( data ), out );
           if(( error = ak_mac_test_context_functions_random( &ctx,
                                 ( ak_function_mac_create *) ak_mac_context_create_hmac,
                                 data, sizeof( data ), out+64, &generator )) == ak_error_ok ) {
             /* здесь данные вычислены и принимается решение о совпадении значений */
              if( ak_ptr_is_equal( out, out+64, ctx.ctx.hsize )) {
                if( audit >= ak_log_maximum )
                  ak_error_message_fmt( ak_error_ok, __func__ ,
                                   "mac realization of \"%s\" is Ok", oid->name );
                } else {
                   char *str = NULL;
                   ak_error_message_fmt( error = ak_error_not_equal_data, __func__ ,
                               "different values for %s and mac function", oid->name );
                   ak_log_set_message(( str = ak_ptr_to_hexstr( out, ctx.ctx.hsize, ak_false ))); free( str );
                   ak_log_set_message(( str = ak_ptr_to_hexstr( out+64, ctx.ctx.hsize, ak_false ))); free( str );
                  }
           }
         }
         ak_hmac_context_destroy( &ctx );
      } /* конец if context_create */
    } /* конец if алгоритм */
   /* выполняем поиск следующего */
    if( error == ak_error_ok ) oid = ak_oid_context_findnext_by_engine( oid, hmac_function );
     else oid = NULL;
  }

 /* очищаем и уничтожаем вспомогательные данные */
  label_exit: memset( data, 0, sizeof( data ));
  ak_random_context_destroy( &generator );
  if( error != ak_error_ok ) return ak_false;

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Поскольку при тестировании блочных шифров было проведено тестирование на совпадение с
    эталонными значениями из ГОСТ Р 34.13-2015, здесь проверяется эквивалентность реализации
    для класса bckey (она же используется в omac) и mac.                                           */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_mac_test_omac_functions( void )
{
  size_t i = 0;
  struct mac mctx;
  struct omac octx;
  ak_uint8 data[36], out[16], out1[16];
  ak_oid oid = NULL;
  struct random generator;
  int error = ak_error_ok;

 /* создаем какие-то случайные данные для тестирвоания */
  if( ak_random_context_create_lcg( &generator ) != ak_error_ok )
    memset( data, 127, sizeof( data ));
   else {
          ak_random_context_random( &generator, data, sizeof( data ));
          ak_random_context_destroy( &generator );
        }

 /* основной цикл перебора алгоритмов */
  oid = ak_oid_context_find_by_engine( omac_function );
  while( oid != NULL ) {
    if( oid->mode == algorithm ) {
     /* создаем контексты */
      if(( error = ak_omac_context_create_oid( &octx, oid )) != ak_error_ok ) {
        ak_error_message_fmt( error, __func__,
                                  "incorrect context creation for %s algorithm", oid->name );
        return ak_false;
      }
      if(( error = ak_omac_context_set_key( &octx, testkey, 32, ak_true )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect assigning key value to omac context" );
        ak_omac_context_destroy( &octx );
        return ak_false;
      }
      if(( error = ak_mac_context_create_omac( &mctx, &octx )) != ak_error_ok ) {
        ak_error_message_fmt( error, __func__,
                              "incorrect mac context creation for %s algorithm", oid->name );
        return ak_false;
      }
      if(( error = ak_omac_context_set_key( &octx, testkey, 32, ak_true )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect assigning key value to mac context" );
        ak_omac_context_destroy( &octx );
        ak_mac_context_destroy( &mctx );
        return ak_false;
      }

     /* теперь цикл побайтного перебора случайных данных */
      for( i = 1; i <= sizeof( data ); i++ ){
         ak_omac_context_ptr( &octx, data, i, out );
         ak_mac_context_ptr( &mctx, data, i, out1 );
         if( memcmp( out, out1, mctx.hsize ) != 0 ) {
            char *str = NULL;
            ak_error_message_fmt( error = ak_error_not_equal_data, __func__ ,
              "different values for %s and mac algorithms on iteration %u", oid->name, (unsigned int)i );
            ak_log_set_message(( str = ak_ptr_to_hexstr( out,  mctx.hsize, ak_false ))); free( str );
            ak_log_set_message(( str = ak_ptr_to_hexstr( out1, mctx.hsize, ak_false ))); free( str );
            ak_omac_context_destroy( &octx );
            ak_mac_context_destroy( &mctx );
            return ak_false;
         }
      }

     /* уничтожаем контексты */
      ak_omac_context_destroy( &octx );
      ak_mac_context_destroy( &mctx );
      if( ak_log_get_level() >= ak_log_maximum )
        ak_error_message_fmt( ak_error_ok, __func__ , "mac realization of \"%s\" is Ok", oid->name );
    }
    oid = ak_oid_context_findnext_by_engine( oid, omac_function );
  }

 return ak_true;
}

/*! \todo Необходимо сделать цикл тестов со
    случайными имитовставками, вычисляемыми с помощью класса struct mac. */

/*! -----------------------------------------------------------------------------------------------
    \example example-mac.c
    \example test-internal-mac01.c                                                                 */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_mac.c  */
/* ----------------------------------------------------------------------------------------------- */
