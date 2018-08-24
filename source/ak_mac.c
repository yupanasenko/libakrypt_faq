/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_mac.с                                                                                  */
/*  - содержит реализацию функций итерационного сжатия.                                            */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>
 #include <ak_tools.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст структуры struct mac в значения, определяемые
    заданным контекстом hctx функции хеширования.
    При этом, владение контекстом hctx не происходит (в частности не происходит его удаление).

    @param ictx указатель на структуру struct mac.
    @param hctx контекст бесключевой функции хеширования; контекст должен быть
    предварительно инициализирован.
    @return В случае успеха возвращается \ref ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_create_hash( ak_mac ictx, ak_hash hctx )
{
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
  ictx->ctx = hctx;
  ictx->has_key = ak_false;
  ictx->hsize = hctx->hsize;
  ictx->clean = hctx->clean;
  ictx->update = hctx->update;
  ictx->finalize = hctx->finalize;
  ictx->free = NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст структуры struct mac. При этом используется временно
   создаваемый контекст алгоритма хеширования, определяемый идентификатора алгоритма.

    @param ictx указатель на структуру struct mac.
    @return В случае успеха возвращается \ref ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_context_create_oid( ak_mac ictx, ak_oid oid )
{
  ak_hash hctx = NULL;
  int error = ak_error_ok;

 /* вначале, необходимые проверки */
  if( ictx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to mac context" );
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__, "using oid with wrong mode" );

 /* теперь разбираем тип алгоритма */
  switch( oid->engine ) {
    case hash_function: /* создаем бесключевую функцию хеширования */
    /* выделяем память */
     if(( hctx = malloc( sizeof( struct hash ))) == NULL )
       return ak_error_message( ak_error_out_of_memory, __func__ ,
                                    "incorrect memory allocation for hash function context" );
    /* инициализируем контекст функции хеширования */
      if(( error = (( ak_function_hash_create *)oid->func.create)( hctx )) != ak_error_ok ) {
        hctx = ak_hash_context_delete( hctx );
        return ak_error_message( error, __func__,
                                        "incorrect initialization of hash function context" );
      }
    /* инициализируем контекст сжимающего отображения */
      if(( error = ak_mac_context_create_hash( ictx, hctx )) != ak_error_ok ) {
        hctx = ak_hash_context_delete( hctx );
        return ak_error_message( error, __func__, "incorrect initialization of mac context" );
      }
    /* на-последок, устанавливаем функцию освобождения контекста хеширования */
      ictx->free = ak_hash_context_delete;
    break;

    default: return ak_error_message( ak_error_oid_engine, __func__, "using oid with wrong engine" );
  }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция уничтожает контекст сжимающего отображения.

  @param ictx указатель на структуру struct mac.
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
  ictx->has_key = ak_false;
  ictx->ctx =        NULL;
  ictx->hsize =         0;
  ictx->bsize =         0;
  ictx->clean =      NULL;
  ictx->update =     NULL;
  ictx->finalize =   NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ictx указатель на структуру struct mac.
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
/*! @param ictx указатель на структуру struct mac.
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
/*! @param ictx указатель на структуру struct mac.
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

    @param ictx указатель на структуру struct mac.
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

    @param ictx указатель на структуру struct mac.
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

  if( !ak_file_is_exist( &file, filename, ak_false )) {
    ak_error_message_fmt( ak_error_get_value(), __func__, "incorrect access to file %s", filename );
  }

 /* для файла нулевой длины результатом будет хеш от нулевого вектора */
  ak_mac_context_clean( ictx );
  if( !file.st.st_size ) return ak_mac_context_finalize( ictx, "", 0, out );

 /* готовим область для хранения данных */
  #ifdef _WIN32
    block_size = ak_max( 4096, ictx->bsize );
  #else
    block_size = ak_max( file.st.st_blksize, ictx->bsize );
  #endif
 /* здесь мы выделяем локальный буффер для считывания/обработки данных */
  if((localbuffer = ( ak_uint8 * ) malloc( block_size )) == NULL ) {
    ak_file_close( &file );
    ak_error_message( ak_error_out_of_memory, __func__ , "memory allocation error for local buffer" );
    return NULL;
  }
 /* теперь обрабатываем файл с данными */
 #ifdef _WIN32
  read_label: len = read( file.fd, localbuffer, (unsigned int) block_size );
 #else
  read_label: len = read( file.fd, localbuffer, block_size );
 #endif
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
/*                              функции для тестирования                                           */
/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */
/*! \param ctx Контекст бесключевой функции хеширования. Должен быть инициализирован.
  * \param data Указатель на сжимаемую область памяти.
  * \param size Длина памяти (в байтах).
  * \param out Область памяти, куда помещается результат.
  * \param generator Контекст генератора псевдо-случайных чисел. Должен быть инициализирован.
  * \return Функция возвращает код ошибки.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_mac_test_hash_functions_random( ak_hash ctx,
                                 ak_pointer data, size_t size, ak_pointer out, ak_random generator )
{
  struct mac ictx;
  size_t offset = 0;
  int error = ak_error_ok;

// /* хешируем через итеративное сжатие */
//  ctx->clean( ctx ); /* очищаем объект от предыдущего мусора */
 /* инициализируем контекст итерационного сжатия путем указания ссылки
                                    на объект бесключевого хеширования */
  if(( error = ak_mac_context_create_hash( &ictx, ctx )) != ak_error_ok )
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
    \ref compress для случайной траектории вычислений.                                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_mac_test_hash_functions( void )
{
  struct hash ctx;
  ak_oid oid = NULL;
  ak_uint8 data[4096];
  int error = ak_error_ok;
  struct random generator;
  int audit = ak_log_get_level();

 /* создаем генератор и вырабатываем необходимое количество псевдослучацных данных */
  if(( error = ak_random_context_create_xorshift64( &generator )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of random generator context" );
    return ak_false;
  }
  if(( error = ak_random_context_random( &generator, data, sizeof( data ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of random data");
    goto label_exit;
  }

 /* перебираем все oid в поисках алгоритмов хеширования */
  oid = ak_oid_context_find_by_engine( hash_function );
  while( oid != NULL ) {
    if( oid->mode == algorithm ) {
      ak_uint8 out[128];

      memset( out, 0, 128 );
      if(( error = ak_hash_context_create_oid( &ctx, oid )) == ak_error_ok ) {
         if( ctx.hsize <= 64 ) {
           ak_hash_context_ptr( &ctx, data, sizeof( data ), out );
           if(( error = ak_mac_test_hash_functions_random( &ctx,
                                 data, sizeof( data ), out+64, &generator )) == ak_error_ok ) {
             /* здесь данные вычислены и принимается решение о совпадении значений */
              if( ak_ptr_is_equal( out, out+64, ctx.hsize )) {
                if( audit >= ak_log_maximum )
                  ak_error_message_fmt( ak_error_ok, __func__ ,
                                         "hash algorithm for %s function is Ok", ctx.oid->name );
                } else {
                   char *str = NULL;
                   ak_error_message_fmt( error = ak_error_not_equal_data, __func__ ,
                               "different values for %s and compress function", ctx.oid->name );
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

/*! -----------------------------------------------------------------------------------------------
    \example test-internal-mac01.c                                                                 */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_mac.c  */
/* ----------------------------------------------------------------------------------------------- */
