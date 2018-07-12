/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_compress.h                                                                             */
/*  - содержит реализацию функций, используемых в итеративных алгоритмах сжатия.                   */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_tools.h>
 #include <ak_compress.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значение полей структуры struct compress в значения, определяемые
    заданным контекстом функции хеширования.

    @param comp указатель на структуру struct compress.
    @param hctx контекст бесключевой функции хеширования. контекст должен быть
    предварительно инициализирован.
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_compress_context_create_hash( ak_compress comp, ak_hash hctx )
{
 /* вначале, необходимые проверки */
  if( comp == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                       "using null pointer to compress context" );
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to hash context" );
  if(( hctx->update == NULL ) || ( hctx->finalize == NULL ) || ( hctx->clean == NULL ))
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                                           "using non initialized hash context" );
 /* теперь собственно инициализация */
  if(( comp->data = (ak_uint8 *) malloc( comp->bsize = hctx->bsize )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                     "wrong memory alllocation for a new temporary data buffer" );
  } else memset( comp->data, 0, hctx->bsize );
  comp->length = 0;

 /* устанавливаем значения и полей и методы из контекста функции хеширования */
  comp->ctx = hctx;
  comp->hsize = hctx->hsize;
  comp->clean = hctx->clean;
  comp->update = hctx->update;
  comp->finalize = hctx->finalize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает значения полей структуры struct compress.
    \b Внимание! Удаление и очистка контекста, реализующего вычисления - не производится.

  @param comp указатель на структуру struct compress
  @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
  возвращается ее код.                                                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_compress_context_destroy( ak_compress comp )
{
  if( comp == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "destroying null pointer to compress context" );
  if( comp->data != NULL ) free( comp->data );

  comp->length =      0;
  comp->ctx =      NULL;
  comp->hsize =       0;
  comp->bsize =       0;
  comp->clean =    NULL;
  comp->update =   NULL;
  comp->finalize = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param comp указатель на структуру struct compress
    @return Функция всегда возвращает NULL. В случае необходимости, код ошибки может быть получен
    с помощью вызова функции ak_error_get_value().                                                 */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_compress_context_delete( ak_pointer ctx )
{
  if( ctx != NULL ) {
      ak_compress_context_destroy(( ak_compress ) ctx );
      free( ctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to compress context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param comp указатель на структуру struct compress.
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_compress_context_clean( ak_compress comp )
{
  if( comp == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using a null pointer to null compress context" );
  if( comp->clean == NULL ) return ak_error_message( ak_error_undefined_function, __func__ ,
                                                             "using an undefined clean function" );
  if( comp->data != NULL ) memset( comp->data, 0, comp->bsize );
  comp->length = 0;
  comp->clean( comp->ctx );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param comp указатель на структуру struct compress.
    @param in Сжимаемые данные
    @param size Размер сжимаемых данных в байтах. Данное значение может
    быть произвольным, в том числе равным нулю и/или не кратным длине блока обрабатываемых данных
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_compress_context_update( ak_compress comp, const ak_pointer in, const size_t size )
{
  ak_uint8 *ptrin = (ak_uint8 *) in;
  size_t quot = 0, offset = 0, newsize = size;

  if( comp == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using a null pointer to null compress context" );
  if( comp->update == NULL ) return ak_error_message( ak_error_undefined_function, __func__ ,
                                                            "using an undefined update function" );

 /* в начале проверяем, есть ли данные во временном буфере */
  if( comp->length != 0 ) {
   /* если новых данных мало, то добавляем во временный буффер и выходим */
    if(( comp->length + newsize ) < comp->bsize ) {
       memcpy( comp->data + comp->length, ptrin, newsize );
       comp->length += newsize;
       return ak_error_ok;
    }
   /* дополняем буффер до длины, кратной bsize */
    offset = comp->bsize - comp->length;
    memcpy( comp->data + comp->length, ptrin, offset );

   /* обновляем значение контекста функции и очищаем временный буффер */
    comp->update( comp->ctx, comp->data, comp->bsize );
    memset( comp->data, 0, comp->bsize );
    comp->length = 0;
    ptrin += offset;
    newsize -= offset;
  }

 /* теперь обрабатываем входные данные с пустым временным буффером */
  if( newsize != 0 ) {
    quot = newsize/comp->bsize;
    offset = quot*comp->bsize;
   /* обрабатываем часть, кратную величине bsize */
    if( quot > 0 ) comp->update( comp->ctx, ptrin, offset );
   /* хвост оставляем на следующий раз */
    if( offset < newsize ) {
      comp->length = newsize - offset;
      memcpy( comp->data, ptrin + offset, comp->length );
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

    @param comp указатель на структуру struct compress.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_compress_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_compress_context_finalize( ak_compress comp,
                                            const ak_pointer in, const size_t size, ak_pointer out )
{
  if( comp == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                  "using a null pointer to null compress context" );
    return NULL;
  }
  if( comp->finalize == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ ,
                                                           "using an undefined finalize function" );
    return NULL;
  }

 /* начинаем с того, что обрабатываем все переданные данные */
  ak_compress_context_update( comp, in, size );
 /* потом обрабатываем хвост, оставшийся во временном буффере, и выходим */
 return comp->finalize( comp->ctx, comp->data, comp->length, out );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет результат сжимающего отображения для заданного файла и помещает
    его в область памяти, на которую указывает out. Если out равен NULL, то функция создает новый
    буффер (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель
    на буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param comp указатель на структуру struct compress.
    @param filename имя сжимаемого файла
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_compress_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_compress_context_file( ak_compress comp, const char* filename, ak_pointer out )
{
  size_t len = 0;
  struct file file;
  ak_uint8 *localbuffer; /* место для локального считывания информации */
  size_t block_size = 4096; /* оптимальная длина блока для Windows пока не ясна */
  ak_buffer result = NULL;

 /* выполняем необходимые проверки */
  if( comp == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to compress context" );
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
  ak_compress_context_clean( comp );
  if( !file.st.st_size ) return ak_compress_context_finalize( comp, "", 0, out );

 /* готовим область для хранения данных */
  #ifdef _WIN32
    block_size = ak_max( 4096, comp->bsize );
  #else
    block_size = ak_max( file.st.st_blksize, comp->bsize );
  #endif
 /* здесь мы выделяем локальный буффер для считывания/обработки данных */
  if((localbuffer = ( ak_uint8 * ) malloc( block_size )) == NULL ) {
    ak_file_close( &file );
    ak_error_message( ak_error_out_of_memory, __func__ , "out of memory" );
    return NULL;
  }
 /* теперь обрабатываем файл с данными */
 #ifdef _WIN32
  read_label: len = read( file.fd, localbuffer, (unsigned int) block_size );
 #else
  read_label: len = read( file.fd, localbuffer, block_size );
 #endif
  if( len == block_size ) {
    ak_compress_context_update( comp, localbuffer, block_size ); /* добавляем считанные данные */
    goto read_label;
  } else {
           size_t qcnt = len / comp->bsize,
                  tail = len - qcnt*comp->bsize;
           if( qcnt ) ak_compress_context_update( comp, localbuffer, qcnt*comp->bsize );
           result = ak_compress_context_finalize( comp, localbuffer + qcnt*comp->bsize, tail, out );
         }
 /* очищаем за собой данные, содержащиеся в контексте */
  ak_compress_context_clean( comp );
 /* закрываем данные */
  ak_file_close( &file );
  free( localbuffer );
 return result;
}

/*! -----------------------------------------------------------------------------------------------
    \example example-internal-compress01.c

 * ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_compress.c */
/* ----------------------------------------------------------------------------------------------- */
