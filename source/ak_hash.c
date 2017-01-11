/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*   Redistribution and use in source and binary forms, with or without modification, are          */
/*   permitted provided that the following conditions are met:                                     */
/*                                                                                                 */
/*   1. Redistributions of source code must retain the above copyright notice, this list of        */
/*      conditions and the following disclaimer.                                                   */
/*   2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/*      conditions and the following disclaimer in the documentation and/or other materials        */
/*      provided with the distribution.                                                            */
/*   3. Neither the name of the copyright holder nor the names of its contributors may be used     */
/*      to endorse or promote products derived from this software without specific prior written   */
/*      permission.                                                                                */
/*                                                                                                 */
/*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/*   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/*   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL        */
/*   THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, */
/*   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/*   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/*   AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/*   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/*   OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/*                                                                                                 */
/*   ak_hash.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hash.h>
 #include <ak_oid.h>

 #include <errno.h>
 #include <fcntl.h>
 #ifndef _WIN32
  #include <unistd.h>
 #endif
 #include <sys/stat.h>

/* ----------------------------------------------------------------------------------------------- */
/*                               некоторые методы класса ak_hash                                   */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание нового контектса хеширования

   Функция выделяет память под контекст, а также под внутренние данные контекста
   @param data_size Размер внутренних данных контекста в байтах
   @return указатель на контекст или NULL, сли создание контекста произошло неудачно.              */
/* ----------------------------------------------------------------------------------------------- */
 ak_hash ak_hash_new( const size_t data_size )
{
  ak_hash ctx = ( ak_hash ) malloc( sizeof( struct hash ));
  if( ctx == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "incorrect context memory allocation" );
    return NULL;
  }
  if(( ctx->data = malloc( data_size )) == NULL ) {
      ak_error_message( ak_error_create_function, __func__ ,
                                                   "incorrect internal data memory allocation" );
      return ctx = ak_hash_delete( ctx );
  }
  ctx->bsize =     0;
  ctx->hsize =     0;
  ctx->oid =    NULL;
  ctx->clean =  NULL;
  ctx->code =   NULL;
  ctx->update = NULL;
  ctx->final =  NULL;
 return ctx;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param inctx указатель на контекст хеширования
    @return Функция возвращает NULL. В случае возникновения ошибки, функция сохраняет ее код в
    переменной ak_errno.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_hash_delete( ak_pointer inctx )
{
  ak_hash ctx = ( ak_hash )inctx;
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a context" );
  } else {
           if( ctx->data != NULL ) free( ctx->data );
           ctx->bsize =     0;
           ctx->hsize =     0;
           ctx->data =   NULL;
           ctx->oid =    NULL;
           ctx->clean =  NULL;
           ctx->code =   NULL;
           ctx->update = NULL;
           ctx->final =  NULL;
           free( inctx );
         }
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx контекст функции хеширования
    @return функция возвращает количество байт, которые нужны для хранения хешкода. В случае
    возникновения ошибки возвращается ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hash_get_code_size( ak_hash ctx )
{
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a context" );
    return ak_error_null_pointer;
  }
 return ctx->hsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx контекст функции хеширования
    @return функция возвращает количество байт, которые обрабатываются за один такт работы
    сжимающего отображения. В случае возникновения ошибки возвращается ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_hash_get_block_size( ak_hash ctx )
{
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a context" );
    return ak_error_null_pointer;
  }
 return ctx->bsize;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx контекст функции хеширования
    @return функция возвращает указатель на OID. В случае возникновения ошибки, функция сохраняет
    ее код в переменной ak_errno  возвращает NULL.                                                 */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_hash_get_oid( ak_hash ctx )
{
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a context" );
    return NULL;
  }
 return ctx->oid;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет хеш-код от заданной области памяти на которую указывает in. Размер памяти
    задается в байтах в переменной size. Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param ctx Контекст алгоритма хеширования, должен быть отличен от NULL.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен рещультат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_hash_get_code_size().

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений.                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hash_data( ak_hash ctx, const ak_pointer in, const ak_uint64 size, ak_pointer out )
{
  ak_buffer result = NULL;
  ak_uint64 quot = 0, offset = 0;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a context" );
    return NULL;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a data" );
    return NULL;
  }

  /* вычищаем результаты предыдущих вычислений */
  ctx->clean( ctx );
  quot = size/ctx->bsize;
  offset = quot*ctx->bsize;
  /* вызываем, если длина сообщения не менее одного полного блока */
  if( quot > 0 ) ctx->update( ctx, in, offset );
  /* обрабатываем хвост */
  ctx->final( ctx, (unsigned char *)in + offset, size - offset );

  /* проверяем, надо ли выделять память */
  if( out != NULL ) ctx->code( ctx, out );
   else
     if(( result = ak_buffer_new_size( ctx->hsize )) != NULL ) ctx->code( ctx, result->data );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  Функция вычисляет хеш-код от файла, имя которого задается переменной filename.
     Результат вычислений помещается в область памяти,
     на которую указывает out. Если out равен NULL, то функция создает новый буффер
     (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
     буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

  @param ctx Контекст алгоритма хеширования, должен быть отличен от NULL.
  @param filename Указатель на строку, в которой содержится имя файла.
  @param out Область памяти, куда будет помещен рещультат. Память должна быть заранее выделена.
  Размер выделяемой памяти может быть определен с помощью вызова ak_hash_get_code_size().

  @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
  возвращается указатель на буффер, содержащий результат вычислений.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hash_file( ak_hash ctx, const char* filename, ak_pointer out )
{
  int fd = 0;
  struct stat st;
  ak_uint64 len = 0;
  ak_uint8 *localbuffer; /* место для локального считывания информации */
  ak_uint32 block_size = 4096; /* оптимальная длина блока для Windows пока не ясна */
  ak_buffer result = NULL;

  /* выполняем необходимые проверки */
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to a context" );
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
  if( !st.st_size ) return ak_hash_data( ctx, "", 0, out );
  /* готовим область для хранения данных */
  #ifdef _WIN32
    block_size = ak_max( 4096, ctx->bsize );
  #else
    block_size = ak_max( st.st_blksize, ctx->bsize );
  #endif
  if((localbuffer = ( ak_uint8 * ) malloc( block_size )) == NULL ) {
    close( fd );
    ak_error_message( ak_error_out_of_memory, __func__ , "out of memory" );
    return NULL;
  }
  /* теперь обрабатываем файл с данными */
  ctx->clean( ctx );
  read_label: len = read( fd, localbuffer, block_size );
  if( len == block_size ) {
    ctx->update( ctx, localbuffer, block_size ); /* добавляем считанные данные */
    goto read_label;
  } else {
           ak_uint64 qcnt = len / ctx->bsize,
                     tail = len - qcnt*ctx->bsize;
           if( qcnt ) ctx->update( ctx, localbuffer, qcnt*ctx->bsize );
           ctx->final( ctx, localbuffer + qcnt*ctx->bsize, tail );
         }
 /* закрываем данные */
  close(fd);
  free( localbuffer );
 /* проверяем, надо ли выделять память */
  if( out != NULL ) ctx->code( ctx, out );
   else
     if(( result = ak_buffer_new_size( ctx->hsize )) != NULL ) ctx->code( ctx, result->data );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param oid идентификатор алгоритма хеширования
    @return функция возвращает ссылку на контекст алгоритма хеширования. В случае возникновения
    ошибки возвращается NULL, а код ошибки помещается а переменную ak_errno.                      */
/* ----------------------------------------------------------------------------------------------- */
 ak_hash ak_hash_new_oid( ak_oid oid )
{
 if( oid == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to OID" );
   return NULL;
 }
 if( oid->engine != hash_function ) {
     ak_error_message( ak_error_oid_engine, __func__ , "using a not hash function OID" );
     return NULL;
 }

 if( !memcmp( ak_buffer_get_str( oid->name ), "streebog256", 11 )) return ak_hash_new_streebog256();
 if( !memcmp( ak_buffer_get_str( oid->name ), "streebog512", 11 )) return ak_hash_new_streebog512();
 if( !memcmp( ak_buffer_get_str( oid->name ), "gosthash94", 11 )) {
      return ak_hash_new_gosthash94( ak_oids_find_by_name( "id-gosthash94-CryptoPro-A-ParamSet" ));
 }

 ak_error_message( ak_error_undefined_value, __func__ , "using a pointer to undefined OID" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Контекст функции хеширования.
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_clean( ak_hash ctx )
{
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to a context" );
    return ak_error_null_pointer;
  }
  if( ctx->clean == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ ,
                                                     "using an undefined internal function" );
    return ak_error_undefined_function;
  }
  ctx->clean( ctx );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Контекст функции хеширования.
    @param in Хешируемые данные.
    @param size Размер хешируемых данных в байтах. Данное значение не может
    быть произвольным и должно быть кратным длине блока обрабатываемых данных.
    Данная величина может быть получена с помощью вызова функции ak_hash_get_block_size().
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_update( ak_hash ctx, const ak_pointer in, const ak_uint64 size )
{
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to a context" );
    return ak_error_null_pointer;
  }
  if( ctx->update == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ ,
                                                    "using an undefined internal function" );
    return ak_error_undefined_function;
  }
  ctx->update( ctx, in, size );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Контекст функции хеширования.
    @param in Хешируемые данные.
    @param size Размер хешируемых данных в байтах. Данное значение не может
    быть произвольным и должно быть меньше блока обрабатываемых данных.
    Данная величина может быть получена с помощью вызова функции ak_hash_get_block_size().
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_final( ak_hash ctx, const ak_pointer in, const ak_uint64 size )
{
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to a context" );
    return ak_error_null_pointer;
  }
  if( ctx->final == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ ,
                                                     "using an undefined internal function" );
    return ak_error_undefined_function;
  }
  ctx->final( ctx, in, size );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

   @param ctx Контекст алгоритма хеширования, должен быть отличен от NULL.
   @param out Область памяти, куда будет помещен рещультат. Память должна быть заранее выделена.
   Размер выделяемой памяти может быть определен с помощью вызова ak_hash_get_code_size().

   @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
   возвращается указатель на буффер, содержащий результат вычислений.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_hash_get_code( ak_hash ctx, ak_pointer out )
{
  ak_buffer result = NULL;
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to a context" );
    return NULL;
  }
  if( ctx->code == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ ,
                                                     "using an undefined internal function" );
    return NULL;
  }
 /* проверяем, надо ли выделять память */
  if( out != NULL ) ctx->code( ctx, out );
   else
     if(( result = ak_buffer_new_size( ctx->hsize )) != NULL ) ctx->code( ctx, result->data );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-hash.c
    \example example-hash-parts.c
    \example example-hash-oids.c                                                                   */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hash.c  */
/* ----------------------------------------------------------------------------------------------- */
