/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hashrnd.c                                                                              */
/*  - содержит реализацию алгоритма бесключевого хэширования, регламентируемого ГОСТ Р 34.11-2012  */
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
 #include <ak_hash.h>
 #include <ak_mpzn.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения внутренних состояний генератора hashrnd. */
 typedef struct random_hashrnd {
  /*! \brief структура используемой бесключевой функции хеширования */
   struct hash ctx;
  /*! \brief текущее значение счетчика обработанных блоков */
   ak_mpzn512 counter;
  /*! \brief массив выработанных значений */
   ak_uint8 buffer[64];
  /*! \brief текущее количество доступных для выдачи октетов */
   size_t len;
 } *ak_random_hashrnd;

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd Контекст генератора.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_hashrnd_next( ak_random rnd )
{
  ak_random_hashrnd hrnd = NULL;
  ak_mpzn512 one = ak_mpzn512_one;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                    "use a null pointer to a random generator" );
 /* получаем указатель и вырабатываем новый вектор значений */
  hrnd = ( ak_random_hashrnd )rnd->data;
  if( hrnd->len != 0 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                             "unexpected use of next function" );
 /* увеличиваем счетчик */
  ak_mpzn_add( hrnd->counter, hrnd->counter, one, ak_mpzn512_size );
 /* вычисляем новое хеш-значение */
  ak_hash_context_ptr( &hrnd->ctx, hrnd->counter, 64, hrnd->buffer );
 /* определяем доступный объем данных для считывания */
  hrnd->len = hrnd->ctx.hsize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr Указатель на область внутренних данных генератора.                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_random_hashrnd_free( ak_pointer ptr )
{
  int error = ak_error_ok;
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "freeing a null pointer to data" );
    return;
  }
 /* уничтожаем контекст функции хеширования */
  if(( error = ak_hash_context_destroy( &(( ak_random_hashrnd )ptr)->ctx )) != ak_error_ok )
     ak_error_message( error, __func__ , "wrong destroying internal hash function context" );
 /* теперь уничтожаем собственно структуру hashrnd */
  free(ptr);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param rnd Контекст генератора.
    \param ptr Указатель на область данных, которыми инициалиируется генератор
    \param size Размер области в байтах
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_hashrnd_randomize_ptr( ak_random rnd,
                                                          const ak_pointer ptr, const ssize_t size )
{
  ak_random_hashrnd hrnd = NULL;
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "use a null pointer to a random generator" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                   "use a null pointer to data" );
  if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                 "use a data with wrong length" );
 /* восстанавливаем начальное значение */
  hrnd = ( ak_random_hashrnd )rnd->data;
  hrnd->len = 0;
  memset( hrnd->counter, 0, 64 );
  memset( hrnd->buffer, 0, 64 );

 /* теперь вырабатываем 47 октетов начального заполнения */
  if(( size <= 47 ) || ( hrnd->ctx.hsize > 64 ))
    memcpy( hrnd->counter+2, ptr, (size_t)ak_min( size, 47 ));
   else {
          ak_uint8 buffer[64];  /* промежуточный буффер */
          memset( buffer,  0x11, 64 );
          ak_hash_context_ptr( &hrnd->ctx, ptr, (size_t)size, buffer );
          memcpy( hrnd->counter+2, buffer, 47 );
   }
 /* вычисляем псевдо-случайные данные */
  ak_random_hashrnd_next( rnd );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param rnd Контекст генератора.
    \param ptr Указатель на область памяти, в которую помещаются вырабатываемые значения
    \param size Размер области в байтах
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_hashrnd_random( ak_random rnd, const ak_pointer ptr, const ssize_t size )
{
  ak_uint8 *inptr = ptr;
  ssize_t realsize = size;
  ak_random_hashrnd hrnd = NULL;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "use a null pointer to a random generator" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                   "use a null pointer to data" );
  if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                 "use a data with wrong length" );
  hrnd = ( ak_random_hashrnd )rnd->data;
  while( realsize > 0 ) {
    size_t offset = ak_min( (size_t)realsize, hrnd->len );
    memcpy( inptr, hrnd->buffer + (hrnd->ctx.hsize - hrnd->len), offset );
    inptr += offset;
    realsize -= offset;
    if(( hrnd->len -= offset ) <= 0 ) /* вычисляем следующий массив данных */
      ak_random_hashrnd_next( rnd );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функия создает генератор, вырабатывающий последовательность псевдо-случайных данных с
    использованием бесключевой функции хеширования согласно рекомендациям по
    стандартизации Р 1323565.1.006-2017.
    Параметр oid задает используемый алгоритм хеширования.

    \param generator контекст инициализируемого генератора псевдо-случайных чисел.
    \param oid идентификатор бесключевой функции хеширования.
    \return Функция возвращает код ошибки.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_context_create_hashrnd_oid( ak_random generator, ak_oid oid )
{
  struct random rnd;
  int error = ak_error_ok;
  ak_random_hashrnd hrnd = NULL;
  char oidname[32]; /* имя для oid генератора псевдо-случайных чисел */

  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to hash function OID" );
 /* проверяем, что OID от бесключевой функции хеширования */
  if( oid->engine != hash_function )
    return ak_error_message( ak_error_oid_engine, __func__ , "using oid with wrong engine" );
 /* проверяем, что OID от алгоритма, а не от параметров */
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__ , "using oid with wrong mode" );

 /* создаем генератор */
  if(( error = ak_random_context_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  if(( hrnd = generator->data = malloc( sizeof( struct random_hashrnd ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
              "incorrect memory allocation for an internal variables of random generator" );

  /* инициализируем поля и данные внутренней структуры данных */
   if(( error = ak_hash_context_create_oid( &hrnd->ctx, oid )) != ak_error_ok ) {
     ak_random_context_destroy( generator );
     return ak_error_message( error, __func__ ,
                                   "incorrect creation of internal hash function context" );
   }
   hrnd->len = 0;
   memset( hrnd->counter, 0, 64 );
   memset( hrnd->buffer, 0, 64 );
   ak_snprintf( oidname, 30, "hashrnd-%s", oid->name );

   generator->oid = ak_oid_context_find_by_name( oidname );
   generator->next = ak_random_hashrnd_next;
   generator->randomize_ptr = ak_random_hashrnd_randomize_ptr;
   generator->random = ak_random_hashrnd_random;
   generator->free = ak_random_hashrnd_free;

 /* для корректной работы присваиваем какое-то случайное начальное значение,
    используя для этого другой генератор псевдо-случайных чисел */

#if defined(__unix__) || defined(__APPLE__)
   error = ak_random_context_create_urandom( &rnd );
#else
   error = ak_random_context_create_xorshift32( &rnd );
#endif
   if( error != ak_error_ok ) {
     ak_random_context_destroy( generator );
     return ak_error_message( error, __func__ ,
                                "incorrect creation of internal random generator context" );
   }
  /* константа 47 означает, что младшие 16 октетов вектора (область изменения счетчика)
     останутся нулевыми, также как и один старший октет (согласно рекомендациям Р 1323565.1.006-2017) */
   ak_random_context_random( &rnd, hrnd->counter+2, 47 );
   ak_random_context_destroy( &rnd );
  /* вычисляем псевдо-случайные данные */
   ak_random_hashrnd_next( generator );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param generator контекст инициализируемого генератора псевдо-случайных чисел.                 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_context_create_hashrnd_streebog256( ak_random generator )
{
  return ak_random_context_create_hashrnd_oid( generator,
                                                     ak_oid_context_find_by_name( "streebog256" ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param generator контекст инициализируемого генератора псевдо-случайных чисел.                 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_context_create_hashrnd_streebog512( ak_random generator )
{
  return ak_random_context_create_hashrnd_oid( generator,
                                                     ak_oid_context_find_by_name( "streebog512" ));
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_hashrnd.c  */
/* ----------------------------------------------------------------------------------------------- */
