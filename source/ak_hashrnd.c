/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_hashrnd.c                                                                              */
/*  - содержит реализацию алгоритма бесключевого хэширования, регламентируемого ГОСТ Р 34.11-2012  */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hash.h>
 #include <ak_random.h>

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
/*! \brief Класс для хранения внутренних состояний генератора hashrnd. */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct hashrnd {
  /*! \brief Структура используемой бесключевой функции хеширования */
   struct hash hctx;
  /*! \brief Текущее значение счетчика обработанных блоков */
   ak_uint8 counter[64];
  /*! \brief Массив выработанных значений */
   ak_uint8 buffer[64];
  /*! \brief Текущее количество доступных для выдачи октетов */
   size_t len;
 } *ak_hashrnd;


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция вычисяет следующее внутреннее состояние генератора.
    \param rnd Контекст генератора.
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_context_next_hashrnd( ak_random rnd )
{
  size_t idx = 0;
  ak_uint8 carry = 0;
  ak_hashrnd hrnd = NULL;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                    "use a null pointer to a random generator" );
 /* получаем указатель и вырабатываем новый вектор значений */
  hrnd = ( ak_hashrnd ) rnd->data.ctx;
  if( hrnd->len != 0 ) return ak_error_message( ak_error_wrong_length, __func__,
                                            "unexpected value of internal variable \"length\"" );
 /* увеличиваем счетчик */
  hrnd->counter[0]++;
  do {
       carry = hrnd->counter[idx++] > 0 ? 0 : 1;
       hrnd->counter[idx] += carry;
  } while( carry );
  hrnd->counter[63] = 0;

 /* вычисляем новое хеш-значение */
  ak_hash_context_ptr( &hrnd->hctx, hrnd->counter, 64, hrnd->buffer, 64 );
 /* определяем доступный объем данных для считывания */
  hrnd->len = 64;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param rnd Контекст генератора.
    \param ptr Указатель на область данных, которыми инициалиируется генератор
    \param size Размер области в байтах
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_context_randomize_hashrnd( ak_random rnd,
                                                       const ak_pointer ptr, const ssize_t size )
{
  ak_hashrnd hrnd = NULL;
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                             "use a null pointer to a random generator context" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                   "use a null pointer to data" );
  if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                 "use a data with wrong length" );
 /* восстанавливаем начальное значение */
  hrnd = rnd->data.ctx;
  hrnd->len = 0;
  memset( hrnd->counter, 0, 64 );
  memset( hrnd->buffer, 0, 64 );

 /* теперь вырабатываем начальное заполнение */
  ak_hash_context_ptr( &hrnd->hctx, ptr, (size_t)size, hrnd->counter, 64 );
  hrnd->counter[63] = 0;

 /* вычисляем псевдо-случайные данные */
  return rnd->next( rnd );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param rnd Контекст генератора.
    \param ptr Указатель на область памяти, в которую помещаются вырабатываемые значения
    \param size Размер области в байтах
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_context_random_hashrnd( ak_random rnd,
                                                          const ak_pointer ptr, const ssize_t size )
{
  ak_uint8 *inptr = ptr;
  ak_hashrnd hrnd = NULL;
  ssize_t realsize = size;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "use a null pointer to a random generator" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                   "use a null pointer to data" );
  if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                 "use a data with wrong length" );
  hrnd = ( ak_hashrnd )rnd->data.ctx;
  while( realsize > 0 ) {
    size_t offset = ak_min( (size_t)realsize, hrnd->len );
    if( offset > 64 ) return ak_error_message( ak_error_undefined_value , __func__ ,
                                                    "incorrect value of internal buffer offset" );
    memcpy( inptr, hrnd->buffer + (64 - hrnd->len), offset );
    inptr += offset;
    realsize -= offset;
   /* вычисляем следующий массив данных */
    if(( hrnd->len -= offset ) <= 0 ) rnd->next( rnd );
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr Указатель на область внутренних данных генератора.                                  */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_context_free_hashrnd( ak_random rnd )
{
  int error = ak_error_ok;
  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                            "freeing a null pointer to random generator context" );

 /* уничтожаем контекст функции хеширования */
  if(( error = ak_hash_context_destroy(  ( ak_hash )rnd->data.ctx)) != ak_error_ok )
     ak_error_message( error, __func__ , "wrong destroying internal hash function context" );
 /* теперь уничтожаем собственно структуру hashrnd */
  if( rnd->data.ctx ) free( rnd->data.ctx );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd Контекст создаваемого генератора.
    @return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_context_create_hashrnd( ak_random rnd )
{
  int error = ak_error_ok;
  ak_uint64 qword = ak_random_value(); /* вырабатываем случайное число */

  if(( error = ak_random_context_create( rnd )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  rnd->next = ak_random_context_next_hashrnd;
  rnd->randomize_ptr = ak_random_context_randomize_hashrnd;
  rnd->random = ak_random_context_random_hashrnd;
  rnd->free = ak_random_context_free_hashrnd;

  if(( rnd->data.ctx = malloc( sizeof( struct hashrnd ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                        "incorrect memory allocation for internal variables of random generator" );

  if(( error = ak_hash_context_create_streebog512( &((ak_hashrnd)rnd->data.ctx)->hctx ))
                                                                                != ak_error_ok  ) {
    ak_random_context_destroy( rnd );
    return ak_error_message( error, __func__ , "incorrect creation of streebog512 context" );
  }

  if(( rnd->oid = ak_oid_context_find_by_name( "hashrnd" )) == NULL ) {
    ak_random_context_destroy( rnd );
    return ak_error_message( ak_error_wrong_oid, __func__ ,
                                     "incorrect search internal identifier fo hashrnd generator" );
  }

 /* для корректной работы присваиваем какое-то случайное начальное значение */ 
  return ak_random_context_randomize_hashrnd( rnd, &qword, sizeof( ak_uint64 ));
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_hashrnd.c  */
/* ----------------------------------------------------------------------------------------------- */
