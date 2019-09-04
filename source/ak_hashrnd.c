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
  ak_hashrnd hrnd = NULL;
  ak_mpzn512 one = ak_mpzn512_one;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                    "use a null pointer to a random generator" );
 /* получаем указатель и вырабатываем новый вектор значений */
  hrnd = ( ak_hashrnd ) rnd->data.ctx;
  if( hrnd->len != 0 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                             "unexpected use of next function" );
 /* увеличиваем счетчик */
  ak_mpzn_add( hrnd->counter, hrnd->counter, one, ak_mpzn512_size );
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

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param rnd Контекст создаваемого генератора.
    @return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_context_create_hashrnd( ak_random rnd )
{
  ak_hashrnd hrnd = NULL;
  int error = ak_error_ok;
   ak_uint64 qword = ak_random_value(); /* вырабатываем случайное число */

  if(( error = ak_random_context_create( rnd )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  if(( hrnd = rnd->data.ctx = malloc( sizeof( struct hashrnd ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                        "incorrect memory allocation for internal variables of random generator" );

  if(( error = ak_hash_context_create_streebog512( hrnd->hctx )) != ak_error_ok  ) {
    ak_random_context_destroy( rnd );
    return ak_error_message( error, __func__ , "incorrect creation of streebog512 context" );
  }

  if(( rnd->oid = ak_oid_context_find_by_name( "hashrnd" )) == NULL ) {
    ak_random_context_destroy( rnd );
    return ak_error_message( ak_error_wrong_oid, __func__ ,
                                     "incorrect search internal identifier fo hashrnd generator" );
  }

  rnd->next = ak_random_context_next_hashrnd;
  rnd->randomize_ptr = ak_random_context_randomize_hashrnd;
  rnd->random = ak_random_context_random_hashrnd;
  rnd->free = ak_random_context_free_hashrnd;

 /* для корректной работы присваиваем какое-то случайное начальное значение */
  ak_random_context_randomize_hashrnd( rnd, &qword, sizeof( ak_uint64 ));
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_hashrnd.c  */
/* ----------------------------------------------------------------------------------------------- */
