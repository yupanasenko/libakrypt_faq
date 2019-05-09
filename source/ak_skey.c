/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_skey.h                                                                                 */
/*  - содержит реализации функций, предназначенных для хранения и обработки ключевой информации.   */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_TIME_H
 #include <time.h>
#else
 #error Library cannot be compiled without time.h header
#endif
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

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует поля структуры, выделяя для этого необходимую память. Всем полям
    присваиваются значения по-умолчанию.

    После создания, указатели на методы cекретного ключа инициализируются для
    работы с аддитивной по модулю 2 маской (наложение маски с помощью операции `xor`).
    В случае необходимости использования другого способа маскирования,
    функции должны переопределяться в производящих функциях для конктерного типа секретного ключа.

    \b Внимание! Остаются неопределенными поля `data`, `resource` и `oid`.
    Перечисленные поля и методы также должны определяться производящими функциями.

    @param skey контекст (структура struct skey) секретного ключа. Память под контекст
    должна быть выделена заранее.
    @param size размер секретного ключа в байтах
    @param isize размер контрольной суммы ключа в байтах
    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_create( ak_skey skey, size_t size, size_t isize )
{
  int error = ak_error_ok;
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                              "using a zero length for key size" );
  if( isize == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                        "using a zero length for integrity code" );
 /* Инициализируем данные базовыми значениями */
  if(( error = ak_buffer_create_function_size( &skey->key,
                       /* в настоящий момент для выделения памяти используются стандартные функции */
                                    ak_libakrypt_aligned_malloc, free, size )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a secret key buffer" );
    ak_skey_context_destroy( skey );
    return error;
  }
  if(( error = ak_buffer_create_size( &skey->mask, size )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a key mask buffer" );
    ak_skey_context_destroy( skey );
    return error;
  }
  if(( error = ak_buffer_create_size( &skey->icode, isize )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a integrity code buffer" );
    ak_skey_context_destroy( skey );
    return error;
  }
  skey->data = NULL;
  memset( &(skey->resource), 0, sizeof( union resource ));

 /* инициализируем генератор масок */
  if(( error = ak_random_context_create_xorshift32( &skey->generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of random generator" );
    ak_skey_context_destroy( skey );
    return error;
  }

 /* номер ключа генерится случайным образом; изменяется позднее, например,
                                                           при считывания с файлового носителя */
  if(( error = ak_buffer_create_size( &skey->number,
                (const size_t) ak_libakrypt_get_option( "key_number_length" ))) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation key number buffer" );
    ak_skey_context_destroy( skey );
    return error;
  }
  if(( error = ak_skey_context_set_unique_number( skey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid creation of key number" );
    ak_skey_context_destroy( skey );
    return error;
  }

  /* OID ключа устанавливается производящей функцией */
  skey->oid = NULL;
  /* После создания ключа все его флаги не определены */
  skey->flags = skey_flag_undefined;
 /* В заключение определяем указатели на методы.
    по умолчанию используются механизмы для работы с аддитивной по модулю 2 маской.

    Внимание: указатели на функции, отличные от данных, должны устанавливаться при создании
    конкретного типа ключа, например, конкретного алгоритма блочного шифрования */
  skey->set_mask = ak_skey_context_set_mask_xor;
  skey->unmask = ak_skey_context_unmask_xor;
  skey->set_icode = ak_skey_context_set_icode_xor;
  skey->check_icode = ak_skey_context_check_icode_xor;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция удаляет все выделенную память и уничтожает хранившиеся в ней значения.

    @param skey контекст секретного ключа
    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_destroy( ak_skey skey )
{
  int error = ak_error_ok;
  ak_uint8 data[sizeof( struct skey )];

  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                             __func__ , "destroying a null pointer to secret key" );
 /* готвим маску */
  if(( error = ak_random_context_random( &skey->generator,
                                                  data, sizeof( struct skey ))) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of random data" );
    memset( data, 0, sizeof( struct skey ));
  }
 /* удаляем данные */
  ak_buffer_wipe( &(skey->key), &skey->generator );
  ak_buffer_destroy( &(skey->key ));

  ak_buffer_wipe( &(skey->mask), &skey->generator );
  ak_buffer_destroy( &(skey->mask ));

  ak_buffer_wipe( &(skey->icode), &skey->generator );
  ak_buffer_destroy( &(skey->icode ));

  ak_random_context_destroy( &skey->generator );
  if( skey->data != NULL ) {
   /* при установленном флаге прамять не очищаем */
    if( !((skey->flags)&skey_flag_data_not_free )) free( skey->data );
  }
  ak_buffer_destroy( &skey->number );
  skey->oid = NULL;
  skey->flags = skey_flag_undefined;

 /* замещаем ключевый данные произвольным мусором */
  memcpy( skey, data, sizeof( struct skey ));
  memset( data, 0, sizeof( struct skey ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Выработанный функцией номер является уникальным (в рамках библиотеки) и однозначно идентифицирует
    секретный ключ. Данный идентификатор может сохраняться вместе с ключом.

    @param skey контекст секретного ключа, для клоторого вырабатывается уникальный номер
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае, возвращается
    номер ошибки.                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_unique_number( ak_skey skey )
{
  time_t tm = 0;
  size_t len = 0;
  struct hash ctx;
  ak_uint8 out[64]; /* размер совпадает с длиной входного блока функции Стрибог256 */
  int error = ak_error_ok;
  const char *version =  ak_libakrypt_version();

 /* стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key" );
  if(( error = ak_hash_context_create_streebog256( &ctx )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong creation of hash function context" );

 /* заполняем стандартное начало вектора */
  memset( out, 0, sizeof( out ));
  len = strlen( version );
  memcpy( out, version, len ); /* сначала версия библиотеки */
  tm = time( NULL );
  memcpy( out+len, &tm, sizeof( tm )); /* потом время генерации номера ключа */
  len += sizeof( time_t );
  if( len < sizeof( out )) { /* используем генератор, отличный от генератора масок */
    struct random generator;
    if( ak_random_context_create_lcg( &generator ) == ak_error_ok ) {
      ak_random_context_random( &generator, out+len, (ssize_t)( sizeof( out ) - len )); /* добавляем мусор */
      ak_random_context_destroy( &generator );
    }
  }

 /* вычисляем номер и очищаем память */
  ak_hash_context_ptr( &ctx, out, sizeof( out ), out );
  ak_hash_context_destroy( &ctx );

  if(( error = ak_buffer_set_ptr( &skey->number,
                          out, ak_min( 32, skey->number.size ), ak_true )) != ak_error_ok )
    return ak_error_message( ak_error_write_data, __func__ , "wrong assigning key number" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Указатель на контекст секретного ключа.
    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_check( ak_skey skey )
{
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to secret key" );
 /* проверяем длину ключа */
  if( skey->key.data == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
 /* проверяем маску */
  if( skey->mask.data == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to mask buffer" );
  if( skey->mask.size != skey->key.size ) return ak_error_message( ak_error_wrong_length,
                                     __func__ , "using mask and key buffer with diffenent sizes" );
 /* проверяем контрольную сумму */
  if( skey->icode.data == NULL ) return ak_error_message( ak_error_null_pointer,
                                               __func__ , "using a null pointer to icode buffer" );
  if( skey->icode.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                         "using a icode buffer with zero length" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает случайный вектор \f$ v \f$ длины, совпадающей с длиной ключа,
    и заменяет значение ключа \f$ k \f$ на величину \f$ k \oplus v \f$.
    Значение вектора \f$ v \f$ сохраняется в буффере `mask`.

    @param skey Указатель на контекст секретного ключа.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_mask_xor( ak_skey skey )
{
  size_t idx = 0;
  ak_uint8 newmask[64];
  int error = ak_error_ok;

 /* выполняем стандартные проверки длин и указателей */
  if(( error = ak_skey_context_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* проверяем, установлена ли маска ранее */
  if( (( skey->flags)&skey_flag_set_mask ) == 0 ) {
    /* создаем маску*/
     if(( error = ak_random_context_random( &skey->generator,
                                    skey->mask.data, (ssize_t)skey->mask.size )) != ak_error_ok )
       return ak_error_message( error, __func__ , "wrong random mask generation for key buffer" );
    /* накладываем маску на ключ */
     for( idx = 0; idx < skey->key.size; idx++ )
        ((ak_uint8 *) skey->key.data)[idx] ^= ((ak_uint8 *) skey->mask.data)[idx];
    /* меняем значение флага */
     skey->flags |= skey_flag_set_mask;

  } else { /* если маска уже установлена, то мы ее сменяем */
            size_t jdx = 0, offset = 0,
                   blocks = skey->mask.size >> 6, /* работаем с блоком длины 64 байта */
                   tail = skey->mask.size - ( blocks << 6 );

           /* сначала обрабатываем полные блоки */
            for( jdx = 0; jdx < blocks; jdx++, offset += 64 ) {
               if(( error = ak_random_context_random( &skey->generator,
                                                                  newmask, 64 )) != ak_error_ok )
               return ak_error_message( error, __func__ ,
                                                  "wrong random mask generation for key buffer" );
               for( idx = 0; idx < 64; idx++ ) {
                  ((ak_uint8 *) skey->key.data)[offset+idx] ^= newmask[idx];
                  ((ak_uint8 *) skey->mask.data)[offset+idx] ^= newmask[idx];
               }
            }
           /* потом обрабатываем хвост */
            if( tail ) {
               if(( error = ak_random_context_random( &skey->generator,
                                                       newmask, (ssize_t)tail )) != ak_error_ok )
               return ak_error_message( error, __func__ ,
                                                  "wrong random mask generation for key buffer" );
               for( idx = 0; idx < tail; idx++ ) {
                  ((ak_uint8 *) skey->key.data)[offset+idx] ^= newmask[idx];
                  ((ak_uint8 *) skey->mask.data)[offset+idx] ^= newmask[idx];
               }
            }
         }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция снимает наложенную ранее маску и оставляет значение ключа в его истинном виде.
    В буффер `mask` помещается нулевое значение.
    @param skey Указатель на контекст секретного ключа.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_unmask_xor( ak_skey skey )
{
  size_t idx = 0;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_context_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* проверяем, установлена ли маска ранее */
  if( (( skey->flags)&skey_flag_set_mask ) == 0 ) return ak_error_ok;

 /* снимаем маску с ключа */
  for( idx = 0; idx < skey->key.size; idx++ ) {
     ((ak_uint8 *) skey->key.data)[idx] ^= ((ak_uint8 *) skey->mask.data)[idx];
     ((ak_uint8 *) skey->mask.data)[idx] = 0;
  }
 /* меняем значение флага */
  skey->flags ^= skey_flag_set_mask;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Нелинейная перестановка в кольце \f$ \mathbb Z_{2^{64}} \f$

    Функция реализует преобразование, которое можно рассматривать как нелинейную
    перестановку \f$ \pi \f$ элементов кольца \f$ \mathbb Z_{2^{64}} \f$, задаваемое следующим образом.

    Пусть \f$ \overline x \f$ есть побитовое инвертирование переменной \f$ x \f$,
    a \f$ f(x,y)\in\mathbb Z[x]\f$ многочлен,
    определяемый равенством \f$ f(x,y) = \frac{1}{2}\left( (x+y)^2 + x + 3y \right)\f$. Тогда
    перестановка \f$ \pi \f$ определяется равенством
    \f$ \pi(x,y) = const \oplus
                    \left\{ \begin{array}{ll}
                              f(x,y), & x+y < 2^{32}, \\
                              \overline{f(\overline{x},\overline{y})}, & 2^{32} \le x+y < 2^{64}.
                            \end{array}
                    \right.\f$

    @param xv Величина \f$ x \in \mathbb Z_{2^{32}} \f$
    @param yv Величина \f$ y \in \mathbb Z_{2^{32}} \f$
    @return Значение перестановки \f$ \pi \f$                                                      */
/* ----------------------------------------------------------------------------------------------- */
 static ak_uint64 ak_skey_context_icode_permutation( const ak_uint32 xv, const ak_uint32 yv )
{
  ak_uint32 x = xv, y = yv, carry = 0;
  ak_uint64 s =  ( ak_uint64 )x + y, more = s&0x100000000, result = 0;

  if( more ) { x = ~x; y = ~y; s = ( ak_uint64 )x + y; }
  result = y; result *= 3; result += x;
  s *= s; result += s; if( result < s ) carry = 1;

  result >>= 1;
  if( carry ) result ^= 0x8000000000000000L;
  if( more ) result = ~result;
 return result^0xC5BF891B4EF6AA79L; // константа есть \sqrt{\pi}
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Реализация алгоритма вычисления контрольной суммы для xor-маски ключа.

    Ключ разбивается на фрагменты длины 128 бит.
    Каждый фрагмент делится на четыре 32-х битных значения \f$ x_1, x_2, x_3, x_4 \f$
    и вычисляется \f$z = \pi( x_1 \oplus x_2, x_3 \oplus x_4 )\f$.
    Данные, не кратные 64 битам, дополняются нулями. В заключение у сумме
    прибавляется длина ключевой  информации.

    Сумма значений $z$, с добавлением \f$ \pi( const, key length)\f$,
    является контрольной суммой.

    @param skey Контекст секретного ключа.
    @param result область памяти, в которую помещается результат.                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_skey_context_icode_xor_sum( ak_skey skey, ak_uint64 *result )
{
  size_t i = 0, blocks = skey->key.size/16;

  *result = 0;
  for( i = 0; i < blocks; i++ ) {
     ak_uint32 x = ((ak_uint32 *) skey->key.data)[i],
               y = ((ak_uint32 *) skey->key.data)[i+2];
               x ^= ((ak_uint32 *) skey->key.data)[i+1];
               y ^= ((ak_uint32 *) skey->key.data)[i+3];
               x ^= ((ak_uint32 *) skey->mask.data)[i];
               x ^= ((ak_uint32 *) skey->mask.data)[i+1];
               y ^= ((ak_uint32 *) skey->mask.data)[i+2];
               y ^= ((ak_uint32 *) skey->mask.data)[i+3];
         *result += ak_skey_context_icode_permutation( x, y );
  }
  *result += ak_skey_context_icode_permutation( 0xf3a21109, (ak_uint32) skey->key.size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Указатель на контекст секретного ключа.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_icode_xor( ak_skey skey )
{
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_context_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* теперь, собственно вычисление контрольной суммы */
  ak_skey_context_icode_xor_sum( skey, skey->icode.data );

 /* устанавливаем флаг */
  skey->flags |= skey_flag_set_icode;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Указатель на контекст секретного ключа.

    @return В случае совпадения контрольной суммы ключа функция возвращает истину (\ref ak_true).
    В противном случае, возвращается ложь (\ref ak_false).                                         */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_skey_context_check_icode_xor( ak_skey skey )
{
  ak_uint64 result = 0;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_context_check( skey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "using invalid secret key" );
    return ak_false;
  }
  if( skey->icode.size != 8 ) {
    ak_error_message( ak_error_wrong_length, __func__ , "wrong length of icode buffer" );
    return ak_false;
  }

 /* теперь, собственно вычисление контрольной суммы */
  ak_skey_context_icode_xor_sum( skey, &result );
 /* и сравнение */
  if( memcmp( skey->icode.data, &result, 8 )) return ak_false;
   else return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                             функции установки ключевой информации                               */
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу заданное значение, размер которого определяется размером секретного
    ключа. В зависимости от значения флага `cflag` при присвоении данные могут копироваться в контекст
    секретного ключа, либо в контекст может передаваться владение указателем на данные.
    В этом случае поведение функции аналогично поведению функции ak_buffer_set_ptr().

    \b Внимание! В процессе работы ключ может изменять свое значение при наложении/изменении маски,
    поэтому если контекст ключа использует внешний буффер (`cflag` = `ak_false`), внешний буффер должен
    быть доступен все время существования ключа. Контроль за существованием внешнего буффера возлагается
    на фрагмент кода, вызывающий данную функцию.

    Основная область применения функции заключается в реализации тестовых примеров, для которых
    значение ключа является заранее известной константой. Другим вариантом использования данной функции
    явлются ситуации, в котрых выработка ключевого значения является результатом некоторого
    криптографического преобразования.

    @param skey Контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    @param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    @param size Размер данных, на которые указывает `ptr` (размер в байтах).
    Если величина `size` меньше, чем размер выделенной памяти под секретный ключ, то копируется
    только `size` байт (остальные заполняются нулями). Если `size` больше, чем количество выделенной памяти
    под ключ, то копируются только младшие байты, в количестве `key.size` байт.

    @param cflag Флаг передачи владения указателем `ptr`. Если `cflag` ложен (принимает значение `ak_false`),
    то физического копирования данных не происходит: внутренний буфер лишь указывает на размещенные
    в другом месте данные, но не владеет ими. Если `cflag` истиннен (принимает значение `ak_true`),
    то происходит выделение памяти и копирование данных в эту память (размножение данных).

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_key( ak_skey skey,
                                     const ak_pointer ptr, const size_t size, const bool_t cflag )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if(( error = ak_skey_context_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using a null pointer to secret key data" );
 /* присваиваем ключ */
  if(( error = ak_buffer_set_ptr( &skey->key, ptr, size, cflag )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong assigning a secret key data" );

 /* очищаем флаг начальной инициализации */
  skey->flags &= (0xFFFFFFFFFFFFFFFFLL ^ skey_flag_set_mask );

 /* проверяем маску */
  if( skey->mask.size != skey->key.size )
    if(( error = ak_buffer_alloc( &skey->mask, size )) != ak_error_ok )
      return ak_error_message( error, __func__ , "incorrect memory allocation for secret key mask" );

 /* маскируем ключ и вычисляем контрольную сумму */
  if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                           __func__ , "wrong secret key masking" );

  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                __func__ , "wrong calculation of integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= skey_flag_set_key;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу случайное (псевдо-случайное) значение, размер которого определяется
    размером секретного ключа. Способ выработки ключевого значения определяется используемым
    генератором случайных (псевдо-случайных) чисел.

    @param skey контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    @param generator контекст генератора псевдо-случайных чисел.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_key_random( ak_skey skey, ak_random generator )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if(( error = ak_skey_context_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using a null pointer to random number generator" );
 /* присваиваем случайный ключ и случайную маску
    тем самым точное значение ключа ни как не фигурирует */
  if(( error =
            ak_random_context_random( generator, skey->key.data, skey->key.size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong generation a secret key" );
  if(( error =
          ak_random_context_random( generator, skey->mask.data, skey->mask.size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong generation a mask" );

 /* меняем значение флага на установленное */
  skey->flags |= skey_flag_set_mask;

  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                 __func__ , "wrong calculation of integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= skey_flag_set_key;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу значение, выработанное из заданного пароля при помощи
    алгоритма PBKDF2, описанного  в рекомендациях по стандартизации Р 50.1.111-2016.
    Пароль должен быть непустой строкой символов в формате utf8.

    Количество итераций алгоритма PBKDF2 определяется опцией библиотеки `pbkdf2_iteration_count`,
    значение которой может быть опредедено с помощью вызова функции ak_libakrypt_get_option().

    @param skey контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    @param pass пароль, представленный в виде строки символов.
    @param pass_size длина пароля в байтах
    @param salt случайный вектор, представленный в виде строки символов.
    @param salt_size длина случайного вектора в байтах

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_set_key_from_password( ak_skey skey,
                                                const ak_pointer pass, const size_t pass_size,
                                                     const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using a null pointer to secret key" );
  if( skey->key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                       "using non initialized secret key context" );
  if( pass == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                               "using a null pointer to password" );
  if( !pass_size ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                              "using a password with zero length" );
 /* присваиваем буффер и маскируем его */
  if(( error = ak_hmac_context_pbkdf2_streebog512( pass, pass_size, salt, salt_size,
                   (const size_t) ak_libakrypt_get_option("pbkdf2_iteration_count"),
                                                 skey->key.size, skey->key.data )) != ak_error_ok )
                  return ak_error_message( error, __func__ , "wrong generation a secret key data" );

 /* очищаем флаг начальной инициализации */
  skey->flags &= (0xFFFFFFFFFFFFFFFFLL ^ skey_flag_set_mask );

  if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                            __func__ , "wrong secret key masking" );
  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                      __func__ , "wrong calculation of secret key integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= skey_flag_set_key;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован ключевым значением.
    @param ictx контекст алгоритма итеративного сжатия. К моменту вызова функции контекст должен
    быть инициализирован.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_mac_context_update( ak_skey skey, struct mac *ictx )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using a null pointer to secret key" );
  if( !(skey->flags&skey_flag_set_key )) return ak_error_message( ak_error_key_value, __func__ ,
                                             "using a secret key context with not assigned value" );
 /* теперь собственно вызов функции обновления контекста */
  skey->unmask( skey );
  error = ak_mac_context_update( ictx, skey->key.data, skey->key.size );
  skey->set_mask( skey );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_skey.c  */
/* ----------------------------------------------------------------------------------------------- */
