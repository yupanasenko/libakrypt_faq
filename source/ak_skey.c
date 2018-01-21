/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_skey.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <time.h>
 #include <ak_tools.h>
 #include <ak_hmac.h>
 #include <ak_bckey.h>
 #include <ak_curves.h>
 #include <ak_compress.h>
 #include <KeyValue.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует поля структуры, выделяя необходимую память. Всем полям
    присваиваются значения по-умолчанию.

    \b Внимание! После создания, указатели на методы cекретного ключа инициализируются для
    работы с аддитивной по модулю 2 маской. В слуае необходимости использования другого способа
    маскирования, функции должны переопределятиься в производящих функциях для конктерного
    типа секретного ключа.

    Кроме того, остаются неопределенными поля data, resource и oid. Перечисленные поля и методы
    также должны определяться далее, в производящих функциях.

    @param skey контекст (структура struct skey) секретного ключа. Память под контекст
    должна быть выделена заранее.
    @param size размер секретного ключа в байтах
    @param isize размер контрольной суммы ключа в байтах
    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_create( ak_skey skey, size_t size, size_t isize )
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
                                               malloc, free,
                                               size )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a secret key buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  if(( error = ak_buffer_create_size( &skey->mask, size )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a key mask buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  if(( error = ak_buffer_create_size( &skey->icode, isize )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a integrity code buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  skey->data = NULL;
  memset( &(skey->resource), 0, sizeof( union resource ));

 /* инициализируем генератор масок */
  if(( error = ak_random_create_lcg( &skey->generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of random generator" );
    ak_skey_destroy( skey );
    return error;
  }

 /* номер ключа генерится случайным образом. изменяется позднее, например,
                                                           при считывания с файлового носителя */
  if(( error = ak_buffer_create_size( &skey->number,
                           ak_libakrypt_get_option( "key_number_length" ))) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation key number buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  if(( error = ak_skey_set_unique_number( skey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid creation of key number" );
    ak_skey_destroy( skey );
    return error;
  }
  /* OID ключа устанавливается производящей функцией */
  skey->oid = NULL;

  /* После создания ключа все его флаги не определены */
  skey->flags = 0;

 /* в заключение определяем указатели на методы.
    по умолчанию используются механизмы для работы с аддитивной по модулю 2 маской.

    Указатели на функции, отличные от данных, должны устанавливаться при создании
    конкретного типа ключа, например, конкретного алгоритма блочного шифрования */
  skey->set_mask = ak_skey_set_mask_xor;
  skey->remask = ak_skey_remask_xor;
  skey->set_icode = ak_skey_set_icode_xor;
  skey->check_icode = ak_skey_check_icode_xor;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция удаляет все выделенную память и уничтожает хранившиеся в ней значения.

    @param skey контекст секретного ключа
    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_destroy( ak_skey skey )
{
  if( skey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "destroying a null pointer to secret key" );
    return ak_error_null_pointer;
  }

 /* удаляем данные */
  ak_buffer_wipe( &(skey->key), &skey->generator );
  ak_buffer_destroy( &(skey->key ));
  memset( &(skey->key), 0, sizeof( struct buffer ));

  ak_buffer_wipe( &(skey->mask), &skey->generator );
  ak_buffer_destroy( &(skey->mask ));
  memset( &(skey->mask), 0, sizeof( struct buffer ));

  ak_buffer_wipe( &(skey->icode), &skey->generator );
  ak_buffer_destroy( &(skey->icode ));
  memset( &(skey->icode), 0, sizeof( struct buffer ));

  ak_random_destroy( &skey->generator );
  if( skey->data != NULL )
   /* удаляем память только при установленном флаге */
    if( !((skey->flags)&ak_skey_flag_data_nonfree )) free( skey->data );

  ak_buffer_destroy( &skey->number );
  skey->oid = NULL;
  memset( &(skey->resource), 0, sizeof( union resource ));
  skey->flags = 0;

 /* обнуляем указатели */
  skey->set_mask = NULL;
  skey->remask = NULL;
  skey->set_icode = NULL;
  skey->check_icode = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Выработанный функцией номер является уникальным (в рамках библиотеки) и однозначно идентифицирует
    секретный ключ. Данный идентификатор может сохраняться вместе с ключом.

    @param key контекст секретного ключа, для клоторого вырабатывается уникальный номер
    @return В случае успеха функция возвращает k_error_ok (ноль). В противном случае, возвращается
    номер ошибки.                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_unique_number( ak_skey skey )
{
  time_t tm = 0;
  size_t len = 0;
  struct hash ctx;
  ak_uint8 out[32];
  int error = ak_error_ok;
  const char *version =  ak_libakrypt_version();

 /* стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key" );
  if(( error = ak_hash_create_streebog256( &ctx )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong creation of hash function context" );

 /* заполняем стандартное начало вектора */
  memset( out, 0, 32 );
  len = strlen( version );
  memcpy( out, version, len ); /* сначала версия библиотеки */
  tm = time( NULL );
  memcpy( out+len, &tm, sizeof(tm) ); /* потом время генерации номера ключа */
  len += sizeof( time_t );
  if( len < 32 ) skey->generator.random( &skey->generator, out+len, 32 - len ); /* добавляем мусор */

 /* вычисляем номер и очищаем память */
  ak_hash_context_ptr( &ctx, out, 32, out );
  if(( error = ak_buffer_set_ptr( &skey->number,
                          out, ak_min( 32, skey->number.size ), ak_true )) != ak_error_ok )
    return ak_error_message( ak_error_write_data, __func__ , "wrong assigning key number" );

  ak_hash_destroy( &ctx );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка параметров контекста секретного ключа

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_check( ak_skey skey )
{
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to secret key" );
 /* проверяем длину ключа */
  if( skey->key.data == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
  if( skey->key.size%8 != 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                          "using a key buffer with wrong length" );
 /* проверяем маску */
  if( skey->mask.data == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->mask.size != skey->key.size ) return ak_error_message( ak_error_wrong_length,
                                     __func__ , "using mask and key buffer with diffenent sizes" );
 /* проверяем контрольную сумму */
  if( skey->icode.data == NULL ) return ak_error_message( ak_error_null_pointer,
                                               __func__ , "using a null pointer to icode buffer" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает случайный вектор \f$ v \f$ длины, совпадающей с длиной ключа,
    и заменяет значение ключа \f$ k \f$ на величину \f$ k \oplus v \f$.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_mask_xor( ak_skey skey )
{
  size_t idx = 0;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* создаем маску*/
  if(( error = skey->generator.random( &skey->generator,
                                           skey->mask.data, skey->mask.size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong mask generation for key buffer" );

 /* накладываем маску на ключ */
  for( idx = 0; idx < ( skey->key.size >> 3 ); idx++ )
     ((ak_uint64 *) skey->key.data)[idx] ^= ((ak_uint64 *) skey->mask.data)[idx];

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает случайный вычет \f$ v \f$ из кольца вычетов \$f \mathbb Z_q\$f
    и заменяет значение ключа \f$ k \f$ на величину \f$ k + v \pmod{q} \f$.
    Величина \f$ q \f$ должна быть простым числом, помещенным в параметры эллиптической кривой,
    на которые указывает `skey->data`.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_mask_ladditive( ak_skey skey )
{
  ak_wcurve wc = NULL;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* создаем маску*/
  if(( error = skey->generator.random( &skey->generator,
                                           skey->mask.data, skey->mask.size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong mask generation for key buffer" );

 /* накладываем маску на ключ */
  if(( wc = ( ak_wcurve ) skey->data ) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                      "using internal null pointer to elliptic curve" );
  ak_mpzn_rem( (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->key.data, wc->q, wc->size );
  ak_mpzn_mul_montgomery( (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->key.data, wc->r2q,
                                                                           wc->q, wc->nq, wc->size);
  ak_mpzn_rem( (ak_uint64 *)skey->mask.data, (ak_uint64 *)skey->mask.data, wc->q, wc->size );
  ak_mpzn_add_montgomery( (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->key.data,
                                                    (ak_uint64 *)skey->mask.data, wc->q, wc->size );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает вектор ключа как последовательность \f$ k_1, \ldots, k_n\f$, состоящую
    из элементов кольца  \f$ \mathbb Z_{2^{32}}\f$. Функция вырабатывает случайный вектор
    \f$ x_1, \ldots, x_n\f$ и заменяет ключевой вектор на последовательность значений
    \f$ k_1 + x_1 \pmod{2^{32}}, \ldots, k_n + x_n \pmod{2^{32}}\f$.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_mask_additive( ak_skey skey )
{
  size_t idx = 0;

  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
 /* проверяем длину ключа */
  if( skey->key.size != 32 ) return ak_error_message( ak_error_undefined_value, __func__ ,
                                                          "using a key buffer with wrong length" );
 /* создаем маску*/
  if( skey->generator.random( &skey->generator, skey->mask.data, skey->mask.size ) != ak_error_ok )
    return ak_error_message( ak_error_write_data, __func__ ,
                                                          "wrong mask generation for key buffer" );
 /* накладываем маску на ключ */
  for( idx = 0; idx < (skey->key.size >> 2); idx++ )
     ((ak_uint32 *) skey->key.data)[idx] += ((ak_uint32 *) skey->mask.data)[idx];

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет новый случайный вектор \f$ v \f$ и изменяет значение
    значение ключа, снимая старую маску и накладывая новую.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_remask_xor( ak_skey skey )
{
  size_t idx = 0;
  ak_uint64 newmask = 0;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* накладываем маску */
  for( idx = 0; idx < ( skey->key.size >> 3 ); idx++ ) {
     if( skey->generator.random( &skey->generator, &newmask, sizeof( ak_uint64 )) == ak_error_ok )
    {
       ((ak_uint64 *) skey->mask.data )[idx] ^= newmask;
       ((ak_uint64 *) skey->key.data)[idx] ^= ((ak_uint64 *) skey->mask.data )[idx];
       ((ak_uint64 *) skey->mask.data )[idx] = newmask;
    } else return ak_error_message( ak_error_undefined_value,
                                                       __func__ , "wrong random mask generation" );
  }

 /* удаляем старое */
  memset( &newmask, 0, sizeof( ak_uint64 ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_remask_ladditive( ak_skey skey )
{
  ak_wcurve wc = NULL;
  int error = ak_error_ok;
  ak_uint64 zeta[ak_mpzn512_size];

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* создаем маску */
  if(( error = skey->generator.random( &skey->generator, zeta, skey->mask.size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong mask generation for key buffer" );

 /* меняем маску */
  if(( wc = ( ak_wcurve ) skey->data ) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                      "using internal null pointer to elliptic curve" );
  ak_mpzn_rem( zeta, zeta, wc->q, wc->size );
  ak_mpzn_sub( skey->mask.data, wc->q, skey->mask.data, wc->size );
  ak_mpzn_add_montgomery( skey->key.data, skey->key.data, zeta, wc->q, wc->size );
  ak_mpzn_add_montgomery( skey->key.data, skey->key.data, skey->mask.data, wc->q, wc->size );
  ak_mpzn_set( skey->mask.data, zeta, wc->size );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет новый случайный вектор \f$ y_1, \ldots, y_n\f$ и изменяет значение
    значение ключа, снимая старую маску и накладывая новую.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_remask_additive( ak_skey skey )
{
  size_t idx = 0;
  ak_uint32 newmask[8];

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( skey->key.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "using undefined key buffer" );
  if( skey->key.size != 32 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                         "key length is too big" );
  if( skey->mask.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                   "using undefined mask buffer" );
 /* вырабатываем случайные данные */
  if( skey->generator.random( &skey->generator, newmask, skey->key.size ) != ak_error_ok )
    return ak_error_message( ak_error_undefined_value, __func__ , "wrong random mask generation" );

 /* накладываем маску */
  for( idx = 0; idx < (skey->key.size >> 2); idx++ ) {
     ((ak_uint32 *) skey->key.data)[idx] += newmask[idx];
     ((ak_uint32 *) skey->key.data)[idx] -= ((ak_uint32 *) skey->mask.data)[idx];
     ((ak_uint32 *) skey->mask.data)[idx] = newmask[idx];
  }

 /* удаляем старое */
  memset( newmask, 0, 32 );
 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Нелинейная перестановка в кольце \f$ \mathbb Z_{2^{64}} \f$

    Функция реализует преобразование, которое можно рассматривать как нелинейную
    перестановку \f$ \pi \f$ элементов кольца \f$ \mathbb Z_{2^{64}} \f$, задаваемое следующим образом.

    Пусть \f$ \overline x \f$ есть побитовое инвертирование переменной x,
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
 static ak_uint64 ak_skey_icode_permutation( const ak_uint32 xv, const ak_uint32 yv )
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
/*! \brief Реализация алгоритма вычисления контрольной суммы для xor-маски ключа */
 static void ak_skey_icode_xor_sum( ak_skey skey, ak_uint64 *result )
{
  size_t i = 0;
  for( i = 0; i < (skey->key.size >> 2); i+=4 ) {
     ak_uint32 x = ((ak_uint32 *) skey->key.data)[i],
               y = ((ak_uint32 *) skey->key.data)[i+2];
     x ^= ((ak_uint32 *) skey->key.data)[i+1];
     y ^= ((ak_uint32 *) skey->key.data)[i+3];
     x ^= ((ak_uint32 *) skey->mask.data)[i];
     x ^= ((ak_uint32 *) skey->mask.data)[i+1];
     y ^= ((ak_uint32 *) skey->mask.data)[i+2];
     y ^= ((ak_uint32 *) skey->mask.data)[i+3];
     *result += ak_skey_icode_permutation( x, y );
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_icode_xor( ak_skey skey )
{
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* теперь, собственно вычисление контрольной суммы */
  ak_skey_icode_xor_sum( skey, (ak_uint64 *)skey->icode.data );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_icode_ladditive( ak_skey skey )
{
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Реализация алгоритма вычисления контрольной суммы для аддитивной маски ключа */
 static void ak_skey_icode_additive_sum( ak_skey skey, ak_uint64 *result )
{
  size_t i = 0;
  for( i = 0; i < (skey->key.size >> 2); i+=4 ) {
     ak_uint32 x = ((ak_uint32 *) skey->key.data)[i],
               y = ((ak_uint32 *) skey->key.data)[i+2];
     x += ((ak_uint32 *) skey->key.data)[i+1];
     y += ((ak_uint32 *) skey->key.data)[i+3];
     x -= ((ak_uint32 *) skey->mask.data)[i];
     x -= ((ak_uint32 *) skey->mask.data)[i+1];
     y -= ((ak_uint32 *) skey->mask.data)[i+2];
     y -= ((ak_uint32 *) skey->mask.data)[i+3];
     *result += ak_skey_icode_permutation( x, y );
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_icode_additive( ak_skey skey )
{
  ak_uint64 result = 0;

  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
 /* проверяем наличие и длину ключа */
  if( skey->key.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "using undefined key buffer" );
  if( skey->key.size != 32 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                          "using a key buffer with wrong length" );
  if( skey->mask.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                   "using undefined mask buffer" );
  if( skey->icode.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                   "using undefined mask buffer" );
  if( skey->icode.size != 8 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                 "using integrity code buffer with wrong length" );

 /* теперь, собственно вычисление контрольной суммы */
  ak_skey_icode_additive_sum( skey, &result );
  memcpy( skey->icode.data, &result, 8 );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае совпадения контрольной суммы ключа функция возвращает истину (\ref ak_true).
    В противном случае, возвращается ложь (\ref ak_false).                                         */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_skey_check_icode_xor( ak_skey skey )
{
  ak_uint64 result = 0;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "using invalid secret key" );
    return ak_false;
  }
  if( skey->icode.size != 8 ) {
    ak_error_message( ak_error_wrong_length, __func__ , "wrong length of icode buffer" );
    return ak_false;
  }

 /* теперь, собственно вычисление контрольной суммы */
  ak_skey_icode_xor_sum( skey, &result );
 /* и сравнение */
  if( memcmp( skey->icode.data, &result, 8 )) return ak_false;
   else return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_skey_check_icode_ladditive( ak_skey skey )
{
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть в точности равна 32.

    @return В случае совпадения контрольной суммы ключа функция возвращает истину (\ref ak_true).
    В противном случае, возвращается ложь (\ref ak_false).                                         */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_skey_check_icode_additive( ak_skey skey )
{
  ak_uint64 result = 0;

  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using a null pointer to secret key" );
 /* проверяем наличие и длину ключа */
  if( skey->key.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                     "using undefined key buffer" );
  if( skey->key.size != 32 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                           "using a key buffer with wrong length" );
  if( skey->mask.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "using undefined mask buffer" );
  if( skey->icode.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "using undefined mask buffer" );
  if( skey->icode.size != 8 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                  "using integrity code buffer with wrong length" );

 /* теперь, собственно вычисление контрольной суммы */
  ak_skey_icode_additive_sum( skey, &result );
 /* и сравнение */
  if( memcmp( skey->icode.data, &result, 8 )) return ak_false;
   else return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу заданное значение, размер которого определяется размером секретного
    ключа. В зависимости от значения флага cflag при присвоении данные могут копироваться в контекст
    секретного ключа, либо в контекст может передаваться владение указателем на данные.
    В этом случае поведение функции аналогично поведению функции ak_buffer_set_ptr().

    \b Внимание! В процессе работы ключ может изменять свое значение при наложении/изменении маски,
    поэтому если контекст ключа использует внешний буффер (cflag == ak_false), внешний буффер должен
    быть доступен все время существования ключа. Контроль за существованием внешнего буффера возлагается
    на фрагмент кода, вызывающий данную функцию.

    Основная область применения функции заключается в реализации тестовых примеров, для которых
    значение ключа является заранее известной константой.

    @param skey Контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    @param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    @param size Размер данных, на которые указывает ptr (размер в байтах).
    Если величина size меньше, чем размер выделенной памяти под секретный ключ, то копируется
    только size байт (остальные заполняются нулями). Если size больше, чем количество выделенной памяти
    под ключ, то копируются только младшие байты, в количестве `key.size` байт.

    @param cflag Флаг передачи владения укзателем ptr. Если cflag ложен (ak_false), то физического
    копирования данных не происходит: внутренний буфер лишь указывает на размещенные в другом месте
    данные, но не владеет ими. Если cflag истиннен (ak_true), то происходит выделение памяти и
    копирование данных в эту память (размножение данных).

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_ptr( ak_skey skey, const ak_pointer ptr, const size_t size, const ak_bool cflag )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using a null pointer to secret key" );
  if( skey->key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                       "using non initialized secret key context" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using a null pointer to secret key data" );
 /* обнуляем ключ и присваиваем буффер */
  memset( skey->key.data, 0, skey->key.size );
  if(( error =
      ak_buffer_set_ptr( &skey->key, ptr, ak_min( size, skey->key.size ), cflag )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong assigning a secret key data" );

 /* маскируем ключ и вычисляем контрольную сумму */
  if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                           __func__ , "wrong secret key masking" );

  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                __func__ , "wrong calculation of integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= ak_skey_flag_set_key;

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
 int ak_skey_set_random( ak_skey skey, ak_random generator )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using a null pointer to secret key" );
  if( skey->key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                       "using non initialized secret key context" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using a null pointer to random number generator" );
 /* присваиваем буффер и маскируем его */
  if(( error = ak_buffer_set_random( &skey->key, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong generation a secret key data" );

  if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                           __func__ , "wrong secret key masking" );
  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                __func__ , "wrong calculation of integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= ak_skey_flag_set_key;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу значение, выработанное из заданного пароля при помощи алгоритма,
    описанного  в рекомендациях по стандартизации Р 50.1.111-2016.
    Пароль должен быть не пустой строкой символов в формате utf8.

    @param skey контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    @param pass пароль, представленный в виде строки символов.
    @param pass_size длина пароля в байтах
    @param salt пароль, представленный в виде строки символов.
    @param salt_size длина пароля в байтах

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_password( ak_skey skey, const ak_pointer pass, const size_t pass_size,
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
  if(( error = ak_hmac_pbkdf2_streebog512( pass, pass_size, salt, salt_size,
                                  ak_libakrypt_get_option("pbkdf2_iteration_count"),
                                                 skey->key.size, skey->key.data )) != ak_error_ok )
                  return ak_error_message( error, __func__ , "wrong generation a secret key data" );

  if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                           __func__ , "wrong secret key masking" );
  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                __func__ , "wrong calculation of integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= ak_skey_flag_set_key;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                    Функциии для сохранения/чтения ключевой информации                           */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Переменная, в которой хранятся указатели на соотвествующие алгоритмы экспорта ключей */
 static struct key_export_algorithms export_algorithms = {
  .cipher = NULL,
  .mode = NULL,
  .mac = NULL
};

/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_create_key_export_algorithms( void )
{
 return ak_libakrypt_set_key_export_algorithm_oids( ak_oid_find_by_name( "magma" ),
                     ak_oid_find_by_name( "counter" ), ak_oid_find_by_name( "hmac-streebog256" ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param cipher дескриптор алгоритма шифрования
    @param mode дескриптор режима шифрования
    @param mac дескриптор алгоритма выработки имитовставки

    @return В случае успеха, возвращается \ref ak_error_ok. В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_set_key_export_algorithm_oids( ak_oid cipher, ak_oid mode, ak_oid mac )
{
 /* проверяем, что oid cipher является блочным шифром */
  if(( cipher->engine == block_cipher ) && ( cipher->mode == algorithm ))
    export_algorithms.cipher = cipher;
   else return ak_error_message( ak_error_oid_engine, __func__,
                   "incorrect initialization of cipher oid in key export algorithms context" );

 /* проверяем, что oid mode является режимом работы блочного шифра */
  if( mode->engine == block_cipher ) {
    switch( mode->mode ) {
     case counter:
     case counter_gost:
     case cfb:
     case ofb:
     case xts:
     case xts_mac: export_algorithms.mode = mode;
                   break;
     default: return ak_error_message( ak_error_oid_mode, __func__,
                                   "using block cipher oid with unsupported encryption mode" );
    }
  }
  else return ak_error_message( ak_error_oid_engine, __func__,
          "incorrect initialization of encryption mode oid in key export algorithms context" );

 /* проверяем, что oid mac является алгоритмом выработки hmac */
  if(( mac->engine == hmac_function ) && ( mac->mode == algorithm ))
    export_algorithms.mac = mac;
   else return ak_error_message( ak_error_oid_engine, __func__,
       "incorrect initialization of authenticated code oid in key export algorithms context" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция для итерационного вычисления сжимающего отображения при der-кодировании.

   Функция передается в качестве параметра в функцию der_encode(), что позволяет
   итеративно вычислять значение сжимающего отображения, как правило, hmac от секретного ключа.
   При этом на вход функции могут подаваться фрагменты произвольного размера.

   @param buffer Указатель на буффер, в котором хранятся обрабатываемые данные
   @param size Размер данных (в байтах)
   @param app_key Указатель на струтуру криптографического преобразования ak_compress
   (может использоваться как для функций хеширования, так и для вычисления имитовставки)

   @return В соответствии с соглашением функции der_encode, данная функция возвращает ноль, если
   все усспешно, и -1 если произошла ошибка. Код ошибки можно получить с помощью вызова функции
   ak_error_get_value().                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_der_encode_update( const void *buffer, size_t size, void *app_key )
{
  return ak_compress_update(
               ( ak_compress )app_key, ( const ak_pointer ) buffer, size ) != ak_error_ok ? -1 : 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Перед преобразованием контекст ключа и структура `SecretKeyData` должны быть инициализированы.
    Контекст ключа должен содержать в себе ключевое значение.

    Для защиты ключа используются алгоритмы, oid которых определены
    структурой \ref export_algotithms. Устанвить поля этой структуры можно с помощью функции
    ak_libakrypt_set_key_export_algorithm_oids().

    @param skey Контекст секретного ключа, который будет преобразован в ASN1 структуру.
    @param pass Пароль, представленный в виде строки символов в формате utf8.
    @param pass_size Длина пароля в байтах.
    @param description Человекочитаемое описание ключа (если описание не определено,
           должен передаваться NULL).

    @return В случае успеха возвращается \ref ak_error_ok. В случае возникновения ошибки
           возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_to_asn1_secret_key_data( ak_skey skey, SecretKeyData_t *secretKeyData,
                            const ak_pointer pass, const size_t pass_size, const char *description )
{
 #define temporary_size (1024)

 ak_uint8 salt[64]; /* массив для хранения случайных инициализационных данных */
 asn_enc_rval_t ec;
 size_t kivsize = 0;
 KeyValue_t keyValue;
 struct hmac hmacKey;
 int error = ak_error_ok;
 OBJECT_IDENTIFIER_t cipher;
 struct bckey encryptionKey; /* ключ шифрования */
 struct compress compressCtx; /* структура для итеративного сжатия */
 ak_uint8 temporary[temporary_size]; /* массив для хранения EncodedKeyValue */

 /* проверяем входные данные */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                        "using null pointer to block cipher key context" );
  if( secretKeyData == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                    "using null pointer to asn1 secretKeyData structure" );

  if( pass == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to password" );
  if( pass_size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                       "using password with zero length" );
  if( skey->key.size + skey->mask.size + 6 > temporary_size )
    return ak_error_message( ak_error_wrong_length, __func__ ,
              "size of internal temporary buffer is smaller than given block cipher key" );
 /* примечание: здесь мы по-умолчанию считаем, что дополнительные данные
    для шифрования в структуре KeyValue отсутствуют. Дополнительные 6 байтов
    требуются для кодирования ASN1 структуры */

  if( export_algorithms.cipher == NULL )
    return ak_error_message( ak_error_undefined_function, __func__,
                                       "using internal null pointer to block cipher oid" );
  if( export_algorithms.mode == NULL )
    return ak_error_message( ak_error_undefined_function, __func__,
                                    "using internal null pointer to encryption mode oid" );
  if( export_algorithms.mac == NULL )
    return ak_error_message( ak_error_undefined_function, __func__,
                                 "using internal null pointer to authenticated code oid" );

 /* очищаем текущее значение ошибки, может быть полезно */
  ak_error_set_value( ak_error_ok );

 /* delme!!!!
   skey->generator.randomize_ptr( &skey->generator, "hello", 5 );
   memset( skey->number.data, 0, skey->number.size ); */

 /* перемаскируем текущее значение сохраняемого ключа */
  if( skey->remask == NULL ) return ak_error_message( ak_error_undefined_function,
                          __func__, "using not masked block cipher key (internal error)" );
    else skey->remask( skey );

 /* вырабатываем случайное значение,
  * которое будет использовано для определения всех инициализационных векторов */
  if(( error = skey->generator.random( &skey->generator, salt, 64 )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong generation a temporary salt value" );

 /* создаем ключ шифрования ключа */
  if(( error = ((ak_function_bckey_create *) export_algorithms.cipher->func )( &encryptionKey )) != ak_error_ok )
    return ak_error_message( error , __func__ ,
                            "wrong initialization of temporary block cipher key context" );

 /* вырабатываем значение ключа из пароля пользователя */
  if(( error = ak_bckey_context_set_password( &encryptionKey, pass, pass_size,
                                                              salt, 16 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong generation a temporary block cipher value" );
    ak_bckey_destroy( &encryptionKey );
    return error;
  }

 /* создаем вектор, содержащий зашифрованное значение ключа и маски, и формируем указатели */
  memset( &keyValue, 0, sizeof( struct KeyValue ));
  keyValue.key.buf = skey->key.data; keyValue.key.size = skey->key.size;
  keyValue.mask.buf = skey->mask.data; keyValue.mask.size = skey->mask.size;

  /* кодируем в DER-представление и отсоединяем указатели на ключевые данные */
  memset( temporary, 0, temporary_size );
  ec = der_encode_to_buffer(  &asn_DEF_KeyValue, &keyValue, temporary, temporary_size );
  skey->remask( skey );
  memset( &keyValue, 0, sizeof( struct KeyValue ));

  if( ec.encoded < 0 ) {
    ak_error_message( error = ak_error_wrong_asn1_encode, __func__,
                                            "incorect KeyValue's ASN1 structure encoding");
    ak_ptr_wipe( temporary, temporary_size, &encryptionKey.key.generator );
    ak_bckey_destroy( &encryptionKey );
    return error;
  }

  /* зашифровываем вектор в режиме гаммирования и уничтожаем ключ защиты */
  if(( error =  ((ak_function_bckey_encrypt *)(( ak_two_pointers ) export_algorithms.mode->data )->direct)
                   ( &encryptionKey, temporary, temporary, ec.encoded,
                        salt+32, kivsize = encryptionKey.ivector.size )) != ak_error_ok )
  {
    ak_error_message( error, __func__, "wrong encryption of temporary buffer" );
    ak_bckey_destroy( &encryptionKey );
    return error;
  }
  ak_bckey_destroy( &encryptionKey );

 /* переходим к формированию ASN1 структуры */
  memset( secretKeyData, 0, sizeof( struct SecretKeyData ));

 /* добавляем зашифрованный ключ */
  if(( error = ak_ptr_to_asn1_octet_string( temporary,
                                ec.encoded, &secretKeyData->data.value )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong assignment a secret key to asn1 structure" );
    goto exit;
  }

 /* устанавливаем engine */
  if(( error = ak_oid_to_asn1_object_identifier( skey->oid,
                   (OBJECT_IDENTIFIER_t *) &secretKeyData->data.engine )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                               "incorrect secret key engine assigning to asn1 structure" );
    goto exit;
  }

 /* устанавливаем номер ключа */
  if(( error = ak_ptr_to_asn1_octet_string( skey->number.data,
                    skey->number.size, &secretKeyData->data.number )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                             "incorrect secret key's number assigning to asn1 structure" );
    goto exit;
  }

 /* устанавливаем ресурс ключа */
  if(( secretKeyData->data.resource = malloc( sizeof( struct KeyResource ))) == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                           "incorrect memory allocation for key resource");
    goto exit;
  } else memset( secretKeyData->data.resource, 0 , sizeof( struct KeyResource ));
  /* TODO: здесь надо проверить, что ресурс содержит либо численное значение,
   * либо временной интервал - в зависимости от типа ключа */
  secretKeyData->data.resource->present = KeyResource_PR_counter;
  secretKeyData->data.resource->choice.counter = skey->resource.counter;

 /* устанавливаем описание ключа
    внимание, оно может быть непредусмотрительно длинным! */
  if( description != NULL ) {
    secretKeyData->data.description = malloc( sizeof( struct OCTET_STRING ));
    memset( secretKeyData->data.description, 0, sizeof( struct OCTET_STRING ));
    if(( error = ak_ptr_to_asn1_octet_string( (void *)description,
                strlen( description ), secretKeyData->data.description )) != ak_error_ok ) {
      ak_error_message( error, __func__,
                        "incorrect secret key's description assigning to asn1 structure" );
      goto exit;
    }
  }

 /* устанавливаем параметры алгоритмов защиты */
  /* 1. число итераций алгоритма PBKDF2 */
  secretKeyData->data.parameters.iterationCount =
                                       ak_libakrypt_get_option( "pbkdf2_iteration_count" );

  /* 2. инициализационный вектор для PBKDF2 (ключ шифрования) */
  if(( error = ak_ptr_to_asn1_octet_string( salt, 16,
                        &secretKeyData->data.parameters.encryptionSalt )) != ak_error_ok ) {
    ak_error_message( error, __func__,
      "incorrect initial vector for PBKDF2 assigning to asn1 structure (encryption key)" );
    goto exit;
  }

  /* 3. режим шифрования и блочный шифр (как параметр алгоритма шифрования) */
  if(( error = ak_oid_to_asn1_object_identifier( export_algorithms.mode,
        (OBJECT_IDENTIFIER_t *) &secretKeyData->data.parameters.encryptionMode.algorithm )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                             "incorrect block cipher engine assigning to asn1 structure" );
    goto exit;
  }

  /* создаем asn1 структуру и кодируем ее в der-представление (помещаем параметры в структуру ANY) */
  memset( &cipher, 0, sizeof( OBJECT_IDENTIFIER_t ));
  if(( error = ak_oid_to_asn1_object_identifier(
                                     export_algorithms.cipher, &cipher )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                                "incorrect assigning block cipher oid to asn1 structure" );
    goto exit;
  }
  secretKeyData->data.parameters.encryptionMode.parameters =
                                   ANY_new_fromType( &asn_DEF_OBJECT_IDENTIFIER, &cipher );
  asn_DEF_OBJECT_IDENTIFIER.free_struct( &asn_DEF_OBJECT_IDENTIFIER, &cipher, 1 );

  if( secretKeyData->data.parameters.encryptionMode.parameters == NULL ) {
    ak_error_message( error, __func__,
                       "incorrect assigning encryptionMode parameters to asn1 structure" );
    goto exit;
  }

  /* 4. инициализационный вектор для режима шифрования */
  if(( error = ak_ptr_to_asn1_octet_string( salt+32, kivsize,
                          &secretKeyData->data.parameters.encryptionIV )) != ak_error_ok ) {
    ak_error_message( error, __func__,
          "incorrect assignment of initial vector for encryption mode to asn1 structure" );
    goto exit;
  }

  /* 5. инициализационный вектор для PBKDF2 (ключ имитозащиты) */
  if(( error = ak_ptr_to_asn1_octet_string( salt+16, 16,
                         &secretKeyData->data.parameters.integritySalt )) != ak_error_ok ) {
    ak_error_message( error, __func__,
       "incorrect initial vector for PBKDF2 assigning to asn1 structure (integrity key)" );
    goto exit;
  }

  /* 6. алгоритм вычисления имитовставки */
  if(( error = ak_oid_to_asn1_object_identifier( export_algorithms.mac,
              (OBJECT_IDENTIFIER_t *) &secretKeyData->data.parameters.integrityMode.algorithm )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                                  "incorrect integrity mode assigning to asn1 structure" );
    goto exit;
  }

  /* создаем asn1 структуру и кодируем ее в der-представление (помещаем параметры в структуру ANY) */
  memset( &cipher, 0, sizeof( OBJECT_IDENTIFIER_t ));
  if(( error = ak_oid_to_asn1_object_identifier(
                                     export_algorithms.cipher, &cipher )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                                "incorrect assigning block cipher oid to asn1 structure" );
    goto exit;
  }
  secretKeyData->data.parameters.integrityMode.parameters =
                                   ANY_new_fromType( &asn_DEF_OBJECT_IDENTIFIER, &cipher );
  asn_DEF_OBJECT_IDENTIFIER.free_struct( &asn_DEF_OBJECT_IDENTIFIER, &cipher, 1 );

  if( secretKeyData->data.parameters.integrityMode.parameters == NULL ) {
    ak_error_message( error, __func__,
                       "incorrect assigning integrityMode parameters to asn1 structure" );
    goto exit;
  }


  /* 8. инициализационный вектор для режима имитозащиты */

 /* вычисляем имитовставку */
  /* 1. формируем ключ имитозащиты */
  if(( error = ((ak_function_hmac_create *) export_algorithms.mac->func )( &hmacKey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of integrity key" );
    goto exit;
  }

  if(( error = ak_hmac_context_set_key_password( &hmacKey,
                                          pass, pass_size, salt+16, 16 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong generation of integrity key value" );
    ak_hmac_destroy( &hmacKey );
    goto exit;
  }

  /* 2. создаем структуру для итеративного вычисления значений функции hmac */
  if(( error = ak_compress_create_hmac( &compressCtx, &hmacKey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong hmac compress structure creation" );
    ak_hmac_destroy( &hmacKey );
    goto exit;
  }

  /* 3. кодируем данные и одновременно вычисляем имитовставку */
  kivsize = hmacKey.ctx.hsize;
  ak_compress_clean( &compressCtx );
  ec = der_encode( &asn_DEF_SecretKey, &secretKeyData->data,
                                             ak_skey_der_encode_update, &compressCtx );
  /* результат вычислений помещается в temporary */
  ak_compress_finalize( &compressCtx, NULL, 0, temporary );
  ak_compress_destroy( &compressCtx );
  ak_hmac_destroy( &hmacKey );

  if( ec.encoded < 0 ) {
    ak_error_message( error = ak_error_wrong_asn1_encode, __func__,
                                                      "wrong integrity code calculation" );
    goto exit;
  }

  /* 4. присваиваем значение */
  if(( error = ak_ptr_to_asn1_octet_string( temporary, kivsize,
                                         &secretKeyData->integrityCode )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                              "incorrect assignment of integrity code to asn1 structure" );
    goto exit;
  }

 /* на-последок, выполняем проверку созданной структуры */
  if( asn_check_constraints( &asn_DEF_SecretKeyData, secretKeyData, NULL, NULL ) < 0 ) {
    ak_error_message( ak_error_wrong_asn1_encode, __func__,
                                              "unsuccessful checking the asn1 structure" );
    goto exit;
  }

 return ak_error_ok;
 exit:
  SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 1 );
 /* так тоже можно освобождать память - более универсальный способ из документации
    asn_DEF_SecretKeyData.free_struct( &asn_DEF_SecretKeyData, secretKeyData, 1 ); */
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Контекст секретного ключа, который будет сохранен в файле.
    @param pass Пароль, представленный в виде строки символов в формате utf8.
    @param pass_size Длина пароля в байтах.
    @param filename Имя файла, в который будет сохранен ключ.

    @return В случае успеха возвращается \ref ak_error_ok. В случае возникновения ошибки
            возвращается ее код.                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_to_der_file( ak_skey skey, const char *filename,
                            const ak_pointer pass, const size_t pass_size, const char *description )
{
 int error = ak_error_ok;
 SecretKeyData_t secretKeyData; /* asn1 структура */

 /* проверяем имя заданного файла */
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                "using null pointer to file name" );
 /* вычисляем asn1 представление ключа */
  if(( error = ak_skey_to_asn1_secret_key_data( skey, &secretKeyData,
                                                   pass, pass_size, description )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of secret key's asn1 structure");

 /* сохраняем файл */
  if(( error = ak_asn1_save_to_der_file( &asn_DEF_SecretKeyData, &secretKeyData, filename )) != ak_error_ok )
    ak_error_message_fmt( error, __func__, "incorrect saving secret key to \"%s\" file", filename );

 /* освобождаем память
    значение последнего параметра, равное единице означает,
    что освоождение памяти из под &secretKeyData не происходит */
  SEQUENCE_free( &asn_DEF_SecretKeyData, &secretKeyData, 1 );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_skey.c  */
/* ----------------------------------------------------------------------------------------------- */
