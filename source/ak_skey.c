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
 #include <ak_skey.h>
 #include <ak_tools.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует поля структуры, выделяя необходимую память. Всем полям
    присваиваются значения по-умолчанию.

    \b Внимание! После создания, указатели на методы cекретного ключа не установлены (равны NULL).

    @param key контекст (структура struct skey) секретного ключа. Память под контекст
    должна быть выделена заранее.
    @param size размер секретного ключа в байтах
    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_create( ak_skey skey, size_t size )
{
  int error = ak_error_ok;
  if( skey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ ,"using a null pointer to secret key" );
    return ak_error_null_pointer;
  }

 /* Инициализируем данные базовыми значениями */
  if(( error = ak_buffer_create_function_size( &skey->key, malloc, free, size )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a secret key buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  if(( error = ak_buffer_create_size( &skey->mask, size )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a key mask buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  if(( error = ak_buffer_create_size( &skey->icode, 8 )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a integrity code buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  skey->data = NULL;
  memset( &(skey->resource), 0, sizeof( ak_resource ));

 /* инициализируем генератор масок */
  if(( skey->generator = ak_random_new_lcg()) == NULL ) {
    ak_error_message( error = ak_error_get_value(), __func__ ,
                                                       "wrong creation of random generator" );
    ak_skey_destroy( skey );
    return error;
  }

 /* номер ключа генерится случайным образом. изменяется  при считывания с файлового носителя */
  if(( error = ak_buffer_create_size( &skey->number, 33 )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation key number buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  if(( error = ak_skey_assign_unique_number( skey )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"invalid creation of key number" );
    ak_skey_destroy( skey );
    return error;
  }
  /* OID ключа устанавливается производящей функцией */
  skey->oid = NULL;

 /* в заключение определяем нулевые указатели на методы.
    указатели должны устанавливаться при создании конкретного
    типа ключа, например, конкретного блочного алгоритма шифрования */
  skey->set_mask = NULL;
  skey->remask = NULL;
  skey->set_icode = NULL;
  skey->check_icode = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция удаляет все выделенную память и уничтожает хранившиеся в ней знаачения.

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
  ak_buffer_wipe( &(skey->key), skey->generator );
  ak_buffer_destroy( &(skey->key ));
  memset( &(skey->key), 0, sizeof( struct buffer ));

  ak_buffer_wipe( &(skey->mask), skey->generator );
  ak_buffer_destroy( &(skey->mask ));
  memset( &(skey->mask), 0, sizeof( struct buffer ));

  ak_buffer_wipe( &(skey->icode), skey->generator );
  ak_buffer_destroy( &(skey->icode ));
  memset( &(skey->icode), 0, sizeof( struct buffer ));

  if( skey->generator != NULL ) ak_random_delete( skey->generator );
  if( skey->data != NULL ) free( skey->data );

  ak_buffer_destroy( &skey->number );
  skey->oid = NULL;
  memset( &(skey->resource), 0, sizeof( ak_resource ));

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
 int ak_skey_assign_unique_number( ak_skey skey )
{
  time_t tm = 0;
  size_t len = 0;
  ak_hash ctx = NULL;
  ak_uint8 out[32];
  char *number = NULL;
  const char *version =  ak_libakrypt_version();

 /* стандартные проверки */
  if( skey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to secret key" );
    return ak_error_null_pointer;
  }
  if(( ctx = ak_hash_new_streebog256()) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "wrong creation of hash function context" );
    return ak_error_out_of_memory;
  }

 /* заполняем стандартное начало вектора */
  memset( out, 0, 32 );
  len = strlen( version );
  memcpy( out, version, len ); /* сначала версия библиотеки */
  tm = time( NULL );
  memcpy( out+len, &tm, sizeof(tm) ); /* потом время генерации номера ключа */
  len += sizeof( time_t );
  if( len < 32 ) ak_random_ptr( skey->generator, out+len, 32 - len );

 /* вычисляем номер и очищаем память */
  ak_hash_data( ctx, out, 32, out );
  if(( ak_buffer_set_str( &skey->number,
                          number = ak_ptr_to_hexstr( out, 16, ak_false ))) != ak_error_ok ) {
    ak_error_message( ak_error_write_data, __func__ , "wrong assigning key number" );
    return ak_error_write_data;
  }
  if( number ) free( number );
  ctx = ak_hash_delete( ctx );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает вектор ключа как последовательность \f$ k_1, \ldots, k_n\f$, состоящую
    из элементов
    кольца  \f$ \mathbb Z_{2^{32}}\f$. Функция вырабатывает случайный вектор
    \f$ x_1, \ldots, x_n\f$ и заменяет ключевой вектор на последовательность значений
    \f$ k_1 + x_1 \pmod{2^{32}}, \ldots, k_n + x_n \pmod{2^{32}}\f$.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 4.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_mask_additive( ak_skey skey )
{
  size_t idx = 0;

  if( skey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to secret key" );
    return ak_error_null_pointer;
  }
 /* проверяем длину ключа */
  if( skey->key.size == 0 ) {
    ak_error_message( ak_error_zero_length, __func__ , "using a key buffer with zero length" );
    return ak_error_zero_length;
  }
  if( skey->key.size%4 != 0 ) {
    ak_error_message( ak_error_undefined_value, __func__ , "using a key buffer with wrong length" );
    return ak_error_undefined_value;
  }
 /* создаем маску*/
  if( ak_random_ptr( skey->generator, skey->mask.data, skey->mask.size ) != ak_error_ok ) {
    ak_error_message( ak_error_write_data, __func__ , "wrong mask generation for key buffer" );
    return ak_error_write_data;
  }
 /* накладываем маску на ключ */
  for( idx = 0; idx < (skey->key.size >> 2); idx++ )
     ((ak_uint32 *) skey->key.data)[idx] += ((ak_uint32 *) skey->mask.data)[idx];

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет новый случайный вектор \f$ y_1, \ldots, y_n\f$ и изменяет значение
    значение ключа, снимая старую маску и накладывая новую.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 4.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_remask_additive( ak_skey skey )
{
  size_t idx = 0;
  ak_uint32 newmask[16];

 /* выполняем стандартные проверки */
  if( skey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to secret key" );
    return ak_error_null_pointer;
  }
  if( skey->key.data == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using undefined key buffer" );
    return ak_error_null_pointer;
  }
  if(( skey->key.size >> 2 ) > 16 ) {
    ak_error_message( ak_error_wrong_length, __func__ , "key length is too small" );
    return ak_error_wrong_length;
  }
  if( skey->mask.data == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using undefined mask buffer" );
    return ak_error_null_pointer;
  }

 /* вырабатываем случайные данные */
  if( ak_random_ptr( skey->generator, newmask, skey->key.size ) != ak_error_ok ) {
    ak_error_message( ak_error_undefined_value, __func__ , "wrong random mask generation" );
    return ak_error_undefined_value;
  }
 /* накладываем маску */
  for( idx = 0; idx < (skey->key.size >> 2); idx++ ) {
     ((ak_uint32 *) skey->key.data)[idx] += newmask[idx];
     ((ak_uint32 *) skey->key.data)[idx] -= ((ak_uint32 *) skey->mask.data)[idx];
     ((ak_uint32 *) skey->mask.data)[idx] = newmask[idx];
  }
 /* удаляем старое */
  memset( newmask, 0, sizeof( ak_uint32 )*16 );
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
 int ak_skey_set_icode_additive( ak_skey skey )
{
  ak_uint64 result = 0;

  if( skey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to secret key" );
    return ak_error_null_pointer;
  }

 /* проверяем наличие и длину ключа */
  if( skey->key.data == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using undefined key buffer" );
    return ak_error_null_pointer;
  }
  if( skey->key.size%8 != 0 ) {
    ak_error_message( ak_error_wrong_length, __func__ , "using a key buffer with wrong length" );
    return ak_error_wrong_length;
  }
  if( skey->mask.data == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using undefined mask buffer" );
    return ak_error_null_pointer;
  }
  if( skey->icode.data == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using undefined mask buffer" );
    return ak_error_null_pointer;
  }
  if( skey->icode.size != 8 ) {
    ak_error_message( ak_error_wrong_length, __func__ ,
                                      "using integrity code buffer with wrong length" );
    return ak_error_wrong_length;
  }

 /* теперь, собственно вычисление контрольной суммы */
  ak_skey_icode_additive_sum( skey, &result );
  memcpy( skey->icode.data, &result, 8 );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_skey_check_icode_additive( ak_skey skey )
{
  ak_uint64 result = 0;

  if( skey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to secret key" );
    return ak_false;
  }

 /* проверяем наличие и длину ключа */
  if( skey->key.data == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using undefined key buffer" );
    return ak_false;
  }
  if( skey->key.size%8 != 0 ) {
    ak_error_message( ak_error_wrong_length, __func__ , "using a key buffer with wrong length" );
    return ak_false;
  }
  if( skey->mask.data == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using undefined mask buffer" );
    return ak_false;
  }
  if( skey->icode.data == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using undefined mask buffer" );
    return ak_false;
  }
  if( skey->icode.size != 8 ) {
    ak_error_message( ak_error_wrong_length, __func__ ,
                                      "using integrity code buffer with wrong length" );
    return ak_false;
  }

 /* теперь, собственно вычисление контрольной суммы */
  ak_skey_icode_additive_sum( skey, &result );
 /* и сравнение */
  if( memcmp( skey->icode.data, &result, 8 )) return ak_false;
   else return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу заданное значение, размер которого определяется размером секретного
    ключа. В зависимости от значения флага cflag при присвоении данные могут копироваться в контекст
    секретного ключа,
    либо в контекст может передаваться владение указателем на данные.
    В этом случае поведение функции аналогично поведению функции ak_buffer_set_ptr().

    @param skey Контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    @param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    @param cflag Флаг передачи владения укзателем ptr. Если cflag ложен (ak_false), то физического
    копирования данных не происходит: внутренний буфер лишь указывает на размещенные в другом месте
    данные, но не владеет ими. Если cflag истиннен (ak_true), то происходит выделение памяти и
    копирование данных в эту память (размножение данных).

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_assign_ptr( ak_skey skey, const ak_pointer ptr, const ak_bool cflag )
{
  int error = ak_error_ok;

  if( skey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to secret key" );
    return ak_error_null_pointer;
  }
  if( skey->key.size == 0 ) {
    ak_error_message( ak_error_zero_length, __func__ , "using non initialized secret key context" );
    return ak_error_zero_length;
  }
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to buffer" );
    return ak_error_null_pointer;
  }

 /* присваиваем буффер и маскируем его */
  if(( error = ak_buffer_set_ptr( &skey->key, ptr, skey->key.size, cflag )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a key data" );
    return error;
  }
  if(( error = skey->set_mask( skey )) != ak_error_ok ) {
      ak_error_message( error, __func__ , "wrong secret key masking" );
      return error;
  }
  if(( error = skey->set_icode( skey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong calculation of integrity code" );
    return error;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_skey.c  */
/* ----------------------------------------------------------------------------------------------- */
