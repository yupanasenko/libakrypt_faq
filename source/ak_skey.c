/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014, 2015, 2016 by Axel Kenzo, axelkenzo@mail.ru                               */
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
/*   ak_skey.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <time.h>
 #include <ak_skey.h>
 #include <ak_buffer.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает контекст секретного ключа, устанавливая все поля в значения по-умолчанию.

    \b Внимание! После создания, указатели на методы cекретного ключа не установлены (равны NULL).

     @param key контекст (структура struct skey) секретного ключа. Память под контекст
     должна быть выделена заранее.
     @return Функция возвращает ak_error_ok (ноль) в случае, если создание контекста произошло
     успешно. В противном случае возвращается код ошибки.                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_create( ak_skey key )
{
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }
 /*  сначала данные */
  key->key = NULL;
  key->mask = NULL;
  key->generator = ak_random_new_lcg(); /* создаем генератор масок ключа */
  key->icode = NULL;
  key->data = NULL;
  key->number = NULL;

 /* потом методы */
  key->set_mask = NULL;
  key->remask = NULL;
  key->set_icode = NULL;
  key->check_icode = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_destroy( ak_skey key )
{
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }

 /* удаляем данные */
  ak_buffer_wipe( key->key, key->generator );
  key->key = ak_buffer_delete( key->key );
  ak_buffer_wipe( key->mask, key->generator );
  key->mask = ak_buffer_delete( key->mask );
  ak_buffer_wipe( key->icode, key->generator );
  key->icode = ak_buffer_delete( key->icode );
  key->generator = ak_random_delete( key->generator );
  if( key->data != NULL ) free( key->data );

 /* выводим сообщение и завершаем удаление */
  if( ak_log_get_level() >= ak_log_standard ) ak_error_message_str( ak_error_ok,
                     "deleted a secret key", ak_buffer_get_str(key->number), __func__ );
  key->number = ak_buffer_delete( key->number );

 /* обнуляем указатели */
  key->set_mask = NULL;
  key->remask = NULL;
  key->set_icode = NULL;
  key->check_icode = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_skey ak_skey_new( void )
{
  ak_skey skey = ( ak_skey ) malloc( sizeof( struct skey ));
   if( skey != NULL ) ak_skey_create( skey );
     else ak_error_message( ak_error_out_of_memory, "incorrect memory allocation", __func__ );
 return skey;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_skey_delete( ak_pointer skey )
{
  if( skey != NULL ) {
    ak_skey_destroy( skey );
    free( skey );
  } else ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция накладывает аддитивную (в кольце вычетов) маску на ключ.

  Функция рассматривает вектор ключа как последовательность \f$ k_1, \ldots, k_n\f$ из элементов
  кольца  \f$ \mathbb Z_{2^{32}}\f$. Функция вырабатывает случайный вектор
  \f$ x_1, \ldots, x_n\f$ и заменяет ключевой вектор на последовательность значений
  \f$ k_1 + x_1 \pmod{2^{32}}, \ldots, k_n + x_n \pmod{2^{32}}\f$.

  @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
  должна быть кратна 4.

  @return В случае успеха функция возвращает ak_error_ok. В противном случае,
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_mask_additive( ak_skey key )
{
  size_t idx = 0, keylen = 0;
  ak_uint32 *kp = NULL, *mp = NULL;

  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }
  /* проверяем наличие и длину ключа */
  if( key->key == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined key buffer", __func__ );
    return ak_error_undefined_value;
  }
  if( !( keylen = ak_buffer_get_size( key->key ))) {
    ak_error_message( ak_error_zero_length, "using a key buffer with zero length", __func__ );
    return ak_error_zero_length;
  }
  if( keylen%4 != 0 ) {
    ak_error_message( ak_error_undefined_value, "using a key buffer with wrong length", __func__ );
    return ak_error_undefined_value;
  }

 /* уничтожаем старый буфер и создаем новый */
  if( key->mask != NULL ) key->mask = ak_buffer_delete( key->mask );
  if(( key->mask = ak_buffer_new_random( key->generator, keylen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong mask buffer generation", __func__ );
    return ak_error_out_of_memory;
  }
 /* накладываем маску на ключ */
  kp = (ak_uint32 *) ak_buffer_get_ptr( key->key );
  mp = (ak_uint32 *) ak_buffer_get_ptr( key->mask );
  for( idx = 0; idx < (keylen >> 2); idx++ ) kp[idx] += mp[idx];

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция накладывает маску на ключ.

  Функция рассматривает вектор ключа как последовательность \f$ k_1, \ldots, k_n\f$ из элементов
  кольца  \f$ \mathbb Z_{2^{64}}\f$. Функция вырабатывает случайный вектор
  \f$ x_1, \ldots, x_n\f$ и заменяет ключевой вектор на последовательность значений
  \f$ k_1 \oplus x_1, \ldots, k_n \oplus x_n\f$, где операция \f$ \oplus \f$
  есть покоординатное сложение векторов по модулю 2.

  @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
  должна быть кратна 8.

  @return В случае успеха функция возвращает ak_error_ok. В противном случае,
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_mask_xor( ak_skey key )
{
  size_t idx = 0, keylen = 0;
  ak_uint64 *kp = NULL, *mp = NULL;

  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }
  /* проверяем наличие и длину ключа */
  if( key->key == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined key buffer", __func__ );
    return ak_error_undefined_value;
  }
  if( !( keylen = ak_buffer_get_size( key->key ))) {
    ak_error_message( ak_error_zero_length, "using a key buffer with zero length", __func__ );
    return ak_error_zero_length;
  }
  if( keylen%8 != 0 ) {
    ak_error_message( ak_error_undefined_value, "using a key buffer with wrong length", __func__ );
    return ak_error_undefined_value;
  }

  /* уничтожаем старый буфер и создаем новый */
  if( key->mask != NULL ) key->mask = ak_buffer_delete( key->mask );
  if(( key->mask = ak_buffer_new_random( key->generator, keylen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong mask buffer generation", __func__ );
    return ak_error_out_of_memory;
  }
  /* накладываем маску на ключ */
  kp = (ak_uint64 *) ak_buffer_get_ptr( key->key );
  mp = (ak_uint64 *) ak_buffer_get_ptr( key->mask );
  for( idx = 0; idx < (keylen >> 3); idx++ ) kp[idx] ^= mp[idx];

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция изменяет значение аддитивной маски ключа

  Функция вычисляет новый случайный вектор \f$ y_1, \ldots, y_n\f$ и изменяет значение
  значение ключа, снимая старую маску и накладывая новую.

  @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
  должна быть кратна 4.

  @return В случае успеха функция возвращает ak_error_ok. В противном случае,
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_remask_additive( ak_skey key )
{
  size_t idx = 0, keylen = 0;
  ak_buffer newmask = NULL;
  ak_uint32 *kp = NULL, *mp = NULL, *np = NULL;

 /* выполняем стандартные проверки */
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }
  if( key->key == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined key buffer", __func__ );
    return ak_error_undefined_value;
  }
  if( key->mask == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined mask buffer", __func__ );
    return ak_error_undefined_value;
  }

 /* создаем новый буффер */
  keylen = ak_buffer_get_size( key->mask );
  if(( newmask = ak_buffer_new_random( key->generator, keylen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong mask buffer generation", __func__ );
    return ak_error_out_of_memory;
  }
 /* накладываем маску */
  kp = (ak_uint32 *) ak_buffer_get_ptr( key->key );
  mp = (ak_uint32 *) ak_buffer_get_ptr( key->mask );
  np = (ak_uint32 *) ak_buffer_get_ptr( newmask );
  for( idx = 0; idx < (keylen >> 2); idx++ ) { kp[idx] += np[idx]; kp[idx] -= mp[idx]; }

 /* удаляем старое */
  key->mask = ak_buffer_delete( key->mask );
  key->mask = newmask;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция изменяет значение маски ключа

  Функция вычисляет новый случайный вектор \f$ y_1, \ldots, y_n\f$ и изменяет значение
  значение ключа, снимая старую маску и накладывая новую.

  @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
  должна быть кратна 8.

  @return В случае успеха функция возвращает ak_error_ok. В противном случае,
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_remask_xor( ak_skey key )
{
  size_t idx = 0, keylen = 0;
  ak_buffer newmask = NULL;
  ak_uint64 *kp = NULL, *mp = NULL, *np = NULL;

 /* выполняем стандартные проверки */
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }
  if( key->key == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined key buffer", __func__ );
    return ak_error_undefined_value;
  }
  if( key->mask == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined mask buffer", __func__ );
    return ak_error_undefined_value;
  }

 /* создаем новый буффер */
  keylen = ak_buffer_get_size( key->mask );
  if(( newmask = ak_buffer_new_random( key->generator, keylen )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong mask buffer generation", __func__ );
    return ak_error_out_of_memory;
  }
 /* накладываем маску */
  kp = (ak_uint64 *) ak_buffer_get_ptr( key->key );
  mp = (ak_uint64 *) ak_buffer_get_ptr( key->mask );
  np = (ak_uint64 *) ak_buffer_get_ptr( newmask );
  for( idx = 0; idx < (keylen >> 3); idx++ ) { kp[idx] ^= np[idx]; kp[idx] ^= mp[idx]; }

 /* удаляем старое */
  key->mask = ak_buffer_delete( key->mask );
  key->mask = newmask;
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
 static ak_uint64 ak_skey_set_icode_permutation( const ak_uint32 xv, const ak_uint32 yv )
{
  ak_uint32 x = xv, y = yv, carry = 0;
  ak_uint64 s =  ( ak_uint64 )x + y, more = s&0x100000000, result = 0;

  if( more ) { x = ~x; y = ~y; s = ( ak_uint64 )x + y; }
  result = y; result *= 3; result += x;
  s *= s; result += s; if( result < s ) carry = 1;

  result >>= 1;
  if( carry ) result ^= 0x8000000000000000L;
  if( more ) result = ~result;
 return result^0xC5BF891B4EF6AA79L; // \sqrt{\pi}
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_icode_additive( ak_skey key )
{
  ak_uint64 result = 0;
  size_t i = 0, keylen = 0;
  ak_uint32 *kptr = NULL, *mptr = NULL;

  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }

 /* проверяем наличие и длину ключа */
  if( key->key == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined key buffer", __func__ );
    return ak_error_undefined_value;
  }
  if( !( keylen = ak_buffer_get_size( key->key ))) {
    ak_error_message( ak_error_zero_length, "using a key buffer with zero length", __func__ );
    return ak_error_zero_length;
  }
  if( keylen%8 != 0 ) {
    ak_error_message( ak_error_undefined_value, "using a key buffer with wrong length", __func__ );
    return ak_error_undefined_value;
  }

 /* если нужно, создаем новый буффер */
  if( key->icode == NULL ) {
    if(( key->icode = ak_buffer_new_size(8)) == NULL ) {
      ak_error_message( ak_error_out_of_memory, "wrong allocation memory", __func__ );
      return ak_error_out_of_memory;
    }
  }

 /* теперь, собственно вычисление контрольной суммы */
  kptr = (ak_uint32 *) ak_buffer_get_ptr( key->key );
  mptr = (ak_uint32 *) ak_buffer_get_ptr( key->mask );
  for( i = 0; i < (keylen >> 2); i+=4 ) {
      ak_uint32 x = 0, y = 0;
      x = kptr[i] + kptr[i+1];
      y = kptr[i+2] + kptr[i+3];
      x -= mptr[i]; x -= mptr[i+1];
      y -= mptr[i+2]; y -= mptr[i+3];
      result += ak_skey_set_icode_permutation( x, y );
  }
  if( ak_buffer_set_ptr( key->icode, &result, 8, ak_true ) != ak_error_ok ) {
      ak_error_message( ak_error_undefined_value, "wrong integrity code assigning", __func__ );
      return ak_error_undefined_value;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_icode_xor( ak_skey key )
{
  ak_uint64 result = 0;
  size_t i = 0, keylen = 0;
  ak_uint32 *kptr = NULL, *mptr = NULL;

  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }

 /* проверяем наличие и длину ключа */
  if( key->key == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined key buffer", __func__ );
    return ak_error_undefined_value;
  }
  if( !( keylen = ak_buffer_get_size( key->key ))) {
    ak_error_message( ak_error_zero_length, "using a key buffer with zero length", __func__ );
    return ak_error_zero_length;
  }
  if( keylen%8 != 0 ) {
    ak_error_message( ak_error_undefined_value, "using a key buffer with wrong length", __func__ );
    return ak_error_undefined_value;
  }

 /* если нужно, создаем новый буффер */
  if( key->icode == NULL ) {
    if(( key->icode = ak_buffer_new_size(8)) == NULL ) {
      ak_error_message( ak_error_out_of_memory, "wrong allocation memory", __func__ );
      return ak_error_out_of_memory;
    }
  }

 /* теперь, собственно вычисление контрольной суммы */
  kptr = (ak_uint32 *) ak_buffer_get_ptr( key->key );
  mptr = (ak_uint32 *) ak_buffer_get_ptr( key->mask );
  for( i = 0; i < (keylen >> 2); i+=4 ) {
      ak_uint32 x = 0, y = 0;
      x = kptr[i] ^ kptr[i+1];
      y = kptr[i+2] ^ kptr[i+3];
      x ^= mptr[i]; x ^= mptr[i+1];
      y ^= mptr[i+2]; y ^= mptr[i+3];
      result += ak_skey_set_icode_permutation( x, y );
  }
  if( ak_buffer_set_ptr( key->icode, &result, 8, ak_true ) != ak_error_ok ) {
      ak_error_message( ak_error_undefined_value, "wrong integrity code assigning", __func__ );
      return ak_error_undefined_value;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_skey_check_icode_additive( ak_skey key )
{
  ak_uint64 result = 0;
  size_t i = 0, keylen = 0;
  ak_uint32 *kptr = NULL, *mptr = NULL;

 /* выполняем стандартные проверки */
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_false;
  }
  if( key->key == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined key buffer", __func__ );
    return ak_false;
  }
  if( !( keylen = ak_buffer_get_size( key->key ))) {
    ak_error_message( ak_error_zero_length, "using a key buffer with zero length", __func__ );
    return ak_false;
  }
  if( keylen%8 != 0 ) {
    ak_error_message( ak_error_undefined_value, "using a key buffer with wrong length", __func__ );
    return ak_false;
  }
  if( key->mask == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined mask buffer", __func__ );
    return ak_false;
  }
  if( key->icode == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined integrity code buffer", __func__ );
    return ak_false;
  }

 /* теперь, собственно вычисление контрольной суммы */
  kptr = (ak_uint32 *) ak_buffer_get_ptr( key->key );
  mptr = (ak_uint32 *) ak_buffer_get_ptr( key->mask );
  for( i = 0; i < (keylen = ak_buffer_get_size( key->key ) >> 2); i+=4 ) {
      ak_uint32 x = 0, y = 0;
      x = kptr[i] + kptr[i+1];
      y = kptr[i+2] + kptr[i+3];
      x -= mptr[i]; x -= mptr[i+1];
      y -= mptr[i+2]; y -= mptr[i+3];
      result += ak_skey_set_icode_permutation( x, y );
  }

 /* и сравнение */
  if( memcmp( ak_buffer_get_ptr(key->icode),  &result, 8 )) return ak_false;
 else return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_skey_check_icode_xor( ak_skey key )
{
  ak_uint64 result = 0;
  size_t i = 0, keylen = 0;
  ak_uint32 *kptr = NULL, *mptr = NULL;

 /* выполняем стандартные проверки */
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_false;
  }
  if( key->key == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined key buffer", __func__ );
    return ak_false;
  }
  if( !( keylen = ak_buffer_get_size( key->key ))) {
    ak_error_message( ak_error_zero_length, "using a key buffer with zero length", __func__ );
    return ak_false;
  }
  if( keylen%8 != 0 ) {
    ak_error_message( ak_error_undefined_value, "using a key buffer with wrong length", __func__ );
    return ak_false;
  }
  if( key->mask == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined mask buffer", __func__ );
    return ak_false;
  }
  if( key->icode == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined integrity code buffer", __func__ );
    return ak_false;
  }

 /* теперь, собственно вычисление контрольной суммы */
  kptr = (ak_uint32 *) ak_buffer_get_ptr( key->key );
  mptr = (ak_uint32 *) ak_buffer_get_ptr( key->mask );
  for( i = 0; i < (keylen = ak_buffer_get_size( key->key ) >> 2); i+=4 ) {
      ak_uint32 x = 0, y = 0;
      x = kptr[i] ^ kptr[i+1];
      y = kptr[i+2] ^ kptr[i+3];
      x ^= mptr[i]; x ^= mptr[i+1];
      y ^= mptr[i+2]; y ^= mptr[i+3];
      result += ak_skey_set_icode_permutation( x, y );
  }

 /* и сравнение */
  if( memcmp( ak_buffer_get_ptr(key->icode),  &result, 8 )) return ak_false;
 else return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает секретному ключу буффер с данными, владение буффером переходит к ключу     */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_assign_buffer( ak_skey key, ak_buffer buff )
{
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }
  if( buff == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to buffer", __func__ );
    return ak_error_null_pointer;
  }

 /* если ключ уже существует, то его надо удалить */
  if( key->key != NULL ) {
    ak_buffer_wipe( key->key, key->generator );
    key->key = ak_buffer_delete( key->key );
  }

 /* присваиваем буффер и маскируем его */
  key->key = buff;
  if( key->set_mask( key ) != ak_error_ok ) {
    int error = ak_error_get_value();
      ak_error_message( error, "wrong secret key masking", __func__ );
      return error;
  }

  if( key->set_icode( key ) != ak_error_ok ) {
    int error = ak_error_get_value();
    ak_error_message( error, "wrong calculation of integrity code", __func__ );
    return error;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Выработанный функцией номер является уникальным (в рамках библиотеки) и однозначно идентифицирует
    секретный ключ. Данный идентификатор может сохраняться вместе с ключом.

    @param key контекст секретного ключа, для клоторого вырабатывается уникальный номер
    @return В случае успеха функция возвращает k_error_ok (ноль). В противном случае, возвращается
    номер ошибки.                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_assign_unique_number( ak_skey key )
{
  time_t tm = 0;
  size_t len = 0;
  ak_uint8 out[32];
  ak_hash ctx = NULL;
  char *number = NULL;
  const char *version =  ak_libakrypt_version();

 /* стандартные проверки */
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }
  if( ( ctx = ak_hash_new_streebog256()) == NULL ) {
    ak_error_message( ak_error_out_of_memory, "wrong creation of hash function context", __func__ );
    return ak_error_out_of_memory;
  }
 /* заполняем стандартное начало вектора */
  memset( out, 0, 32 );
  len = strlen( version );
  memcpy( out, version, len ); /* сначала версия библиотеки */
  tm = time( NULL );
  memcpy( out+len, &tm, sizeof(tm) ); /* потом время генерации номера ключа */
  len += sizeof( time_t );
  if( len < 32 ) ak_random_ptr( key->generator, out+len, 32 - len );

 /* вычисляем номер и очищаем память */
  ak_hash_data( ctx, out, 32, out );
  key->number = ak_buffer_new_ptr( number = ak_ptr_to_hexstr( out, 16, ak_false ), 33, ak_true );
  free(number);
  ctx = ak_hash_delete( ctx );
  if( key->number == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong calculation of unique key number", __func__ );
    return ak_error_get_value();
  };
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция запрещает доступ к серетному ключу

   В настоящее время функция представляет собой заглушку и нереализована                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_lock( ak_skey key )
{
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция разрешает доступ к серетному ключу

   В настоящее время функция представляет собой заглушку и нереализована                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_unlock( ak_skey key )
{
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                               методы класса ak_cipher_key                                       */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает контекст секретного ключа блочного алгоритма шифрования, устанавливая
    все поля контекста в значения по-умолчанию
    \b Внимание! После создания, указатели на методы не установлены (равны NULL).

      @param key контекст (структура struct skey) секретного ключа. Память под контекст
      должна быть выделена заранее.
      @return Функция возвращает ak_error_ok (ноль) в случае, если создание контекста произошло
      успешно. В противном случае возвращается код ошибки.                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_cipher_key_create( ak_cipher_key ckey )
{
  if( ckey == NULL ) {
    ak_error_message( ak_error_null_pointer, "using null pointer to a cipher key", __func__ );
    return ak_error_null_pointer;
  }
 /* сначала данные */
  if(( ckey->key = ak_skey_new()) == NULL ) {
    ak_error_message( ak_error_null_pointer, "wrong creation of cipher key", __func__ );
    return ak_error_null_pointer;
  }
  ckey->oid = NULL;
  ckey->resource = 0;
  ckey->block_size = 0; /* точное значение длины блока устанавливается при создании ключа  */

 /* потом методы */
  ckey->encrypt = NULL;
  ckey->decrypt = NULL;
  ckey->init_keys = NULL;
  ckey->delete_keys = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_cipher_key_destroy( ak_cipher_key ckey )
{
  if( ckey == NULL ) {
    ak_error_message( ak_error_null_pointer, "using null pointer to a secret key", __func__ );
    return ak_error_null_pointer;
  }
 /* сначала данные */
  if( ckey->delete_keys != NULL ) ckey->delete_keys( ckey->key );
  ckey->key = ak_skey_delete( ckey->key );
  ckey->resource = 0;
  ckey->block_size = 0;
  ckey->oid = NULL; /* указатель содержит ссылку на существующий объект.
                                           его удаление разрушит внутренний список, хранящий OID'ы */
 /* потом методы */
  ckey->encrypt = NULL;
  ckey->decrypt = NULL;
  ckey->init_keys = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_cipher_key ak_cipher_key_new( void )
{
  ak_cipher_key ckey = ( ak_cipher_key ) malloc( sizeof( struct cipher_key ));
   if( ckey != NULL ) ak_cipher_key_create( ckey );
     else ak_error_message( ak_error_out_of_memory, "incorrect memory allocation", __func__ );
 return ckey;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_cipher_key_delete( ak_pointer ckey )
{
  if( ckey != NULL ) {
    ak_cipher_key_destroy( ckey );
    free( ckey );
  } else ak_error_message( ak_error_null_pointer, "using null pointer to a cipher key", __func__ );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает количество блоков, которые можно зашифорвать/расшифровать на
    заданном ключе.

    @param ckey Ключ блочного алгоритма шифрования
    @param value Переменная, в которую помещаетсяч значение.

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
  int ak_cipher_key_get_resource( ak_cipher_key ckey, ak_uint32 *value )
{
  if( ckey == NULL ) {
    ak_error_message( ak_error_null_pointer, "using null pointer to a cipher key", __func__ );
    return ak_error_null_pointer;
  }
  if( value == NULL ) {
    ak_error_message( ak_error_null_pointer, "using null result pointer", __func__ );
    return ak_error_null_pointer;
  }

  *value = ckey->resource;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                        теперь мы реализуем режимы шифрования                                    */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выполняет необходимые проверки и тесты перед использованием секретного ключа

    @param ckey Ключ блочного алгоритма, на котором происходит обработка информации
    @param in Указатель на область памяти, где хранятся входные данные
    @param out Указатель на область памяти, куда помещаются данные
    @param size Размер данных (в байтах)
    @param wholeblock Флаг, нужно ли тестировать длину данных на кратность одному блоку.
    Это важно в таких режимах, как ECB (простая замена), CBC (простая замена с зацеплением) и т.п.

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_cipher_key_check_before_encrypt( ak_cipher_key ckey,
                                    ak_pointer in, ak_pointer out, size_t size, ak_bool wholeblock )
{
 /* проверяем входные параметры */
  if( ckey == NULL ) {
    ak_error_message( ak_error_null_pointer, "using null pointer to a cipher key", __func__ );
    return ak_error_null_pointer;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, "using null pointer to input data", __func__ );
    return ak_error_null_pointer;
  }
  if( out == NULL ) {
    ak_error_message( ak_error_null_pointer, "using null pointer to result data", __func__ );
    return ak_error_null_pointer;
  }
  if( size == 0 ) {
    ak_error_message( ak_error_zero_length, "using zero length of input data", __func__ );
    return ak_error_zero_length;
  }
  /* проверяем ресурс ключа */
  if( ckey->block_size == 0 ) {
    ak_error_message( ak_error_undefined_value,
                                              "using a cipher key with zero block size", __func__ );
    return ak_error_undefined_value;
  }
  if( (size_t)ckey->resource < ( size/ckey->block_size )) {
    ak_error_message( ak_error_low_key_resource, "using a cipher key with low resource", __func__ );
    return ak_error_low_key_resource;
  }
  /* открываем доступ к ключу */
  if( ak_skey_unlock( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_wrong_key_unlock, "wrong unlocking of cipher key", __func__ );
    return ak_error_wrong_key_unlock;
  }
  /* проверяем целостность ключа */
  if( ckey->key->check_icode( ckey->key ) != ak_true ) {
    ak_error_message( ak_error_wrong_key_icode,
                                         "wrong value of integrity code of cipher key", __func__ );
    if( ak_skey_lock( ckey->key ) != ak_error_ok )
              ak_error_message( ak_error_wrong_key_lock, "wrong locking of cipher key", __func__ );
    return ak_error_wrong_key_icode;
  }
  if( wholeblock == ak_true ) { /* в этом режиме данные должны быть кратны длине блока */
     if( size%ckey->block_size != 0 ) {
       ak_error_message( ak_error_wrong_length, "using wrong length of input data", __func__ );
       if( ak_skey_lock( ckey->key ) != ak_error_ok )
              ak_error_message( ak_error_wrong_key_lock, "wrong locking of cipher key", __func__ );
       return ak_error_wrong_length;
     }
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует процедуру зашифрования в режиме простой замены

    @param ckey Ключ блочного алгоритма, на котором происходит зашифрование информации
    @param in Указатель на область памяти, где хранятся входные (зашифровываемые) данные
    @param out Указатель на область памяти, куда помещаются зашифровываемые данные
    @param size Размер зашировываемых данных (в байтах)

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_cipher_key_encrypt_ecb( ak_cipher_key ckey, ak_pointer in, ak_pointer out, size_t size )
{
  size_t blocks = 0;
  int error = ak_error_ok;
  ak_uint64 *inptr = NULL, *outptr = NULL;

  /* выполняем проверку входных параметров */
  if(( error = ak_cipher_key_check_before_encrypt( ckey, in, out, size, ak_true )) != ak_error_ok )
  {
    ak_error_message( error, "wrong testing a cipher key before encryption", __func__ );
    return error;
  }

  /* теперь приступаем к зашифрованию данных */
  blocks = size/ckey->block_size;
  ckey->resource -= (ak_uint32) blocks; /* уменьшаем ресурс ключа */
  inptr = (ak_uint64 *) in;
  outptr = (ak_uint64 *) out;

  if( ckey->block_size == 8 ) { /* здесь длина блока равна 64 бита */
    do{
       ckey->encrypt( ckey->key, inptr++, outptr++ );
    } while( --blocks > 0 );
  }
  if( ckey->block_size == 16 ) { /* здесь длина блока равна 128 бит */
    do{
       ckey->encrypt( ckey->key, inptr, outptr );
       inptr+=2; outptr+=2;
    } while( --blocks > 0 );
  }

  /* перемаскируем ключ */
  if( ckey->key->remask( ckey->key ) != ak_error_ok )
    ak_error_message( ak_error_get_value(), "wrong remasking of secret key", __func__ );
  /* и снова блокируем доступ к ключу */
  if( ak_skey_lock( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_wrong_key_lock, "wrong locking of secret key", __func__ );
    return ak_error_wrong_key_lock;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует процедуру расшифрования в режиме простой замены

    @param ckey Ключ блочного алгоритма, на котором происходит расшифрование информации
    @param in Указатель на область памяти, где хранятся входные (расшифровываемые) данные
    @param out Указатель на область памяти, куда помещаются расшифровываемые данные
    @param size Размер зашировываемых данных (в байтах)

    @return В случае возникновения ошибки функция возвращает ее код, в противном случае
    возвращается ak_error_ok (ноль)                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_cipher_key_decrypt_ecb( ak_cipher_key ckey, ak_pointer in, ak_pointer out, size_t size )
{
  size_t blocks = 0;
  int error = ak_error_ok;
  ak_uint64 *inptr = NULL, *outptr = NULL;

  /* выполняем проверку входных параметров */
  if(( error = ak_cipher_key_check_before_encrypt( ckey, in, out, size, ak_true )) != ak_error_ok )
  {
    ak_error_message( error, "wrong testing a cipher key before decryption", __func__ );
    return error;
  }

  /* теперь приступаем к зашифрованию данных */
  blocks = size/ckey->block_size;
  ckey->resource -= (ak_uint32) blocks; /* уменьшаем ресурс ключа */
  inptr = (ak_uint64 *) in;
  outptr = (ak_uint64 *) out;

  if( ckey->block_size == 8 ) { /* здесь длина блока равна 64 бита */
    do{
       ckey->decrypt( ckey->key, inptr++, outptr++ );
    } while( --blocks > 0 );
  }
  if( ckey->block_size == 16 ) { /* здесь длина блока равна 128 бит */
    do{
       ckey->decrypt( ckey->key, inptr, outptr );
       inptr+=2; outptr+=2;
    } while( --blocks > 0 );
  }

  /* перемаскируем ключ */
  if( ckey->key->remask( ckey->key ) != ak_error_ok )
    ak_error_message( ak_error_get_value(), "wrong remasking of secret key", __func__ );
  /* и снова блокируем доступ к ключу */
  if( ak_skey_lock( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_wrong_key_lock, "wrong locking of secret key", __func__ );
    return ak_error_wrong_key_lock;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example  example-cipherkey01.c                                                                */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_skey.c  */
/* ----------------------------------------------------------------------------------------------- */
