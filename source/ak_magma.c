/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2008 - 2016 by Axel Kenzo, axelkenzo@mail.ru                                    */
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
/*   ak_magma.c                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_oid.h>
 #include <ak_skey.h>
 #include <ak_hash.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Контекст для хранения развернутых таблиц замен алгоритма ГОСТ 28147-89                  */
 struct magma_ctx {
  /*! \brief k-боксы   */
   sbox k21, k43, k65, k87;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует один такт шифрующего преобразования ГОСТ 28147-89                     */
 static ak_uint32 ak_crypt_magma_gostf( ak_uint32 x, const ak_uint8* k21,
                                     const ak_uint8 *k43, const ak_uint8* k65, const ak_uint8 *k87 )
{
  x = k87[x>>24 & 255] << 24 | k65[x>>16 & 255] << 16 | k43[x>> 8 & 255] <<  8 | k21[x & 255];
  return x<<11 | x>>(32-11);
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция зашифрования ГОСТ 28147-89 в режиме простой замены                              */
 static void ak_crypt_magma_encrypt_with_mask( ak_skey key, ak_pointer in, ak_pointer out )
{
  ak_uint32 *kp = (ak_uint32 *) key->key->data, *mp = (ak_uint32 *) key->mask->data, p = 0;
  register ak_uint32 n1 = ((ak_uint32 *) in)[0];
  register ak_uint32 n2 = ((ak_uint32 *) in)[1];
  struct magma_ctx *sx = (struct magma_ctx *) key->data;

  p = (n1 - mp[0]); p += kp[0]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[1]); p += kp[1]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[2]); p += kp[2]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[3]); p += kp[3]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[4]); p += kp[4]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[5]); p += kp[5]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[6]); p += kp[6]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[7]); p += kp[7]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );

  p = (n1 - mp[0]); p += kp[0]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[1]); p += kp[1]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[2]); p += kp[2]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[3]); p += kp[3]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[4]); p += kp[4]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[5]); p += kp[5]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[6]); p += kp[6]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[7]); p += kp[7]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );

  p = (n1 - mp[0]); p += kp[0]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[1]); p += kp[1]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[2]); p += kp[2]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[3]); p += kp[3]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[4]); p += kp[4]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[5]); p += kp[5]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[6]); p += kp[6]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[7]); p += kp[7]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );

  p = (n1 - mp[7]); p += kp[7]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[6]); p += kp[6]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[5]); p += kp[5]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[4]); p += kp[4]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[3]); p += kp[3]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[2]); p += kp[2]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[1]); p += kp[1]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[0]); p += kp[0]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );

  ((ak_uint32 *)out)[0] = n2; ((ak_uint32 *)out)[1] = n1;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция расшифроования ГОСТ 28147-89 в режиме простой замены                            */
 static void ak_crypt_magma_decrypt_with_mask( ak_skey key, ak_pointer in, ak_pointer out )
{
  ak_uint32 *kp = (ak_uint32 *) key->key->data, *mp = (ak_uint32 *) key->mask->data, p = 0;
  register ak_uint32 n1 = ((ak_uint32 *) in)[0];
  register ak_uint32 n2 = ((ak_uint32 *) in)[1];
  struct magma_ctx *sx = (struct magma_ctx *) key->data;

  p = (n1 - mp[0]); p += kp[0]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[1]); p += kp[1]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[2]); p += kp[2]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[3]); p += kp[3]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[4]); p += kp[4]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[5]); p += kp[5]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[6]); p += kp[6]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[7]); p += kp[7]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );

  p = (n1 - mp[7]); p += kp[7]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[6]); p += kp[6]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[5]); p += kp[5]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[4]); p += kp[4]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[3]); p += kp[3]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[2]); p += kp[2]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[1]); p += kp[1]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[0]); p += kp[0]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );

  p = (n1 - mp[7]); p += kp[7]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[6]); p += kp[6]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[5]); p += kp[5]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[4]); p += kp[4]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[3]); p += kp[3]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[2]); p += kp[2]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[1]); p += kp[1]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[0]); p += kp[0]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );

  p = (n1 - mp[7]); p += kp[7]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[6]); p += kp[6]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[5]); p += kp[5]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[4]); p += kp[4]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[3]); p += kp[3]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[2]); p += kp[2]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n1 - mp[1]); p += kp[1]; n2 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );
  p = (n2 - mp[0]); p += kp[0]; n1 ^= ak_crypt_magma_gostf( p, sx->k21, sx->k43, sx->k65, sx->k87 );

  ((ak_uint32 *)out)[0] = n2; ((ak_uint32 *)out)[1] = n1;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает контекст ключа блочного алгоритма шифрования ГОСТ 28147-89 (Магма).

    После выполнения данной функции создается указатель на контекст ключа и устанавливаются
    обработчики (функции класса). Однако само значение ключу не присваивается -
    поле key->key остается равным NULL.

    \b Внимание. Данная функция предназначена для использования другими функциями и не должна
    вызываться напрямую.

    @param oid Параметр oid задает идентификатор таблиц замен, используемых в алгоритме шифрования.
    В случае, если oid равен NULL, используются таблицы по-умолчанию, определяемые ГОСТ Р 34.12-2015.

    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
    возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 static ak_cipher_key ak_cipher_key_new_magma( ak_oid oid )
{
  ak_oid tables_oid = NULL;
  ak_cipher_key ckey = NULL;
  struct magma_ctx *sx = NULL;

  if( oid != NULL ) { /* проверяем корректность переданного в функцию OID таблицы замен */
    if( oid->engine != block_cipher ) {
      ak_error_message( ak_error_oid_engine, "using a not cipher OID", __func__ );
      return NULL;
    }
    if( oid->mode != kbox_params ) {
      ak_error_message( ak_error_oid_mode, "using a wrong mode OID", __func__ );
      return NULL;
    }
    tables_oid = oid;
  } else tables_oid = ak_oids_find_by_name( "id-magma-gost3412-2015-ParamSet" );

 /* теперь создаем ключ алгоритма шифрования и определяем его методы */
  if(( ckey = ak_cipher_key_new()) == NULL ) {
    ak_error_message( ak_error_null_pointer, "incorrect memory allocation", __func__ );
    return NULL;
  }
 /* создаем область для хранения ключевых данных */
  if(( ckey->key->key = ak_buffer_new_function_size( malloc, free, 32 )) == NULL ) {
    ak_error_message( ak_error_get_value(), "incorrect memory allocation for key buffer", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* создаем область для хранения развернутых таблиц замен */
  if(( ckey->key->data = malloc( sizeof( struct magma_ctx ))) == NULL ) {
     ak_error_message( ak_error_out_of_memory, "wrong allocation of internal data", __func__ );
     return ( ckey = ak_cipher_key_delete( ckey ));
  };
 /* вычисляем таблицы замен */
  sx = (struct magma_ctx *) ckey->key->data;
  if( ak_kbox_to_sbox( (const ak_kbox) tables_oid->data,
                                            sx->k21, sx->k43, sx->k65, sx->k87 ) != ak_error_ok ) {
    ak_error_message( ak_error_null_pointer, "wrong extracting of k-boxes", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* устанавливаем OID алгоритма шифрования */
  ckey->oid = ak_oids_find_by_name( "magma" );

 /* устанавливаем ресурс использования серетного ключа */
  ckey->resource = ak_libakrypt_get_magma_resource();

 /* устанавливаем размер блока обрабатываемых данных (в байтах) */
  ckey->block_size = 8;  /* длина блока для Магмы равна 64 бита */

 /* присваиваем ключу уникальный номер */
  if( ak_skey_assign_unique_number( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "incorrect calculation of unique key number", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }

 /* устанавливаем методы */
  ckey->key->set_mask = ak_skey_set_mask_additive;
  ckey->key->remask = ak_skey_remask_additive;
  ckey->key->set_icode = ak_skey_set_icode_additive;
  ckey->key->check_icode = ak_skey_check_icode_additive;

  ckey->init_keys = NULL;
  ckey->delete_keys = NULL;
  ckey->encrypt = ak_crypt_magma_encrypt_with_mask;
  ckey->decrypt = ak_crypt_magma_decrypt_with_mask;

 return ckey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает контекст ключа блочного алгоритма шифрования ГОСТ 28147-89 (Магма)
    и инициализирует его заданным значением.

    Значение ключа инициализируется значением, содержащемся в буффере, передаваемом в функцию.
    После присвоения ключа производится его маскирование, выработка контрольной суммы и
    выработка уникального номера ключа. После создания доступ к ключу закрывается с помощью вызова
    функции ak_skey_lock().

    Предпалагается, что основное использование функции ak_cipher_key_new_magma_buffer()
    заключается в тестировании алгоритма шифрования ГОСТ 28147-89 (Магма) на заданных (тестовых)
    значениях ключей.

    @param oid Параметр oid задает идентификатор таблиц замен, используемых в алгоритме шифрования.
    В случае, если oid равен NULL, используются таблицы по-умолчанию, определяемые ГОСТ Р 34.12-2015.

    @param buff Буффер, содержащий ключевое значение.
    \b Важно: после выполнения функции владение буффером переходит к контексту алгоритма шифрования,
    создаваемому функцией.

    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
    возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 ak_cipher_key ak_cipher_key_new_magma_buffer( ak_oid oid, ak_buffer buff )
{
  ak_cipher_key ckey = NULL;

 /* проверяем входной буффер */
  if( buff == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to buffer", __func__ );
    return NULL;
  }
 /* создаем контекст ключа */
  if(( ckey = ak_cipher_key_new_magma( oid )) == NULL ) {
    ak_error_message( ak_error_get_value(), "incorrect creation of magma secret key", __func__ );
    return NULL;
  }
 /* присваиваем ключевой буффер */
  if( ak_skey_assign_buffer( ckey->key, buff ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "incorrect assigning of key buffer", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* выводим сообщение о факте создания ключа */
  if( ak_log_get_level() >= ak_log_standard ) ak_error_message_fmt( ak_error_ok, __func__ ,
                              "created a secret key %s", ak_buffer_get_str(ckey->key->number ));
 /* закрываем доступ к секретному ключу */
  if( ak_skey_lock( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "incorrect locking of secret key", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 return ckey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param oid Параметр oid задает идентификатор таблиц замен, используемых в алгоритме шифрования.
    В случае, если oid равен NULL, используются таблицы по-умолчанию, определяемые ГОСТ Р 34.12-2015.

    @param generator Генератор псевдослучайных чисел, используемый для генерации ключа.

    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
    возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 ak_cipher_key ak_cipher_key_new_magma_random( ak_oid oid, ak_random generator )
{
  ak_cipher_key ckey = NULL;

 /* проверяем входной буффер */
  if( generator == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to random generator", __func__ );
    return NULL;
  }
 /* создаем контекст ключа */
  if(( ckey = ak_cipher_key_new_magma( oid )) == NULL ) {
    ak_error_message( ak_error_get_value(), "incorrect creation of magma secret key", __func__ );
    return NULL;
  }
 /* присваиваем случайные данные, выработанные генератором */
  if(( ak_random_ptr( generator,
    ak_buffer_get_ptr( ckey->key->key ), ak_buffer_get_size( ckey->key->key ))) != ak_error_ok ) {
      ak_error_message( ak_error_get_value(), "incorrect generation a random key data", __func__ );
      return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* накладываем маску */
  if( ckey->key->set_mask( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "wrong secret key masking", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* вычисляем контрольную сумму */
  if( ckey->key->set_icode( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "wrong calculation of integrity code", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* выводим сообщение о факте создания ключа */
  if( ak_log_get_level() >= ak_log_standard ) ak_error_message_fmt( ak_error_ok, __func__ ,
                            "created a secret key %s", ak_buffer_get_str(ckey->key->number ));
 /* закрываем доступ к секретному ключу */
  if( ak_skey_lock( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "incorrect locking of secret key", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 return ckey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выполняет тестирование блочного алгоритма Магма в соответствии с ГОСТ 28147-89,
    ГОСТ Р 34.12-2015 и ГОСТ Р 34.13-2015.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_cipher_key_test_magma( void )
{
  char *str = NULL;
  ak_cipher_key ckey = NULL;
  int audit = ak_log_get_level();

 /* тестовое значение ключа для ГОСТ 28147-89 */
  ak_uint32 test_28147_89_key[8] = {
   0xe0f67504, 0xfafb3850, 0x90c3c7d2, 0x3dcab3ed, 0x42124715, 0x8a1eae91, 0x9ecd792f, 0xbdefbcd2 };
 /* тестовое значение ключа из ГОСТ Р 34.12-2015 */
  ak_uint32 test_3412_2015_key[8] = {
   0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff };

 /* тестовые значения сообщения и результатов его зашифрования в различных режимах */
  ak_uint8 result28147[256], result3413[32];
  ak_uint32 p_text_com[64] = {
                  0x04050607, 0x00010203, 0x0c0d0e0f, 0x08090a0b,
                  0x14151617, 0x10111213, 0x1c1d1e1f, 0x18191a1b,
                  0x24252627, 0x20212223, 0x2c2d2e2f, 0x28292a2b,
                  0x34353637, 0x30313233, 0x3c3d3e3f, 0x38393a3b,
                  0x44454647, 0x40414243, 0x4c4d4e4f, 0x48494a4b,
                  0x54555657, 0x50515253, 0x5c5d5e5f, 0x58595a5b,
                  0x64656667, 0x60616263, 0x6c6d6e6f, 0x68696a6b,
                  0x74757677, 0x70717273, 0x7c7d7e7f, 0x78797a7b,
                  0x84858687, 0x80818283, 0x8c8d8e8f, 0x88898a8b,
                  0x94959697, 0x90919293, 0x9c9d9e9f, 0x98999a9b,
                  0xa4a5a6a7, 0xa0a1a2a3, 0xacadaeaf, 0xa8a9aaab,
                  0xb4b5b6b7, 0xb0b1b2b3, 0xbcbdbebf, 0xb8b9babb,
                  0xc4c5c6c7, 0xc0c1c2c3, 0xcccdcecf, 0xc8c9cacb,
                  0xd4d5d6d7, 0xd0d1d2d3, 0xdcdddedf, 0xd8d9dadb,
                  0xe4e5e6e7, 0xe0e1e2e3, 0xecedeeef, 0xe8e9eaeb,
                  0xf4f5f6f7, 0xf0f1f2f3, 0xfcfdfeff, 0xf8f9fafb};

  ak_uint32 c_text_ecb[64] = {
                  0x984c8c4b, 0xea4af215, 0x0957c31e, 0xd12ebcb3,
                  0x22f2d1e0, 0x18592d65, 0x80fcdff7, 0x685cde4b,
                  0x53755346, 0xec0d46a7, 0xd31b1f05, 0xb71a630a,
                  0xe043c478, 0x0ea43e5d, 0xa9237e2d, 0xbc02c91b,
                  0xcb840c21, 0xc8070a0d, 0xb5fbd07b, 0x5c04141a,
                  0x719753a2, 0x8fc25c2e, 0x526f3f39, 0x4e2630f2,
                  0x01d1e08c, 0xd3dc6d75, 0xca1e7903, 0x120ec1d5,
                  0xe2780a53, 0xea1cb10a, 0xb955f83a, 0xba0be17c,
                  0xeb96c8a0, 0x60d35a50, 0x980fa343, 0x6d50d9db,
                  0x01af9163, 0x5a75e940, 0x191f5c46, 0x9b890b4a,
                  0xf5f8f6c4, 0xfa3f872f, 0x25f8d426, 0x82981fba,
                  0x2daf26fc, 0x58c4f9c0, 0x8009fa49, 0x34a46202,
                  0x6b5acb2d, 0x085d61ab, 0x08e026d4, 0x022ed613,
                  0xd0e8372a, 0xc7f136cf, 0x219b3fc0, 0x2d29bd60,
                  0x4e48012e, 0x16208ff8, 0xdc82bf8a, 0x18a37a32,
                  0x5950d169, 0x6cf29131, 0x58ca5f5a, 0xb22db29a};
  /*
  ak_uint32 c_text_cfb[64] = {
                  0xfbfaf8f9, 0xfefffdfc, 0x2879623c, 0xab07e6bf,
                  0x40e37b6a, 0x7ce3c8a6, 0x4eccbf3f, 0x292ccfc0,
                  0x3dbc57d4, 0x7614ae57, 0x9d257334, 0xc247e1ed,
                  0xc5d986a2, 0x4ff5c68c, 0x06b6a447, 0xed362235,
                  0x3df01471, 0x66462ee8, 0x7139a725, 0x0b40e58c,
                  0x721bc377, 0xfba0abdf, 0x16b3c6bb, 0x7c79d2d7,
                  0xba4f6113, 0x537a6f6e, 0x652eeb26, 0x86a63077,
                  0x814aec97, 0xf55ab96c, 0xbbbfd4ff, 0x30243e4f,
                  0xb90e4bec, 0x4b80f1de, 0xf70877d9, 0x90d1d864,
                  0x61672f27, 0x50e04b94, 0x5b0128e1, 0x434f097f,
                  0x5f70b7df, 0x7e5eb969, 0xfe659ff3, 0xdcf996a8,
                  0xef60f1d7, 0x7983d5f8, 0xb7f07b08, 0x175ca01b,
                  0xe27dd376, 0x0b0d01fa, 0xfef3edb3, 0x0ea3bdf1,
                  0x9501688d, 0x7ad83a4f, 0x1997cc60, 0x80bc39fe,
                  0xa348ccac, 0x4b70b361, 0xeaf5438a, 0x062dd801,
                  0xfcc7e945, 0xb46d2f44, 0x093b8508, 0x5f64c839}; */

  ak_uint64 out_text = 0;
  ak_uint64 in_3412_2015_text = 0xfedcba9876543210, out_3412_2015_text = 0x4ee901e5c2d8ca3d;
  ak_uint64 in_3413_2015_text[4] = {
                  0x92def06b3c130a59, 0xdb54c704f8189d20, 0x4a98fb2e67a8024c, 0x8912409b17b57e41 };
  ak_uint64 out_3413_2015_ecb_text[4] = {
                  0x2b073f0494f372a0, 0xde70e715d3556e48, 0x11d8d9e9eacfbc1e, 0x7c68260996c67efb };


 /* 1. Выполняем тестовый пример из ГОСТ 34.12-2015 */
  if(( ckey = ak_cipher_key_new_magma_buffer(
         ak_oids_find_by_name( "id-magma-gost3412-2015-ParamSet" ),
                                 ak_buffer_new_ptr( test_3412_2015_key, 32, ak_false ))) == NULL ) {
   ak_error_message( ak_error_get_value(), "wrong creation of secret key", __func__ );
   return ak_false;
  }
  ckey->encrypt( ckey->key, &in_3412_2015_text, &out_text );
  if( out_text != out_3412_2015_text ) {
    ak_error_message( ak_error_not_equal_data,
                       "the one block encryption test from GOST R 34.12-2015 is wrong", __func__ );
    ak_log_set_message(( str = ak_ptr_to_hexstr( &out_text, sizeof( ak_uint64 ), ak_false ))); free( str );
    ak_log_set_message(( str =
                     ak_ptr_to_hexstr( &out_3412_2015_text, sizeof( ak_uint64 ), ak_false ))); free( str );
    ckey = ak_cipher_key_delete( ckey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok,
                         "the one block encryption test from GOST R 34.12-2015 is Ok", __func__ );

  ckey->decrypt( ckey->key, &out_text, &out_text );
  if( out_text != in_3412_2015_text ) {
    ak_error_message( ak_error_not_equal_data,
                    "the one block decryption test from GOST R 34.12-2015 is wrong", __func__ );
    ak_log_set_message(( str = ak_ptr_to_hexstr( &out_text, sizeof( ak_uint64 ), ak_false ))); free( str );
    ak_log_set_message(( str =
                      ak_ptr_to_hexstr( &in_3412_2015_text, sizeof( ak_uint64 ), ak_false ))); free( str );
    ckey = ak_cipher_key_delete( ckey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok,
                       "the one block decryption test from GOST R 34.12-2015 is Ok", __func__ );

 /* 2. Выполняем пример из ГОСТ 34.13-2015 для режима простой замены (ECB) */
  memset( result3413, 0, 32 );
  ak_cipher_key_encrypt_ecb( ckey, in_3413_2015_text, result3413, 32 );
  if( memcmp( out_3413_2015_ecb_text, result3413, 32 ) != 0 ) {
    ak_error_message( ak_error_not_equal_data,
                       "the ecb mode encryption test from GOST 34.13-2015 is wrong", __func__ );
    ak_log_set_message(( str = ak_ptr_to_hexstr( out_3413_2015_ecb_text, 32, ak_false ))); free( str );
    ak_log_set_message(( str = ak_ptr_to_hexstr( result3413, 32, ak_false ))); free( str );
    ckey = ak_cipher_key_delete( ckey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok,
                          "the ecb mode encryption test from GOST 34.13-2015 is Ok", __func__ );

  memset( result3413, 0, 32 );
  ak_cipher_key_decrypt_ecb( ckey, out_3413_2015_ecb_text, result3413, 32 );
  if( memcmp( in_3413_2015_text, result3413, 32 ) != 0 ) {
    ak_error_message( ak_error_not_equal_data,
                       "the ecb mode decryption test from GOST 34.13-2015 is wrong", __func__ );
    ak_log_set_message(( str = ak_ptr_to_hexstr( in_3413_2015_text, 32, ak_false ))); free( str );
    ak_log_set_message(( str = ak_ptr_to_hexstr( result3413, 32, ak_false ))); free( str );
    ckey = ak_cipher_key_delete( ckey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok,
                          "the ecb mode decryption test from GOST 34.13-2015 is Ok", __func__ );

  ckey = ak_cipher_key_delete( ckey );

  /* Далее мы используем другой секретный ключ */
  /* 1. Выполняем тестовый пример для таблиц замен из ГОСТ 28147-89 в режиме простой замены */
  if(( ckey = ak_cipher_key_new_magma_buffer(
         ak_oids_find_by_name( "id-magma-TestParamSet" ),
                                 ak_buffer_new_ptr( test_28147_89_key, 32, ak_false ))) == NULL ) {
   ak_error_message( ak_error_get_value(), "wrong creation of secret key", __func__ );
   return ak_false;
  }

  memset( result28147, 0, 256 );
  ak_cipher_key_encrypt_ecb( ckey, p_text_com, result28147, 256 );
  if( memcmp( c_text_ecb, result28147, 256 ) != 0 ) {
    ak_error_message( ak_error_not_equal_data,
      "the ecb encryption test for 256 bytes message with GOST 28147-89 tables is wrong", __func__ );
    ak_log_set_message(( str = ak_ptr_to_hexstr( c_text_ecb, 256, ak_false ))); free( str );
    ak_log_set_message(( str = ak_ptr_to_hexstr( result28147, 256, ak_false ))); free( str );
    ckey = ak_cipher_key_delete( ckey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok,
       "the ecb encryption test for 256 bytes message with GOST 28147-89 tables is Ok", __func__ );

  memset( result28147, 0, 256 );
  ak_cipher_key_decrypt_ecb( ckey, c_text_ecb, result28147, 256 );
  if( memcmp( p_text_com, result28147, 256 ) != 0 ) {
    ak_error_message( ak_error_not_equal_data,
      "the ecb decryption test for 256 bytes message with GOST 28147-89 tables is wrong", __func__ );
    ak_log_set_message(( str = ak_ptr_to_hexstr( p_text_com, 256, ak_false ))); free( str );
    ak_log_set_message(( str = ak_ptr_to_hexstr( result28147, 256, ak_false ))); free( str );
    ckey = ak_cipher_key_delete( ckey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok,
       "the ecb decryption test for 256 bytes message with GOST 28147-89 tables is Ok", __func__ );
  ckey = ak_cipher_key_delete( ckey );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_magma.c  */
/* ----------------------------------------------------------------------------------------------- */
