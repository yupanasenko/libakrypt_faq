/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 by Anton Sakharov                                                           */
/*  Copyright (c) 2020 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_asn1_keys.c                                                                            */
/*  - содержит реализацию функций,                                                                 */
/*    используемых для базового кодирования/декодированя ASN.1 структур                            */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hmac.h>
 #include <ak_tools.h>
 #include <ak_asn1_keys.h>

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
 static ak_function_password_read *ak_function_default_password_read = NULL;

/* ----------------------------------------------------------------------------------------------- */
/*! \note Функция экспортируется.
    \param function Обработчик операции чтения пароля.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_set_password_read_function( ak_function_password_read *function )
{
  if( function == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to password read function" );
  ak_function_default_password_read = function;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет последовательность октетов `basicKey` длиной 64 октета в соответствии со
    следующим равенством

\code
    basicKey = PBKDF2( password, salt, count, 64 )
\endcode

и определяет производные ключи шифрования и имитозащиты равенствами

\code
    KEK = Lsb( 256, BasicKey ) = BasicKey[0..31],
    KIM = Msb( 256, BasicKey ) = BasicKey[32..63].
\endcode

После этого функция формирует следующую ASN.1 структуру.

\code
    BasicKeyMetaData ::= SEQUENCE {
      method OBJECT IDENTIFIER,  -- метод генерации производных ключей
                                 -- для выработки производных ключей из пароля
                                    используется значение 1.2.643.2.52.1.127.2.1
      basicKey PBKDF2BasicKey    -- данные, необходимые для выработки и использования
                                    производных ключей.
    }
\endcode

Структура `PBKDF2BasicKey` определяется следующим образом.

\code
    PBKDF2BasicKey ::= SEQUENCE {
      algorithm OBJECT IDENTIFIER -- алгоритм блочного шифрования,
                                     для которого предназначены производные ключи
      parameters PBKDF2Parameters -- параметры алгоритма генерации производных ключей
    }
\endcode

Структура `PBKDF2Parameters` определяется следующим образом

\code
    PBKDF2Parameters ::= SEQUENCE {
      algorithmID OBJECT IDENTIFIER,   -- идентификатор алгоритма, лежащего в основе PBKDF2
                                       -- по умолчанию, это hmac-streebog512 (1.2.643.7.1.1.4.2)
      salt OCTET STRING,               -- инициализационный вектор для алгоритма PBKDF2,
      iterationCount INTEGER (0..65535),  -- число итераций алгоритма PBKDF2
    }
\endcode

 \param root уровень ASN.1 дерева, к которому добавляется структура BasicKeyMetaData
 \param oid идентификатор алгоритма длочного шифрования
 \param ekey контекст ключа шифрования контекста
 \param ikey контекст ключа имитозащиты
 \param password пароль, используемый для генерации ключа шифрования контента
 \param pass_size длина пароля (в октетах)

 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_add_derived_keys_from_password( ak_asn1 root, ak_oid oid , ak_bckey ekey,
                                       ak_bckey ikey, const char *password, const size_t pass_size )
{
  ak_uint8 salt[32]; /* случайное значение для генерации ключа шифрования контента */
  ak_uint8 derived_key[64]; /* вырабатываемый из пароля ключевой материал,
                               из которого формируются производные ключи шифрования и имитозащиты */
  int error = ak_error_ok;
  ak_asn1 asn1 = NULL, asn2 = NULL, asn3 = NULL;

 /* 1. вырабатываем случайное значение и производный ключевой материал */
   if(( error = ak_bckey_context_create_oid( ekey, oid )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of encryption cipher key" );

   ak_random_context_random( &ekey->key.generator, salt, sizeof( salt ));
   if(( error = ak_hmac_context_pbkdf2_streebog512(
                 (ak_pointer) password,                             /* пароль */
                  pass_size,                                 /* размер пароля */
                  salt,                           /* инициализационный вектор */
                  sizeof( salt ),        /* размер инициализационного вектора */
                  (size_t) ak_libakrypt_get_option( "pbkdf2_iteration_count" ),
                  64,                         /* размер вырабатываемого ключа */
                  derived_key                   /* массив для хранения данных */
     )) != ak_error_ok ) {
      ak_bckey_context_destroy( ekey );
      return ak_error_message( error, __func__, "incorrect creation of derived key" );
   }

 /* 2. инициализируем контексты ключа шифрования контента и ключа имитозащиты */
   if(( error = ak_bckey_context_set_key( ekey, derived_key, 32 )) != ak_error_ok ) {
     ak_bckey_context_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to encryption key" );
   }
   if(( error = ak_bckey_context_create_oid( ikey, oid )) != ak_error_ok ) {
     ak_bckey_context_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect creation of integrity key" );
   }
   if(( error = ak_bckey_context_set_key( ikey, derived_key+32, 32 )) != ak_error_ok ) {
     ak_bckey_context_destroy( ikey );
     ak_bckey_context_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to integrity key" );
   }
  /* очищаем использованную память */
   ak_ptr_context_wipe( derived_key, sizeof( derived_key ), &ikey->key.generator );

 /* 3. собираем ASN.1 дерево - снизу вверх */
   if(( ak_asn1_context_create( asn3 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_context_destroy( ikey );
     ak_bckey_context_destroy( ekey );
     return ak_error_message( error, __func__,
                                         "incorrect creation of PBKDF2Parameters asn1 structure" );
   }
   ak_asn1_context_add_oid( asn3, ak_oid_context_find_by_name( "hmac-streebog512" )->id );
   ak_asn1_context_add_octet_string( asn3, salt, sizeof( salt ));
   ak_asn1_context_add_uint32( asn3,
                                 ( ak_uint32 )ak_libakrypt_get_option( "pbkdf2_iteration_count" ));

   if(( ak_asn1_context_create( asn2 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_context_destroy( ikey );
     ak_bckey_context_destroy( ekey );
     ak_asn1_context_delete( asn3 );
     return ak_error_message( error, __func__,
                                           "incorrect creation of PBKDF2BasicKey asn1 structure" );
   }
   ak_asn1_context_add_oid( asn2, oid->id );
   ak_asn1_context_add_asn1( asn2, TSEQUENCE, asn3 );

   if(( ak_asn1_context_create( asn1 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_context_destroy( ikey );
     ak_bckey_context_destroy( ekey );
     ak_asn1_context_delete( asn2 );
     return ak_error_message( error, __func__,
                                         "incorrect creation of BasicKeyMetaData asn1 structure" );
   }
   ak_asn1_context_add_oid( asn1, ak_oid_context_find_by_name( "pbkdf2-basic-key" )->id );
   ak_asn1_context_add_asn1( asn1, TSEQUENCE, asn2 );

  /* помещаем в основное ASN.1 дерево структуру BasicKeyMetaData */
 return ak_asn1_context_add_asn1( root, TSEQUENCE, asn1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для ввода пароля используется функция, на которую указывает ak_function_defaut_password_read.
    Если этот указатель не установлен (то есть равен NULL), то выполняется чтение пароля
    из терминала.

    Формат ASN.1 структуры, хранящей параметры восстановления производных ключей,
    содержится в документации к функции ak_asn1_context_add_derived_keys_from_password().

    \param akey контекст ASN.1 дерева, содержащий информацию о ключе (структура `BasicKeyMetaData`)
    \param ekey контекст ключа шифрования
    \param ikey контекст ключа имитозащиты
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_get_derived_keys_from_password( ak_asn1 akey, ak_bckey ekey, ak_bckey ikey )
{
  size_t size = 0;
  ak_uint32 u32 = 0;
  ak_asn1 asn = NULL;
  char password[256];
  ak_pointer ptr = NULL;
  int error = ak_error_ok;
  ak_uint8 derived_key[64]; /* вырабатываемый из пароля ключевой материал,
                               из которого формируются производные ключи шифрования и имитозащиты */
  ak_oid eoid = NULL, oid = NULL;

 /* получаем структуру с параметрами, необходимыми для восстановления ключа */
  ak_asn1_context_first( akey );
  if(( akey->count != 1 ) || ( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
              ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = akey->current->data.constructed;

 /* проверяем параметры */
  ak_asn1_context_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
  ak_tlv_context_get_oid( asn->current, &ptr );
  oid = ak_oid_context_find_by_name( "pbkdf2-basic-key" );
  if( strncmp( oid->id, ptr, strlen( oid->id )) != 0 ) return ak_error_invalid_asn1_content;

  ak_asn1_context_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
              ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = asn->current->data.constructed;

 /* получаем информацию о ключе и параметрах его выработки */
  ak_asn1_context_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;

  ak_tlv_context_get_oid( asn->current, &ptr );
  eoid = ak_oid_context_find_by_id( ptr ); /* 1. идентификатор ключа блочного шифрования */
  if(( eoid->engine != block_cipher ) || ( eoid->mode != algorithm ))
    return ak_error_invalid_asn1_tag;

 /* получаем доступ к параметрам алгоритма генерации производных ключей */
  ak_asn1_context_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
              ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = asn->current->data.constructed;

 /* проверяем hmac */
  ak_asn1_context_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
  ak_tlv_context_get_oid( asn->current, &ptr );
  oid = ak_oid_context_find_by_name( "hmac-streebog512" );
  if( strncmp( oid->id, ptr, strlen( oid->id )) != 0 ) return ak_error_invalid_asn1_content;

  ak_asn1_context_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING )) return ak_error_invalid_asn1_tag;
  ak_tlv_context_get_octet_string( asn->current, &ptr, &size ); /* 2. инициализационный вектор */

  ak_asn1_context_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
  ak_tlv_context_get_uint32( asn->current, &u32 ); /* число циклов */

 /* вырабатываем производную ключевую информацию */
   if( ak_function_default_password_read == NULL ) {
     fprintf( stdout, "password: "); fflush( stdout );
     error = ak_password_read( password, sizeof( password ));
     fprintf( stdout, "\n" );
   } else error = ak_function_default_password_read( password, sizeof( password ));
   if( error != ak_error_ok ) return error;

 /* 1. получаем пользовательский пароль и вырабатываем производную ключевую информацию */
   error = ak_hmac_context_pbkdf2_streebog512( (ak_pointer) password, strlen( password ),
                                                                 ptr, size, u32, 64, derived_key );
   memset( password, 0, sizeof( password ));
   if( error != ak_error_ok ) return error;

 /* 2. инициализируем контексты ключа шифрования контента и ключа имитозащиты */
   if(( error = ak_bckey_context_create_oid( ekey, eoid )) != ak_error_ok ) {
     memset( derived_key, 0, sizeof( derived_key ));
     return ak_error_message( error, __func__, "incorrect creation of encryption cipher key" );
   }
   if(( error = ak_bckey_context_set_key( ekey, derived_key, 32 )) != ak_error_ok ) {
     ak_ptr_context_wipe( derived_key, sizeof( derived_key ), &ekey->key.generator );
     ak_bckey_context_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to encryption key" );
   }

   if(( error = ak_bckey_context_create_oid( ikey, eoid )) != ak_error_ok ) {
     ak_ptr_context_wipe( derived_key, sizeof( derived_key ), &ekey->key.generator );
     ak_bckey_context_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect creation of integrity key" );
   }
   if(( error = ak_bckey_context_set_key( ikey, derived_key+32, 32 )) != ak_error_ok ) {
     ak_ptr_context_wipe( derived_key, sizeof( derived_key ), &ekey->key.generator );
     ak_bckey_context_destroy( ikey );
     ak_bckey_context_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to integrity key" );
   }
  /* очищаем использованную память */
   ak_ptr_context_wipe( derived_key, sizeof( derived_key ), &ikey->key.generator );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_keys.c  */
/* ----------------------------------------------------------------------------------------------- */
