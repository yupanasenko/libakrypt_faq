/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2020 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_asn1_keys.c                                                                            */
/*  - содержит реализацию функций,                                                                 */
/*    используемых для базового кодирования/декодирования ключевой информации                      */
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
/*! \brief Указатель на функцию чтения пароля */
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
                  /* Функции выработки и сохранения производных ключей */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция добавляет ASN.1 структуру, содержащую зашифрованное значение секретного ключа.

 \param root ASN.1 структура, к которой добавляется новая структура
 \param skey секретный ключ, содержащий зашифровываемые данные
 \param ekey производный ключ шифрования
 \param ikey производный ключ имитозащиты
 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_context_add_skey_content( ak_asn1 root,
                                                       ak_skey skey, ak_bckey ekey, ak_bckey ikey )
{
  ak_asn1 content = NULL;
  int error = ak_error_ok;
  size_t ivsize  = ekey->bsize >> 1,
         keysize = 2*skey->key_size;
  size_t len = ivsize + keysize + ikey->bsize;
             /* необходимый объем памяти:
                синхропосылка (половина блока) + ( ключ+маска ) + имитовставка (блок) */

  if(( content = ak_asn1_context_new( )) == NULL ) return ak_error_message( ak_error_get_value(),
                                                  __func__, "incorrect creation of asn1 context" );
  if(( error = ak_asn1_context_add_uint32( content, data_present_storage )) != ak_error_ok ) {
    ak_asn1_context_delete( content );
    return ak_error_message( error, __func__, "incorrect adding data storage identifier" );
  }
  if(( error = ak_asn1_context_add_uint32( content,
                  ( ak_uint32 )ak_libakrypt_get_option( "openssl_compability" ))) != ak_error_ok ) {
    ak_asn1_context_delete( content );
    return ak_error_message( error, __func__, "incorrect adding data storage identifier" );
  }

 /* добавляем ключ: реализуем КЕexp15 для ключа и маски */
  if(( error = ak_asn1_context_add_octet_string( content, &len, len )) == ak_error_ok ) {
    ak_uint8 *ptr = content->current->data.primitive;

   /* формируем iv */
    memset( ptr, 0, len );
    ak_random_context_random( &ekey->key.generator, ptr, ivsize );
   /* меняем маску секретного ключа */
    skey->set_mask( skey );
   /* копируем данные:
      сохраняем их как большое целое число в big-endian кодировке */
    ak_mpzn_to_little_endian(( ak_uint64 *)skey->key,
                                             (skey->key_size >> 2), ptr+ivsize, keysize, ak_true );
   /* меняем маску секретного ключа */
    skey->set_mask( skey );
   /* вычисляем имитовставку */
    if(( error = ak_bckey_context_cmac( ikey, ptr, ivsize+keysize,
                                            ptr+(ivsize+keysize), ikey->bsize )) != ak_error_ok ) {
      ak_asn1_context_delete( content );
      return ak_error_message( error, __func__, "incorrect evaluation of cmac" );
    }
   /* шифруем данные */
    if(( error = ak_bckey_context_ctr( ekey, ptr+ivsize, ptr+ivsize, keysize+ikey->bsize,
                                                                  ptr, ivsize )) != ak_error_ok ) {
      ak_asn1_context_delete( content );
      return ak_error_message( error, __func__, "incorrect encryption of skey" );
    }
  } else {
           ak_asn1_context_delete( content );
           return ak_error_message( error, __func__, "incorrect adding a secret key" );
    }

 /* вставляем изготовленную последовательность и выходим */
 return ak_asn1_context_add_asn1( root, TSEQUENCE, content );
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

После этого функция присоединяет к заданному уровню `root` следующую ASN.1 структуру.

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
 \param oid идентификатор алгоритма блочного шифрования,
 для которого вырабатываются производные ключи шифрования и имитозащиты
 \param ekey контекст производного ключа шифрования
 \param ikey контекст производного ключа имитозащиты
 \param password пароль, используемый для генерации ключей шифрования и имитозащиты контента
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
 int ak_asn1_context_get_derived_keys( ak_asn1 akey, ak_bckey ekey, ak_bckey ikey )
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
  if( akey->count != 2 ) return ak_error_invalid_asn1_count;

 /* проверяем параметры */
  if(( DATA_STRUCTURE( akey->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( akey->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
  ak_tlv_context_get_oid( akey->current, &ptr );
  oid = ak_oid_context_find_by_name( "pbkdf2-basic-key" );
  if( strncmp( oid->id, ptr, strlen( oid->id )) != 0 ) return ak_error_invalid_asn1_content;
   /* в дальнейшем, здесь вместо if должен появиться switch,
      который разделяет все три возможных способа генерации производных ключей
      сейчас поддерживается только способ генерации из пароля */

  ak_asn1_context_next( akey );
  if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
              ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = akey->current->data.constructed;

 /* получаем информацию о ключе и параметрах его выработки */
  ak_asn1_context_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;

  ak_tlv_context_get_oid( asn->current, &ptr );
  eoid = ak_oid_context_find_by_id( ptr ); /* идентификатор ключа блочного шифрования */
  if(( eoid->engine != block_cipher ) || ( eoid->mode != algorithm ))
    return ak_error_invalid_asn1_tag;

 /* получаем доступ к параметрам алгоритма генерации производных ключей */
  ak_asn1_context_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
              ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = asn->current->data.constructed;

 /* получаем из ASN.1 дерева параметры, которые будут передаватьсяв функцию pbkdf2 */
  ak_asn1_context_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
  ak_tlv_context_get_oid( asn->current, &ptr );
  oid = ak_oid_context_find_by_name( "hmac-streebog512" );
  if( strncmp( oid->id, ptr, strlen( oid->id )) != 0 ) return ak_error_invalid_asn1_content;

  ak_asn1_context_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING )) return ak_error_invalid_asn1_tag;
  ak_tlv_context_get_octet_string( asn->current, &ptr, &size ); /* инициализационный вектор */

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
                         /* Функции экспорта ключевой информации */
/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Экспорт секретного ключа симметричного алгоритма в ASN.1 дерево.

   Функция создает ASN.1 структуру `Content`, определяемую следующим образом
\code
    Content ::= SEQUENCE {
       type OBJECT IDENTIFIER, -- уникальный тип контента
                               -- для симметричных ключей это значение равно 1.2.643.2.52.1.127.3.1
       symkey SymmetricKeyContent -- собственно контент ключа
    }
\endcode

Структура `SymmetricKeyContent` определяется следующим образом.

\code
    SymmetricKeyContent ::= SEQUENCE {
       algorithm OBJECT IDENTIFIER,   -- идентификатор алгоритма, для которого предназначен ключ
       number OCTET STRING,           -- уникальный номер ключа
       keyname UTF8 STRING,           -- человекочитаемое имя (описание) ключа
       params KeyParameters,          -- параметры секретного ключа, такие ресурс использований и
                                         временной интервал
       content EncryptedContent       -- собственно зашифрованные с помощью преобразования KExp15 данные
    }
\endcode

Формат структуры метаданных `BasicKeyMetaData`, используемой для восстановления ключа,
содержится в документации к функции ak_asn1_context_add_derived_keys_from_password().

Формат структуры `KeyParameters` определяется следующим образом.
\code
    KeyParameters ::= SEQUENCE {
       resourceType INTEGER, -- тип ресурса секретного ключа
       resource INTEGER,     -- значение ресурса
       validity Validity     -- временной интервал использования ключа
    }
\endcode

Структура `Validity` содержит в себе временной интервал действия ключа и определяется стандартным для x509 образом.
\code
    Validity ::= SEQUENCE {
      notBefore Time,
      notAfter Time
    }

    Time ::= CHOICE {
      utcTime UTCTime,
      generalTime generalizedTime
    }
\endcode

 \param root уровень ASN.1 дерева, к которому добавляется структура `Content`
 \param skey контекст секретного ключа
 \param ekey контекст производного ключа шифрования
 \param ikey контекст производного ключа имитозащиты
 \param keyname строка символов, содержащая пользовательское описание (имя) ключа;
        может принимать значение null.
 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_context_add_symmetric_key_content( ak_asn1 root, ak_skey skey,
                                                ak_bckey ekey, ak_bckey ikey , const char *keyname )
{
  ak_asn1 symkey = NULL;
  int error = ak_error_ok;

 /* 1. помечаем контейнер */
   if(( error = ak_asn1_context_add_oid( root,
                   ak_oid_context_find_by_name( "symmetric-key-content" )->id )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect adding contents identifier" );

 /* 2. добавляем соответствующую структуру с данными */
   if(( error = ak_asn1_context_add_asn1( root, TSEQUENCE,
                                               symkey = ak_asn1_context_new( ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context for content" );

  /* 3. создаем пять встроенных полей (данный набор специфичен только для SymmetricKeyContent
     - 3.1. - идентификатор ключа */
   if(( error = ak_asn1_context_add_oid( symkey, skey->oid->id )) != ak_error_ok ) {
     ak_asn1_context_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's identifier" );
   }

  /* - 3.2. - номер ключа ключа */
   if(( error = ak_asn1_context_add_octet_string( symkey,
                                          skey->number, sizeof( skey->number ))) != ak_error_ok ) {
     ak_asn1_context_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's number" );
   }

  /* - 3.3. - имя/описание ключа */
   if(( error = ak_asn1_context_add_utf8_string( symkey, keyname )) != ak_error_ok ) {
     ak_asn1_context_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's description" );
     goto labexit;
   }

  /* - 3.4. - ресурс ключа */
   if(( error = ak_asn1_context_add_resource( symkey, &skey->resource )) != ak_error_ok ) {
     ak_asn1_context_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's parameters" );
     goto labexit;
   }

  /* - 3.5. - собственно зашифрованный ключ */
   if(( error = ak_asn1_context_add_skey_content( symkey, skey, ekey, ikey )) != ak_error_ok ) {
     ak_asn1_context_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's parameters" );
   }

  labexit: return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Экспорт асимметричного секретного ключа в ASN.1 дерево.

   Функция создает ASN.1 структуру `Content`, определяемую следующим образом
\code
    Content ::= SEQUENCE {
       type OBJECT IDENTIFIER, -- уникальный тип контента
                               -- для симметричных ключей это значение равно 1.2.643.2.52.1.127.3.2
       symkey SecretKeyContent -- собственно контент ключа
    }
\endcode

Структура `SecretKeyContent` определяется следующим образом.

\code
    SecretKeyContent ::= SEQUENCE {
       algorithm OBJECT IDENTIFIER,   -- идентификатор алгоритма, для которого предназначен ключ
       number OCTET STRING,           -- уникальный номер ключа
       keyname UTF8 STRING,           -- человекочитаемое имя (описание) ключа
       params KeyParameters,          -- параметры секретного ключа, такие ресурс использований и
                                         временной интервал
       curveOID OBJECT IDENTIFIER     -- идентификатор эллиптической кривой, на которой выполняются
                                         криптографические преобразования
       content EncryptedContent       -- собственно зашифрованные с помощью преобразования KExp15 данные
    }
\endcode

Формат структуры метаданных `BasicKeyMetaData`, используемой для восстановления ключа,
содержится в документации к функции ak_asn1_context_add_derived_keys_from_password().

Формат структуры `KeyParameters` определяется следующим образом.
\code
    KeyParameters ::= SEQUENCE {
       resourceType INTEGER, -- тип ресурса секретного ключа
       resource INTEGER,     -- значение ресурса
       validity Validity     -- временной интервал использования ключа
    }
\endcode

Структура `Validity` содержит в себе временной интервал действия ключа и определяется стандартным для x509 образом.
\code
    Validity ::= SEQUENCE {
      notBefore Time,
      notAfter Time
    }

    Time ::= CHOICE {
      utcTime UTCTime,
      generalTime generalizedTime
    }
\endcode

 \param root уровень ASN.1 дерева, к которому добавляется структура `Content`
 \param skey контекст секретного ключа
 \param ekey контекст производного ключа шифрования
 \param ikey контекст производного ключа имитозащиты
 \param keyname строка символов, содержащая пользовательское описание (имя) ключа;
        может принимать значение null.
 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_context_add_signature_key_content( ak_asn1 root, ak_skey skey,
                                                ak_bckey ekey, ak_bckey ikey , const char *keyname )
{
  ak_oid eoid = NULL;
  ak_asn1 symkey = NULL;
  int error = ak_error_ok;

 /* 1. помечаем контейнер */
   if(( error = ak_asn1_context_add_oid( root,
                   ak_oid_context_find_by_name( "secret-key-content" )->id )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect adding contents identifier" );

 /* 2. добавляем соответствующую структуру с данными */
   if(( error = ak_asn1_context_add_asn1( root, TSEQUENCE,
                                               symkey = ak_asn1_context_new( ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context for content" );

  /* 3. создаем шесть встроенных полей (данный набор специфичен только для SecretKeyContent
     - 3.1. - идентификатор ключа */
   if(( error = ak_asn1_context_add_oid( symkey, skey->oid->id )) != ak_error_ok ) {
     ak_asn1_context_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's identifier" );
   }

  /* - 3.2. - номер ключа ключа */
   if(( error = ak_asn1_context_add_octet_string( symkey,
                                          skey->number, sizeof( skey->number ))) != ak_error_ok ) {
     ak_asn1_context_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's number" );
   }

  /* - 3.3. - имя/описание ключа */
   if(( error = ak_asn1_context_add_utf8_string( symkey, keyname )) != ak_error_ok ) {
     ak_asn1_context_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's description" );
     goto labexit;
   }

  /* - 3.4. - ресурс ключа */
   if(( error = ak_asn1_context_add_resource( symkey, &skey->resource )) != ak_error_ok ) {
     ak_asn1_context_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's parameters" );
     goto labexit;
   }

  /* - 3.5. - сохраняеми идентификатор эллиптической кривой
              поскольку мы имеем только указатель на данные, надо найти oid по заданному адресу */

     eoid = ak_oid_context_find_by_engine( identifier );
     while( eoid != NULL ) {
       if( eoid->data == skey->data ) {
           if(( error = ak_asn1_context_add_oid( symkey, eoid->id )) != ak_error_ok )
             return ak_error_message( error, __func__,
                                                    "incorrect adding elliptic curve identifier" );
           break;
       }
       eoid = ak_oid_context_findnext_by_engine( eoid, identifier );
     }

  /* - 3.6. - собственно зашифрованный ключ */
   if(( error = ak_asn1_context_add_skey_content( symkey, skey, ekey, ikey )) != ak_error_ok ) {
     ak_asn1_context_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's parameters" );
   }

  labexit: return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция экспортирует секретный ключ криптографического преобразования в ASN.1 дерево
   с использованием пользовательского пароля.

   Функция формирует ASN.1 структуру следующего формата.
\code
    Container ::= SEQUENCE {
       id OBJECT IDENTIFIER, -- идентификатор контейнера,
                             -- по умоланию, используется значение 1.2.643.2.52.1.127.1.1
       basicKey BasicKeyMetaData, -- структура, необходимая для восстановления хранимой информации
       content Content       -- собственно содержимое
    }
\endcode

Формат структуры метаданных `BasicKeyMetaData`, используемой для восстановления ключа,
зависит от способа генерации ключей. Описание формата при использовании пароля
содержится в документации к функции ak_asn1_context_add_derived_keys_from_password().

Формат структуры `Content` зависит от типа помещаемых данных

 -  для симметричных ключей (ключей алгоритмов блочного шифрования, алгоритмов выработки имитовставки и т.п.)
    описание формата структуры `Content` содержится в документации к функции
    ak_asn1_context_add_symmetric_key_content().

 -  для секретных ключей асимметричных алгоритмов, в частности, электронной подписи
    описание формата структуры `Content` содержится в документации к функции
    ak_asn1_context_add_signature_key_content().

 \param key секретный ключ криптографического преобразования
 \param engine тип криптографического преобразования
 \param root  уровень ASN.1 дерева, в который помещаются экспортируемые данные
 \param password пароль пользователя
 \param pass_size длина пользовательского пароля в октетах
 \param keyname пользовательское описание (имя) ключа -- null-строка,
        длина которой не должна превышать 32 октета; допускается использование null-указателя.

 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_key_context_export_to_asn1_with_password( ak_pointer key, oid_engines_t engine,
                  ak_asn1 root, const char *password, const size_t pass_size, const char *keyname )
{
  int error = ak_error_ok;
  struct bckey ekey, ikey; /* производные ключи шифрования и имитозащиты */
  ak_asn1 asn = NULL, content = NULL;


  /* выполняем проверки */
   if( root == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to root asn1 context" );
   if( key == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using null pointer to block cipher context" );
   if(((ak_skey)key)->oid->engine != engine )
    return ak_error_message( ak_error_oid_engine, __func__,
                                              "using incorrect pointer on symmetric key context" );
   if(( password == NULL ) || ( !pass_size ))
     return ak_error_message( ak_error_invalid_value, __func__, "using incorrect password value" );

 /* 1. помечаем контейнер */
   if(( error = ak_asn1_context_add_oid( asn = ak_asn1_context_new(),
                      ak_oid_context_find_by_name( "libakrypt-container" )->id )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context" );

 /* 2. добавляем структуру для восстановления информации и вырабатываем два производных ключа,
       в данном случае производные ключи вырабатываются из пароля */
   if(( error = ak_asn1_context_add_derived_keys_from_password( asn,
         ak_oid_context_find_by_name( "kuznechik" ),
                                             &ekey, &ikey, password, pass_size )) != ak_error_ok ) {
    ak_asn1_context_delete( asn );
    return ak_error_message( error, __func__, "incorrect creation of derived secret keys" );
   }

 /* 3. добавляем соответствующую структуру с данными */
   if(( error = ak_asn1_context_add_asn1( asn, TSEQUENCE,
                                               content = ak_asn1_context_new( ))) != ak_error_ok ) {
     ak_asn1_context_delete( asn );
     ak_error_message( error, __func__, "incorrect creation of asn1 context for content" );
     goto labexit;
   }

  /* 4. экспортируем данные.
        перед экспортом выполняем фильтр криптографического механизма еще раз */
   switch( engine ) {
    /* формируем ASN.1 дерево для симметричного секретного ключа */
     case block_cipher:
     case hmac_function:
           if(( error = ak_asn1_context_add_symmetric_key_content( content, (ak_skey)key,
                                                         &ekey, &ikey, keyname )) != ak_error_ok ) {
              ak_asn1_context_delete( asn );
              ak_error_message( error, __func__, "incorrect creation of symmetric key content" );
              goto labexit;
           }
           break;

     case sign_function:
           if(( error = ak_asn1_context_add_signature_key_content( content, (ak_skey)key,
                                                         &ekey, &ikey, keyname )) != ak_error_ok ) {
              ak_asn1_context_delete( asn );
              ak_error_message( error, __func__, "incorrect creation of symmetric key content" );
              goto labexit;
           }
          break;

     default:
           ak_asn1_context_delete( asn );
           ak_error_message( error = ak_error_oid_engine, __func__,
                                                         "using usupported engine of secret key" );
           goto labexit;
  }

   error = ak_asn1_context_add_asn1( root, TSEQUENCE, asn );
   labexit:
     ak_bckey_context_destroy( &ekey );
     ak_bckey_context_destroy( &ikey );
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! В процессе своей работы функция создает ASN.1 дерево, содержащее экспортное представление
    секретного ключа, после чего кодирует дерево в виде der-последовательности и сохряняет
    данную последовательность в файл.

    Для шифрования ключа используются производные ключи, вырабатываемые из заданного пароля.

    Если длина имени файла `filename_size` отлична от нуля, то функция предполагает, что имя файла
    пользователем не указано. В этом случае функция формирует имя файла (в качестве имени берется номер ключа)
    и помещает сформированную строку в переменную, на которую указывает `filename`.

    Формат хранения зашифрованных данных зависит от значения параметра `format`.

    Пример вызова функции.
    \code
      // сохранение ключа в файле, имя которого возвращается в переменной filename
       char filemane[256];
       ak_key_context_export_to_derfile_with_password( key, block_cipher,
             "password", 8, "keyname", filename, sizeof( filename ), asn1_der_format );

      // сохранение ключа в файле с заданным именем
       ak_key_context_export_to_derfile_with_password( key, hmac_function,
                            "password", 8, "keyname", "name.key", 0, asn1_pem_format );
    \endcode

    \param key контекст экспортируемого секретного ключа криптографического преобразования;
    контекст должен быть инициализирован ключевым значением, а поле oid должно содержать
    идентификатор алгоритма, для которого предназначен ключ.
    \param engine тип криптографического преобразования, для которого предназначен ключ
    \param password пароль, используемый для генерации ключа шифрования контента
    \param pass_size длина пароля (в октетах)
    \param keyname произвольное, человекочитаемое имя ключа, может быть NULL
    \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `filename_size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
    \param size  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
    \param format формат, в котором зашифрованные данные сохраняются в файл.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_key_context_export_to_file_with_password( ak_pointer key,
       oid_engines_t engine, const char *password, const size_t pass_size, const char *keyname,
                                        char *filename, const size_t size, export_format_t format )
{
   ak_asn1 asn = NULL;
   int error = ak_error_ok;
   ak_skey skey = (ak_skey)key;
   crypto_content_t content = undefined_content;

   const char *file_extensions[] = { /* имена параметризуются значениями типа export_format_t */
    "key",
    "pem"
   };

  /* необходимые проверки */
   if( key == NULL )
     return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
   if( skey->oid->engine != engine )
     return ak_error_message( ak_error_oid_engine, __func__,
                                                 "using incorrect pointer to secret key context" );

  /* формируем имя файла для хранения ключа
     (данное имя в точности совпадает с номером ключа) */
   if( size ) {
     if( size < ( 5 + 2*sizeof( skey->number )) )
       return ak_error_message( ak_error_out_of_memory, __func__,
                                               "insufficent buffer size for secret key filename" );
     memset( filename, 0, size );
     ak_snprintf( filename, size, "%s.%s",
      ak_ptr_to_hexstr( skey->number, sizeof( skey->number), ak_false ), file_extensions[format] );
   }

 /* реализуем фильтр для проверки допустимых типов криптографических преобразований */
  switch( engine ) {
    /* формируем ASN.1 дерево для секретного ключа */
     case block_cipher:
     case hmac_function:
            content = symmetric_key_content;
            break;

     case sign_function:
            content = secret_key_content;
            break;

     default: ak_error_message( ak_error_oid_engine, __func__,
                                                         "using usupported engine of secret key" );
            goto lab1;
            break;
  }

 /* преобразуем ключ в asn1 дерево */
  if(( error = ak_key_context_export_to_asn1_with_password( key, engine,
                    asn = ak_asn1_context_new(), password, pass_size, keyname )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect export of secret key to asn1 context");
    goto lab1;
  }

 /* сохраняем созданное asn1 дерево в файле */
  switch( format ) {
    case asn1_der_format:
      if(( error = ak_asn1_context_export_to_derfile( asn, filename )) != ak_error_ok )
        ak_error_message_fmt( error, __func__,
                               "incorrect export asn1 context to %s (asn1_der_format)", filename );
      break;

    case asn1_pem_format:
      if(( error = ak_asn1_context_export_to_pemfile( asn, filename, content )) != ak_error_ok )
        ak_error_message_fmt( error, __func__,
                               "incorrect export asn1 context to %s (asn1_pem_format)", filename );
      break;
     }

  lab1: if( asn != NULL ) ak_asn1_context_delete( asn );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                          /* Функции импорта ключевой информации */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает двум своим аргументам ссылки на поддеревья,
    содержащие информацию о процедуре выработки производных ключей (basicKey) и собственно
    зашифрованных данных (content).

    \param tlv узел ASN.1 дерева.
    \param basicKey указатель, в который помещается ссылка на дерево секретного ключа
    \param content указатель, в который помещается ссылка на дерево с данными
    \return Функция возвращает истину, если количество ключей в контейнере отлично от нуля.
    В противном случае возвращается ложь.                                                          */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_tlv_context_check_libakrypt_container( ak_tlv tlv, ak_asn1 *basicKey, ak_asn1 *content )
{
  ak_asn1 asn = NULL;
  ak_pointer str = NULL;
  char *id = ak_oid_context_find_by_name( "libakrypt-container" )->id;

  if( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) return ak_false;
  asn = tlv->data.constructed;

 /* проверяем количество узлов */
  if( asn->count != 3 ) return ak_false;

 /* проверяем наличие фиксированного id */
  ak_asn1_context_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
        ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_false;

 /* проверяем совпадение */
  ak_tlv_context_get_oid( asn->current, &str );
  if( strncmp( str, id, strlen( id )) != 0 ) return ak_false;

 /* получаем доступ к структурам */
  ak_asn1_context_next( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) return ak_false;
   else *basicKey = asn->current->data.constructed;

  ak_asn1_context_next( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) return ak_false;
   else *content = asn->current->data.constructed;

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param content уровень ASN.1 дерева, содержащий структуру с контентом
    \return Функция возвращает тип контента. В случае ошибки возвращается значение undefined_content.
    Код ошибки может быть получен с помощью вызова функции ak_error_get_value()                    */
/* ----------------------------------------------------------------------------------------------- */
 crypto_content_t ak_asn1_context_get_content_type( ak_asn1 content )
{
  ak_oid oid = NULL;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;

 /* получаем структуру с параметрами, необходимыми для восстановления ключа */
  ak_asn1_context_first( content );
  if(( DATA_STRUCTURE( content->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( content->current->tag ) != TOBJECT_IDENTIFIER )) return undefined_content;

 /* получаем oid и */
  if(( error = ak_tlv_context_get_oid( content->current, &ptr )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect asn1 structure of content" );
    return undefined_content;
  }
  if(( oid = ak_oid_context_find_by_id( ptr )) == NULL ) return undefined_content;
  if(( oid->engine != identifier ) || ( oid->mode != parameter )) return undefined_content;

 return (crypto_content_t) oid->data;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция должна применяться к ключевому контейнеру типа symmetric_key_content,
    содержащему секретный ключ симметричного криптографического алгоритма.

   \param content указатель на ASN.1 дерево
   \param oid идентификатор криптографического алгоритма
   \param number номер ключа
   \param name имя ключа
   \param resourse данные о ресурсе ключа
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_get_symmetric_key_info( ak_asn1 content,
            ak_oid *oid, ak_pointer *number, size_t *numlen, char **keyname, ak_resource resource )
{
  ak_asn1 asn = NULL;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;

  /* получаем доступ */
   ak_asn1_context_last( content );
   asn = content->current->data.constructed;

  /* получаем идентификатор ключа */
   ak_asn1_context_first( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER ))
      return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                          "context has'nt object identifer for crypto algorithm" );
   ak_tlv_context_get_oid( asn->current, &ptr );
   if(( *oid = ak_oid_context_find_by_id( ptr )) == NULL )
     return ak_error_message( ak_error_invalid_asn1_content, __func__,
                                           "object identifier for crypto algorithm is not valid" );
  /* получаем номер ключа */
   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING ))
      return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                      "context has incorrect asn1 type for symmetric key number" );
   if(( error = ak_tlv_context_get_octet_string( asn->current, number, numlen )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect reading of symmetric key number");

  /* получаем имя/название ключа */
   ak_asn1_context_next( asn );
   if( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE )
      return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                        "context has incorrect asn1 type for symmetric key name" );
   switch( TAG_NUMBER( asn->current->tag )) {
     case TNULL: /* параметр опционален, может быть null */
              ptr = NULL;
              break;
     case TUTF8_STRING:
              ak_tlv_context_get_utf8_string( asn->current, &ptr );
              break;
     default: return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                        "context has incorrect asn1 type for symmetric key name" );
   }

  /* копируем имя ключа, если оно определено */
   *keyname = NULL;
   if( ptr != NULL ) {
     size_t len = 1 + strlen( ptr );
     if(( *keyname = malloc( len )) != NULL ) {
       memset( *keyname, 0, len );
       memcpy( *keyname, ptr, --len );
     }
   }

  /* получаем ресурс */
   ak_asn1_context_next( asn );
   if(( error = ak_tlv_context_get_resource( asn->current, resource )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect reading of symmetric key resource" );

  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция должна применяться к ключевому контейнеру типа secret_key_content,
    содержащему секретный ключ асимметричного криптографического преобразования.

   \param content указатель на ASN.1 дерево
   \param oid идентификатор криптографического алгоритма
   \param number номер ключа
   \param name имя ключа
   \param resourse данные о ресурсе ключа
   \param eoid идентификатор эллиптической кривой, но которой реализуется асимметричный алгоритм
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_get_secret_key_info( ak_asn1 content, ak_oid *oid, ak_pointer *number,
                               size_t *numlen, char **keyname, ak_resource resource, ak_oid *eoid )
{
  ak_asn1 asn = NULL;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;

  /* получаем доступ */
   ak_asn1_context_last( content );
   asn = content->current->data.constructed;

  /* получаем идентификатор ключа */
   ak_asn1_context_first( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER ))
      return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                          "context has'nt object identifer for crypto algorithm" );
   ak_tlv_context_get_oid( asn->current, &ptr );
   if(( *oid = ak_oid_context_find_by_id( ptr )) == NULL )
     return ak_error_message( ak_error_invalid_asn1_content, __func__,
                                           "object identifier for crypto algorithm is not valid" );
  /* получаем номер ключа */
   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING ))
      return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                         "context has incorrect asn1 type for secret key number" );
   if(( error = ak_tlv_context_get_octet_string( asn->current, number, numlen )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect reading of symmetric key number");

  /* получаем имя/название ключа */
   ak_asn1_context_next( asn );
   if( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE )
      return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                           "context has incorrect asn1 type for secret key name" );
   switch( TAG_NUMBER( asn->current->tag )) {
     case TNULL: /* параметр опционален, может быть null */
              ptr = NULL;
              break;
     case TUTF8_STRING:
              ak_tlv_context_get_utf8_string( asn->current, &ptr );
              break;
     default: return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                        "context has incorrect asn1 type for symmetric key name" );
   }

  /* копируем имя ключа, если оно определено */
   *keyname = NULL;
   if( ptr != NULL ) {
     size_t len = 1 + strlen( ptr );
     if(( *keyname = malloc( len )) != NULL ) {
       memset( *keyname, 0, len );
       memcpy( *keyname, ptr, --len );
     }
   }

  /* получаем ресурс */
   ak_asn1_context_next( asn );
   if(( error = ak_tlv_context_get_resource( asn->current, resource )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect reading of secret key resource" );

  /* получаем идентификатор кривой */
   ak_asn1_context_next( asn );
   ak_tlv_context_get_oid( asn->current, &ptr );
   if(( *eoid = ak_oid_context_find_by_id( ptr )) == NULL )
     return ak_error_message( ak_error_invalid_asn1_content, __func__,
                                             "object identifier for elliptic curve is not valid" );
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param akey контекст ASN.1 дерева, содержащий информацию о ключе
    \param skey контекст ключа, значение которого считывается из ASN.1 дерева
    \param ekey контекст ключа шифрования
    \param ikey контекст ключа имитозащиты
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_get_skey( ak_asn1 akey, ak_skey skey, ak_bckey ekey, ak_bckey ikey )
{
  size_t size = 0;
  size_t ivsize  = ekey->bsize >> 1,
         keysize = 2*skey->key_size;
  ak_uint8 out[64];
  ak_asn1 asn = NULL;
  ak_uint8 *ptr = NULL;
  int error = ak_error_ok;
  ak_uint32 oc = 0, u32 = 0;

  /* проверяем наличие памяти (64 байта это 512 бит) */
   if( ikey->bsize > 64 )
     return ak_error_message( ak_error_wrong_length, __func__, "large size for integrity code" );

  /* получаем доступ к поддереву, содержащему зашифрованное значение ключа */
   ak_asn1_context_last( akey );
   if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
                ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
     else asn = akey->current->data.constructed;

   ak_asn1_context_last( asn );
   if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
                ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
     else asn = asn->current->data.constructed;

  /* теперь мы на уровне дерева, который содержит
     последовательность ключевых данных */

  /* проверяем значения полей дерева */
   ak_asn1_context_first( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   ak_tlv_context_get_uint32( asn->current, &u32 );
   if( u32 != data_present_storage ) return ak_error_invalid_asn1_content;

   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   ak_tlv_context_get_uint32( asn->current, &u32 );  /* теперь u32 содержит флаг совместимости с openssl */
   if( u32 !=  (oc = ( ak_uint32 )ak_libakrypt_get_option( "openssl_compability" ))) /* текущее значение */
     ak_libakrypt_set_openssl_compability( u32 );

  /* расшифровываем и проверяем имитовставку */
   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING )) return ak_error_invalid_asn1_tag;
   ak_tlv_context_get_octet_string( asn->current, (ak_pointer *)&ptr, &size );
   if( size != ( ivsize + keysize + ikey->bsize )) /* длина ожидаемых данных */
     return ak_error_invalid_asn1_content;

  /* расшифровываем */
   if(( error = ak_bckey_context_ctr( ekey, ptr+ivsize, ptr+ivsize, keysize+ikey->bsize,
                                                                  ptr, ivsize )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect decryption of skey" );
     goto labexit;
   }

  /* вычисляем имитовставку */
   memset(out, 0, sizeof( out ));
   if(( error = ak_bckey_context_cmac( ikey, ptr, ivsize+keysize,
                                                     out, ikey->bsize )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect evaluation of cmac" );
     goto labexit;
   }
  /* теперь сверяем значения */
   if( !ak_ptr_is_equal_with_log( out, ptr+(ivsize+keysize), ikey->bsize )) {
     ak_error_message( error = ak_error_not_equal_data, __func__,
                                                             "incorrect value of integrity code" );
     goto labexit;
   }

  /* теперь мы полностью уверенны, что данные, хранящиеся в ASN.1 дереве содержат значение ключа */
   ak_mpzn_set_little_endian( (ak_uint64 *)skey->key, (skey->key_size >>2), ptr+ivsize, keysize, ak_true );

  /* меняем значение флага */
   skey->flags |= ak_key_flag_set_mask;

  /* вычисляем контрольную сумму */
   if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                __func__ , "wrong calculation of integrity code" );
  /* маскируем ключ */
   if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                           __func__ , "wrong secret key masking" );
  /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
   skey->flags |= ak_key_flag_set_key;

  /* восстанавливаем изначальный режим совместимости и выходим */
   labexit: if( u32 != oc ) ak_libakrypt_set_openssl_compability( u32 );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция импортирует ключ с ожидаемым типом криптографического алгоритма и
    может применяться для инициализации статических контекстов ключа.
    Для создания динамического контекста ключа можно воспользоваться функцией
    ak_key_context_new_from_derfile().

    \param key указатель на контекст создаваемого ключа.
    \param engine тип криптографического преобразования
    \param filename имя файла в котором хранятся данные
    \param keyname переменная, в которую помещается имя ключа; позднее, выделенная память должна
    быть освобождена вызовом free(). Если имя ключа не определено, переменной присваивается
    значение NULL.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_key_context_import_from_file( ak_pointer key,
                                       oid_engines_t engine, const char *filename, char **keyname )
{
   size_t len = 0;
   ak_oid oid, eoid = NULL;
   int error = ak_error_ok;
   struct bckey ekey, ikey;
   ak_pointer number = NULL;
   struct resource resource;
   crypto_content_t content_type;
   ak_asn1 asn = NULL, basicKey = NULL, content = NULL;

  /* стандартные проверки */
   if( key == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
   if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to filename" );
  /* считываем ключ и преобразуем его в ASN.1 дерево */
   if(( error = ak_asn1_context_import_from_file( asn = ak_asn1_context_new(),
                                                                   filename )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
     goto lab1;
   }

  /* проверяем контейнер на формат хранящихся данных */
   ak_asn1_context_first( asn );
   if( !ak_tlv_context_check_libakrypt_container( asn->current, &basicKey, &content )) {
     ak_error_message( error = ak_error_invalid_asn1_content, __func__,
                                                      "incorrect format of secret key container" );
     goto lab1;
   }

  /* проверяем тип хранящегося ключа
     и получаем данные: тип ключа, ресурс и т.п. */
   memset( &resource, 0, sizeof( struct resource ));
   switch( content_type = ak_asn1_context_get_content_type( content )) {
     case symmetric_key_content:
       if(( error = ak_asn1_context_get_symmetric_key_info(
                            content, &oid, &number, &len, keyname, &resource )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect reading a symmetric key info" );
         goto lab1;
       }
       break;

     case secret_key_content:
       if(( error = ak_asn1_context_get_secret_key_info(
                     content, &oid, &number, &len, keyname, &resource, &eoid )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect reading a symmetric key info" );
         goto lab1;
       }
       break;

     default: ak_error_message( error = ak_error_invalid_asn1_content, __func__,  "incorrect key type" );
       goto lab1;
       break;
   }

  /* проверяем, что контейнер содержит ключ с ожидаемым типом криптографического алгоритма */
   if( oid->engine != engine ) {
     ak_error_message( ak_error_oid_engine, __func__, "incorrect engine of secret key" );
     goto lab1;
   }

  /* получаем производные ключи шифрования и имитозащиты */
   if(( error = ak_asn1_context_get_derived_keys( basicKey, &ekey, &ikey )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of derived keys" );
     goto lab1;
   }

  /* только сейчас создаем ключ */
   if(( error = (( ak_function_create_object *)oid->func.create)( key )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__, "incorrect creation of symmetric key with engine: %s",
                                                           ak_libakrypt_get_engine_name( engine ));
     goto lab2;
   }

  /* для асимметричных ключей необходимо указать параметры эллиптической кривой */
   if( content_type == secret_key_content ) {
     if(( error = ak_signkey_context_set_curve( key,
                                                 (const ak_wcurve)eoid->data )) != ak_error_ok ) {
       ak_error_message( error, __func__, "incorrect assigning an elliptic curve to seсret key");
       (( ak_function_destroy_object *)oid->func.destroy )( key );
     }
   }

  /* присваиваем ключу необходимые данные
     при этом, мы невно пользуемся тем фактом, что указатель на структуру создаваемого ключа
     совпадает с указателем на секретный ключ, т.е.

     (ak_bckey)key == &((ak_bckey)key)->key
     (ak_hmac)key == &((ak_hmac)key)->key   и.т.д. */

   if(( error = ak_skey_context_set_number( key, number, len )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assigning a seсret key number");
     (( ak_function_destroy_object *)oid->func.destroy )( key );
     goto lab2;
   }
   if(( error = ak_asn1_context_get_skey( content, key, &ekey, &ikey )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assigning a seсret key value");
     (( ak_function_destroy_object *)oid->func.destroy )( key );
     goto lab2;
   }
   if(( error = ak_skey_context_set_resource( key, &resource )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assigning a seсret key number");
     (( ak_function_destroy_object *)oid->func.destroy )( key );
     goto lab2;
   }

   lab2: ak_bckey_context_destroy( &ekey );
         ak_bckey_context_destroy( &ikey );
   lab1: if( asn != NULL ) ak_asn1_context_delete( asn );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выполняет действия, эквивалентные последовательности вызовов функций
     ak_bckey_context_create(),
     ak_bckey_context_set_key().

    Тип алгоритма блочного шифрования, номер ключа, его ресурс, а также значение
    считываются из ключевого контейнера. Функция предполагает, что контейнер содержит
    как минимум один ключ и считывает первый из них.

    Если считывается ключ, зашифрованный на пароле пользователя то, по-умолчанию,
    пароль считывается из консоли. Изменить функцию ввода пароля можно с помощью вызова
    функции ak_libakrypt_set_password_read_function().

    \param bkey контекст создаваемого ключа алгоритма блочного шифрования
    \param filename имя файла
    \param keyname переменная, в которую помещается имя ключа; позднее, выделенная память должна
    быть освобождена вызовом free(). Если имя ключа не определено, переменной присвваивается
    значение NULL.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_import_from_file( ak_bckey key, const char *filename, char **keyname )
{
  int error = ak_error_ok;

  if(( error = ak_key_context_import_from_file( key,
                                               block_cipher, filename, keyname )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect creation of block cipher key" );

  if( key->schedule_keys != NULL ) {
     if(( error = key->schedule_keys( &key->key )) != ak_error_ok ) {
       ak_error_message( error, __func__, "incorrect execution of key scheduling procedure" );
       ak_bckey_context_destroy( key );
     }
  }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выполняет действия, эквивалентные последовательности вызовов функций
     ak_hmac_context_create(),
     ak_hmac_context_set_key().

    Тип алгоритма выработки имитовставки HMAC, номер ключа, его ресурс, а также значение
    считываются из ключевого контейнера. Функция предполагает, что контейнер содержит
    как минимум один ключ и считывает первый из них.

    Если считывается ключ, зашифрованный на пароле пользователя то, по-умолчанию,
    пароль считывается из консоли. Изменить функцию ввода пароля можно с помощью вызова
    функции ak_libakrypt_set_password_read_function().

    \param bkey контекст создаваемого ключа алгоритма выработки имитовставки HMAC
    \param filename имя файла
    \param keyname переменная, в которую помещается имя ключа; позднее, выделенная память должна
    быть освобождена вызовом free(). Если имя ключа не определено, переменной присвваивается
    значение NULL.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_import_from_file( ak_hmac key, const char *filename, char **keyname )
{
  int error = ak_error_ok;

  if(( error = ak_key_context_import_from_file( key,
                                              hmac_function, filename, keyname )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect creation of hmac secret key" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выполняет действия, эквивалентные последовательности вызовов функций
     ak_signkey_context_create(),
     ak_signkey_context_set_key(),
     ak_signkey_context_set_curve().

    Тип асимметричного криптографического алгоритма, номер ключа, его ресурс, а также значение
    считываются из ключевого контейнера. Функция предполагает, что контейнер содержит
    как минимум один ключ и считывает первый из них.

    Если считывается ключ, зашифрованный на пароле пользователя то, по-умолчанию,
    пароль считывается из консоли. Изменить функцию ввода пароля можно с помощью вызова
    функции ak_libakrypt_set_password_read_function().

    \param skey контекст создаваемого ключа асимметричного криптографического алгоритма
    \param filename имя файла
    \param keyname переменная, в которую помещается имя ключа; позднее, выделенная память должна
    быть освобождена вызовом free(). Если имя ключа не определено, переменной присвваивается
    значение NULL.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_import_from_file( ak_signkey key, const char *filename, char **keyname )
{
  int error = ak_error_ok;

  if(( error = ak_key_context_import_from_file( key,
                                              sign_function, filename, keyname )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect creation of secret key" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция получает значение открытого ключа из запроса на сертификат,
    разобранного в ASN.1 дерево.

    Функция считывает oid алгоритма подписи и проверяет, что он соответсвует ГОСТ Р 34.12-2012,
    потом функция считывает параметры эллиптической кривой и проверяет, что библиотека поддерживает
    данные параметры. В заключение функция считывает открытый ключ и проверяет,
    что он принадлежит кривой со считанными ранее параметрами.

    \param vkey контекст создаваемого открытого ключа асимметричного криптографического алгоритма
    \param asnkey считанное из файла asn1 дерево
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_context_import_from_asn1_request( ak_verifykey vkey, ak_asn1 asnkey )
{
  size_t size = 0;
  ak_oid oid = NULL;
  struct bit_string bs;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;
  ak_asn1 asn = asnkey, asnl1; /* копируем адрес */
  ak_uint32 val = 0, val64 = 0;

 /* проверяем, то первым элементом содержится ноль */
  ak_asn1_context_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TINTEGER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                          "the first element of root asn1 context be an integer" );
  ak_tlv_context_get_uint32( asn->current, &val );
  if( val != 0 ) return ak_error_message( ak_error_invalid_asn1_content, __func__ ,
                                              "the first element of asn1 context must be a zero" );
 /* второй элемент содержит имя владельца ключа.
    этот элемент должен быть позднее перенесен в контекст открытого ключа */
  ak_asn1_context_next( asn );

 /* третий элемент должен быть SEQUENCE с набором oid и значением ключа */
  ak_asn1_context_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
             "the third element of root asn1 context must be a sequence with object identifiers" );
  asn = asn->current->data.constructed;
  ak_asn1_context_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                               "the first next level element must be a sequence" );
  asnl1 = asn->current->data.constructed;

 /* получаем алгоритм электронной подписи */
  ak_asn1_context_first( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOBJECT_IDENTIFIER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                          "the first element of child asn1 context must be an object identifier" );
  if(( error = ak_tlv_context_get_oid( asnl1->current, &ptr )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect reading an object identifier" );

  if(( oid = ak_oid_context_find_by_id( ptr )) == NULL )
    return ak_error_message_fmt( ak_error_oid_id, __func__,
                                                   "using unsupported object identifier %s", ptr );
  if(( oid->engine != verify_function ) || ( oid->mode != algorithm ))
    return ak_error_message( ak_error_oid_engine, __func__, "using wrong object identifier" );

 /* получаем параметры элиптической кривой */
  ak_asn1_context_next( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
             "the second element of child asn1 context must be a sequence of object identifiers" );
  asnl1 = asnl1->current->data.constructed;

  ak_asn1_context_first( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOBJECT_IDENTIFIER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                     "the first element of last child asn1 context must be an object identifier" );
  if(( error = ak_tlv_context_get_oid( asnl1->current, &ptr )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect reading an object identifier" );

  if(( oid = ak_oid_context_find_by_id( ptr )) == NULL )
    return ak_error_message_fmt( ak_error_oid_id, __func__,
                                "using unsupported object identifier %s for elliptic curve", ptr );
  if(( oid->engine != identifier ) || ( oid->mode != wcurve_params ))
    return ak_error_message( ak_error_oid_engine, __func__, "using wrong object identifier" );

 /* создаем контекст */
  asnl1 = NULL;
  if(( error = ak_verifykey_context_create( vkey, (const ak_wcurve )oid->data )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect creation of verify key context" );

 /* получаем значение открытого ключа */
  ak_asn1_context_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_context_get_bit_string( asn->current, &bs )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect reading a bit string" );
    goto lab1;
  }

 /* считали битовую строку, проверяем что это der-кодировка некоторого целого числа */
  if(( error = ak_asn1_context_decode( asnl1 = ak_asn1_context_new(),
                                                   bs.value, bs.len, ak_false )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect decoding a value of public key" );
    goto lab1;
  }
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOCTET_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                                        "the public key must be an octet string" );
    goto lab1;
  }

 /* считываем строку и разбиваем ее на две половинки */
  val = ( ak_uint32 )vkey->wc->size;
  val64 = sizeof( ak_uint64 )*val;
  ak_tlv_context_get_octet_string( asnl1->current, &ptr, &size );
  if( size != 2*val64 ) {
    ak_error_message_fmt( error = ak_error_wrong_length, __func__ ,
        "the size of public key is equal to %u (must be %u octets)", (unsigned int)size, 2*val64 );
    goto lab1;
  }

 /* копируем данные и проверям, что точка действительно принадлежит кривой */
  ak_mpzn_set_little_endian( vkey->qpoint.x, val, ptr, val64, ak_false );
  ak_mpzn_set_little_endian( vkey->qpoint.y, val, ((ak_uint8*)ptr)+val64, val64, ak_false );
  ak_mpzn_set_ui( vkey->qpoint.z, val, 1 );
  if( ak_wpoint_is_ok( &vkey->qpoint, vkey->wc ) != ak_true ) {
    ak_error_message_fmt( error = ak_error_curve_point, __func__ ,
                                                  "the public key isn't on given elliptic curve" );
    goto lab1;
  }

 /* устанавливаем флаг и выходим */
  vkey->flags = ak_key_flag_set_key;

  if( asnl1 != NULL ) ak_asn1_context_delete( asnl1 );
 return ak_error_ok;

 lab1:
  if( asnl1 != NULL ) ak_asn1_context_delete( asnl1 );
  ak_verifykey_context_destroy( vkey );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция считывает из заданного файла запрос на получение сертификата. Запрос хранится в виде
    asn1 дерева, определяемого Р 1323565.1.023-2018.
    Собственно asn1 дерево может быть храниться в файле в виде обычной der-последовательности,
    либо в виде der-последовательности, дополнительно закодированной в base64.

    \note Функция является конструктором контекста ak_verifykey.
    После считывания asn1 дерева  функция проверяет подпись под открытым ключом и, в случае успешной проверки,
    создает контекст `vkey` и инициирует его необходимыми значениями.

    \param vkey контекст создаваемого открытого ключа асимметричного криптографического алгоритма
    \param filename имя файла
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_context_import_from_request( ak_verifykey vkey, const char *filename )
{
  size_t size = 0;
  ak_tlv tlv = NULL;
  struct bit_string bs;
  ak_uint8 buffer[4096];
  int error = ak_error_ok;
  ak_asn1 root = NULL, asn = NULL, asnkey = NULL;

 /* стандартные проверки */
  if( vkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to filename" );
 /* считываем ключ и преобразуем его в ASN.1 дерево */
  if(( error = ak_asn1_context_import_from_file( root = ak_asn1_context_new(),
                                                                    filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
    goto lab1;
  }

 /* здесь мы считали asn1, декодировали и должны убедиться, что это то самое дерево */
  ak_asn1_context_first( root );
  tlv = root->current;
  if( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) {
    ak_error_message( ak_error_invalid_asn1_tag, __func__, "incorrect structure of asn1 context" );
    goto lab1;
  }

 /* проверяем количество узлов */
  if(( asn = tlv->data.constructed )->count != 3 ) {
    ak_error_message_fmt( ak_error_invalid_asn1_count, __func__,
                                          "root asn1 context contains incorrect count of leaves" );
    goto lab1;
  }

 /* первый узел позволит нам получить значение открытого ключа
    (мы считываем параметры эллиптической кривой, инициализируем контекст значением
    открытого ключа и проверяем, что ключ принадлежит указанной кривой ) */
  ak_asn1_context_first( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) {
    ak_error_message( ak_error_invalid_asn1_tag, __func__, "incorrect structure of asn1 context" );
    goto lab1;
  }
  if(( error = ak_verifykey_context_import_from_asn1_request( vkey,
                                     asnkey = asn->current->data.constructed )) != ak_error_ok ) {
    ak_error_message( ak_error_invalid_asn1_tag, __func__, "incorrect structure of request" );
    goto lab1;
  }

 /* второй узел, в нашей терминологии, содержит идентификатор секретного ключа
    и бесполезен, поскольку вся информация об открытом ключе проверки подписи,
    эллиптической кривой и ее параметрах уже считана. остается только проверить подпись,
    расположенную в последнем, третьем узле запроса. */

 /* 1. Начинаем с того, что готовим данные, под которыми должна быть проверена подпись */
  memset( buffer, 0, size = sizeof( buffer ));
  ak_asn1_context_first( asn );
  if(( error = ak_tlv_context_encode( asn->current, buffer, &size )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                 "incorrect encoding of asn1 context contains of %u octets", (unsigned int) size );
    goto lab1;
  }

 /* 2. Теперь получаем значение подписи из asn1 дерева и сравниваем его с вычисленным значением */
  ak_asn1_context_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_context_get_bit_string( asn->current, &bs )) != ak_error_ok ) {
    ak_error_message( error , __func__ , "incorrect value of bit string in root asn1 context" );
    goto lab1;
  }

 /* 3. Только сейчас проверяем подпись под данными */
  if( ak_verifykey_context_verify_ptr( vkey, buffer, size, bs.value ) != ak_true ) {
    ak_error_message( error = ak_error_get_value(), __func__, "digital signature isn't valid" );
    goto lab1;
  }

 /* 4. В самом конце, после проверки подписи,
    изымаем узел, содержащий имя владельца открытого ключа -- далее этот узел будет перемещен
    в сертификат открытого ключа.
    Все проверки пройдены ранее и нам точно известна структура asn1 дерева. */
  ak_asn1_context_first( asn );
  asn = asn->current->data.constructed;
  ak_asn1_context_first( asn );
  ak_asn1_context_next( asn ); /* нужен второй узел */
  vkey->name = ak_asn1_context_exclude( asn );

  lab1: if( root != NULL ) ak_asn1_context_delete( root );
 return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует фрагмент asn1 дерева, содержащий параметры открытого ключа.
   \param vk контекст открытого ключа
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_verifykey_context_export_to_asn1_value( ak_verifykey vk )
{
  ak_oid ec = NULL;
  ak_tlv tlv = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_asn1 asn = NULL, basn = NULL;
  size_t val64 = sizeof( ak_uint64 )*vk->wc->size;          /* количество октетов в одном вычете */
  ak_uint8 data[ 2*sizeof(ak_uint64)*ak_mpzn512_size +2 ]; /* asn1 представление открытого ключа */

   if(( error = ak_asn1_context_add_oid( asn = ak_asn1_context_new(),
                                                        vk->oid->id )) != ak_error_ok ) goto labex;
   if(( error = ak_asn1_context_add_asn1( asn, TSEQUENCE,
                                              ak_asn1_context_new( ))) != ak_error_ok ) goto labex;
   if(( ec = ak_oid_context_find_by_data( vk->wc )) == NULL ) goto labex;
   ak_asn1_context_add_oid( asn->current->data.constructed, ec->id );
   ak_asn1_context_add_oid( asn->current->data.constructed, vk->ctx.oid->id );

   if(( basn = ak_asn1_context_new()) == NULL ) goto labex;
   if(( error = ak_asn1_context_add_asn1( basn, TSEQUENCE, asn )) != ak_error_ok ) {
     if( basn != NULL ) ak_asn1_context_delete( basn );
     goto labex;
   }

  /* кодируем открытый ключ */
   memset( data, 0, sizeof( data ));
   data[0] = 0x04; data[1] = 0x40;
   ak_wpoint_reduce( &vk->qpoint, vk->wc );
   ak_mpzn_to_little_endian( vk->qpoint.x, vk->wc->size, data+2, val64, ak_false );
   ak_mpzn_to_little_endian( vk->qpoint.y, vk->wc->size, data+2+val64, val64, ak_false );
   bs.value = data;
   bs.len = (1 + val64) << 1;
   bs.unused = 0;
   ak_asn1_context_add_bit_string( basn, &bs );
   if(( tlv = ak_tlv_context_new_constructed( TSEQUENCE^CONSTRUCTED, basn )) == NULL ) {
     ak_asn1_context_delete( basn );
     ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect addition the bit sting with public key value" );
   }
  return  tlv;

 labex:
  if( asn != NULL ) ak_asn1_context_delete( asn );
  ak_error_message( error, __func__, "incorrect export of public key to asn1 tree" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует asn1 дерево с запросом на сертификат открытого ключа.

    Выполняются следующие действия:

    - формируется tlv элемент, содержащий имя владельца, параметры алгоритма и значение ключа,
    - tlv элемент кодируется в der-последовательность,
    - вырабатывается подпись под der-последовательностью,
    - идентификатор алгоритма выработки подписи и значение подписи также помещаются в asn1 дерево.

   \param vk контекст открытого ключа
   \param sk контекст секретного ключа
   \param a уровень asn1 дерева, в который помещается запрос на сертификат.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_context_export_to_asn1_request( ak_verifykey vk, ak_signkey sk, ak_asn1 a )
{
  ak_tlv tlv = NULL;
  ak_asn1 asn = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_uint8 data[4096], s[128];
  size_t size = sizeof( data );

  if( a == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 context" );
  if( ak_signkey_context_get_tag_size( sk ) > sizeof( s ))
    ak_error_message( ak_error_wrong_length, __func__,
                                   "using digital signature algorithm with very large signature" );

 /* 1. Создаем последовательность, которая будет содержать даннве запроса */
  if(( error = ak_asn1_context_add_asn1( a, TSEQUENCE^CONSTRUCTED,
                                                  asn = ak_asn1_context_new())) != ak_error_ok ) {
    if( asn != NULL ) ak_asn1_context_delete( asn );
    return ak_error_message( error, __func__, "incorrect creation of first level sequence");
  }

 /* 2. Создаем tlv элемент, для которого, потом, будет вычисляться электронная подпись */
   tlv = ak_tlv_context_new_constructed( TSEQUENCE^CONSTRUCTED, asn = ak_asn1_context_new( ));
  /* добавляем ноль */
   ak_asn1_context_add_uint32( asn, 0 );
  /* переносим asn1 дерево с расширенным именем в asn1 дерево формируемого запроса */
   ak_asn1_context_add_tlv( asn, vk->name );
   vk->name = NULL;
  /* помещаем информацию об алгоритме и открытом ключе */
   ak_asn1_context_add_tlv( asn, ak_verifykey_context_export_to_asn1_value( vk ));
  /* 0x00 это помещаемое в CONTEXT_SPECIFIC значение */
   ak_asn1_context_add_asn1( asn, CONTEXT_SPECIFIC^0x00, ak_asn1_context_new( ));

  /* 3. Помещаем tlv элемент в основное дерево */
   ak_asn1_context_add_tlv( a->current->data.constructed, tlv );


  /* 3. Помещаем идентификатор алгоритма выработки подписи */
   ak_asn1_context_add_asn1( a->current->data.constructed,
                               TSEQUENCE^CONSTRUCTED, asn = ak_asn1_context_new());
   ak_asn1_context_add_oid( asn, sk->key.oid->id );

  /* 4. Помещаем bit-string со значением подписи */
   if(( error =  ak_tlv_context_encode( tlv, data, &size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect encoding of asn1 context");

   memset( s, 0, sizeof( s ));
   if(( error = ak_signkey_context_sign_ptr( sk, data, size, s, sizeof( s ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect signing internal data" );
   bs.value = s;
   bs.len = ak_signkey_context_get_tag_size( sk );
   bs.unused = 0;
   if(( error = ak_asn1_context_add_bit_string( a->current->data.constructed, &bs )) != ak_error_ok )
     ak_error_message( error, __func__, "incorrect adding a digital signature value" );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию
    и сохраняет созданное дерево в файл, который называется "запросом на сертификат".

   \note Контекст секретного ключа `sk` должен соотвествовать контектсу открытого ключа `vk`.
   В противном случае нельзя будет проверить электронную подпись под окрытым ключом --
   запрос на сертификат, по сути, является урезанной версией самоподписанного сертификата.
   Отсюда следует, что нельзя содать запрос на сертификат ключа, который не поддерживает
   алгоритм какой-либо алгоритм подписи (например ключ на кривой в 640 бит).
   Такие ключи должны сразу помещаться в сертификат.

   \param vk контекст открытого ключа
   \param sk контекст секретного ключа
   \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `filename_size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
   \param size  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
   \param format формат, в котором сохраняются данные - der или pem.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_context_export_to_request( ak_verifykey vk, ak_signkey sk,
                                       char *filename, const size_t size, export_format_t format )
{
  ak_asn1 asn = NULL;
  int error = ak_error_ok;

  if( vk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to public key context" );
  if( sk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                               "using null pointer to file name" );
  if( size != 0 ) { /* передан запрос на генерацию имени файла с запросом */
    if( size < 12 ) return ak_error_message( ak_error_wrong_length, __func__,
                                               "using small buffer to storing request file name" );
     else strncpy( filename, "pubkey.csr", size );
  }

 /* 1. Создаем asn1 дерево */
  if(( error = ak_verifykey_context_export_to_asn1_request( vk, sk,
                                                 asn = ak_asn1_context_new( ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation af asn1 context" );
    goto labexit;
  }

 /* 2. Сохраняем созданное дерево в файл */
  switch( format ) {
    case asn1_der_format:
      if(( error = ak_asn1_context_export_to_derfile( asn, filename )) != ak_error_ok )
        ak_error_message_fmt( error, __func__,
                              "incorrect export asn1 context to file %s in der format", filename );
      break;

    case asn1_pem_format:
      if(( error = ak_asn1_context_export_to_pemfile( asn, filename,
                                                    public_key_request_content )) != ak_error_ok )
        ak_error_message_fmt( error, __func__,
                              "incorrect export asn1 context to file %s in pem format", filename );
      break;
  }

  labexit:
    if( asn != NULL ) asn = ak_asn1_context_delete( asn );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание tlv узла, содержащего структуру TBSCertificate версии 1 (без расширений)

   \param vk контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param sk контекст ключа подписи, содержащий параметры центра сертификации
   \param version конечная версия сертиката
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_verifykey_context_export_to_tbs( ak_verifykey vk, ak_signkey sk,
                                                                           const ak_uint8 version )
{
  ak_tlv tbs = NULL, tlv = NULL;
  ak_asn1 asn = NULL, tbasn = NULL;

  if( vk == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to public key" );
    return NULL;
  }
  if(( tbs = ak_tlv_context_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
   else tbasn = tbs->data.constructed;

 /* теперь создаем дерево сертификата в соответствии с Р 1323565.1.023-2018
    version: начинаем с размещения версии сертификата, т.е. ветки следующего вида
     ┐
     ├[0]┐
     │   └INTEGER 2 (величина 2 является максимально возможным значением ) */

  ak_asn1_context_add_asn1( tbasn, CONTEXT_SPECIFIC^0x00, asn = ak_asn1_context_new( ));
  if( asn != NULL ) ak_asn1_context_add_uint32( asn, ak_min( version, 2 ));
    else {
      ak_error_message( ak_error_get_value(), __func__,
                                              "incorrect creation of certificate version context");
      goto labex;
    }

 /* serialNumber: вырабатываем и добавляем номер сертификата */
  memset( vk->number, 0, sizeof( vk->number ));
  if( ak_skey_context_geneate_unique_number( vk->number, sizeof( vk->number )) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__,
                                              "incorrect generation of public key unique number" );
    goto labex;
  }
  ak_asn1_context_add_mpzn( tbasn, vk->number, ak_mpzn256_size );

 /* signature: указываем алгоритм подписи (это будет повторено еще раз при выработке подписи) */
  ak_asn1_context_add_tlv( tbasn, tlv = ak_tlv_context_new_sequence( ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                          "incorrect generation of digital signature identifier" );
    goto labex;
  }
  ak_asn1_context_add_oid( tlv->data.constructed, sk->key.oid->id );

 /* issuer: вставляем информацию о расширенном имени лица, подписывающего ключ
    (эмитента, выдающего сертификат) */
  ak_asn1_context_add_tlv( tbasn, sk->name );
  sk->name = NULL;

 /* validity: вставляем информацию в времени действия ключа */
  ak_asn1_context_add_validity( tbasn,
                               sk->key.resource.time.not_before, sk->key.resource.time.not_after );

 /* subject: вставляем информацию о расширенном имени владельца ключа  */
  ak_asn1_context_add_tlv( tbasn, vk->name );
  vk->name = NULL;

 /* subjectPublicKeyInfo: вставляем информацию об открытом ключе */
  ak_asn1_context_add_tlv( tbasn, tlv = ak_verifykey_context_export_to_asn1_value( vk ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                               "incorrect generation of subject public key info" );
    goto labex;
  }
 return tbs;

  labex: if( tbs != NULL ) tbs = ak_tlv_context_delete( tbs );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает asn1 дерево, содержащее сертификат открытого ключа.

   \param vk контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param sk контекст ключа подписи, содержащий параметры центра сертификации
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 static ak_asn1 ak_verifykey_context_export_to_asn1_certificate( ak_verifykey vk, ak_signkey sk )
{
  size_t len = 0;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_asn1 certificate = NULL;
  ak_uint8 encode[4096], out[128];
  ak_tlv tlv = NULL, ta = NULL, tbs = NULL;

 /* создаем контейнер для сертификата */
  if(( error = ak_asn1_context_add_tlv( certificate = ak_asn1_context_new(),
                                         tlv = ak_tlv_context_new_sequence( ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect addition of tlv context" );
    goto labex;
  }
  if( tlv == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "incorrect creation of tlv context" );
    goto labex;
  }

 /* создаем сертификат первой версии */
  if(( tbs = ak_verifykey_context_export_to_tbs( vk, sk, 0 )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                  "incorrect creation of tbsCertificate element" );
    goto labex;
  }

 /* добавляем расширения
    если расширения добавляются, то должна быть версия 3 */


 /* вставляем в основное дерево созданный элемент */
  ak_asn1_context_add_tlv( tlv->data.constructed, tbs );
 /* добавляем информацию о алгоритме подписи */
  ak_asn1_context_add_tlv( tlv->data.constructed, ta = ak_tlv_context_new_sequence( ));
  if( ta == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                          "incorrect generation of digital signature identifier" );
    goto labex;
  }
  ak_asn1_context_add_oid( ta->data.constructed, sk->key.oid->id );

 /* вырабатываем подпись */
  len = sizeof( encode );
  if(( error = ak_tlv_context_encode( tbs, encode, &len )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encoding an asn1 context" );
    goto labex;
  }
  if(( error = ak_signkey_context_sign_ptr( sk, encode, len, out, sizeof( out ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect generation of digital signature" );
    goto labex;
  }

 /* добавляем подпись в основное дерево */
  bs.value = out;
  bs.len = ak_signkey_context_get_tag_size( sk );
  bs.unused = 0;
  if(( error = ak_asn1_context_add_bit_string( tlv->data.constructed, &bs )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect adding a digital signature value" );
    goto labex;
  }

 return certificate;

  labex: if( certificate != NULL ) certificate = ak_asn1_context_delete( certificate );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию,
    помещает в это же дерево информацию о подписывающем лице и правилах применения ключа.
    После этого сформированное дерево сохраняется в файл в заданном пользователем формате.

   \param vk контекст открытого ключа
   \param sk контекст секретного ключа
   \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `filename_size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
   \param size  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
   \param format формат, в котором сохраняются данные - der или pem.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_context_export_to_certificate( ak_verifykey vk, ak_signkey sk,
                                        char *filename, const size_t size, export_format_t format )
{
  int error = ak_error_ok;
  ak_asn1 certificate = NULL;
  const char *file_extensions[] = { /* имена параметризуются значениями типа export_format_t */
   "cer",
   "crt"
  };

 /* необходимые проверки */
  if( vk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to public key context" );
  if( sk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
 /* вырабатываем asn1 дерево */
  if(( certificate = ak_verifykey_context_export_to_asn1_certificate( vk, sk )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__,
                                            "incorrect creation of asn1 context for certificate" );
 /* формируем имя файла для хранения ключа
    (данное имя в точности совпадает с номером ключа) */
  if( size ) {
    if( size < ( 5 + 2*sizeof( vk->number )) ) {
      ak_error_message( error = ak_error_out_of_memory, __func__,
                                              "insufficent buffer size for certificate filename" );
      goto labex;
    }
    memset( filename, 0, size );
    ak_snprintf( filename, size, "%s.%s",
                       ak_mpzn_to_hexstr( vk->number, ak_mpzn256_size ), file_extensions[format] );
  }

 /* 2. Сохраняем созданное дерево в файл */
  switch( format ) {
    case asn1_der_format:
      if(( error = ak_asn1_context_export_to_derfile( certificate, filename )) != ak_error_ok )
        ak_error_message_fmt( error, __func__,
                               "incorrect export certificate to file %s in der format", filename );
      break;

    case asn1_pem_format:
      if(( error = ak_asn1_context_export_to_pemfile( certificate, filename,
                                                            public_key_content )) != ak_error_ok )
        ak_error_message_fmt( error, __func__,
                              "incorrect export asn1 context to file %s in pem format", filename );
      break;
  }

  labex: if( certificate != NULL ) certificate = ak_asn1_context_delete( certificate );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup backend_keys Функции внутреннего интерфейса. Управление ключами.
 * @{

  Общая схема разбора ключевого контейнера может быть представлена следующим образом.

 \code
   cчитать ASN.1 дерево root из файла
   if( root->count == 0 ) завершить работу

   do { // цикл, который перебирает все узлы верхнего уровня

         if( ak_tlv_context_check_libakrypt_container(
              root->current,  // текущий узел
             &basicKey, // часть дерева, отвечающая за генерацию производных ключей
             &content   // часть дерева, содержащая собственно данные
          )) != ak_error_ok ) continue;

         // вырабатываем производные ключи
          ak_asn1_context_get_derived_keys( basicKey, &ekey, &ikey );
         // определяем тип ключа
          switch( ak_asn1_context_get_content_type( content )) {
              case symmetric_key_content: // в контейнере находится секретный ключ
                                          // симметричного преобразования

                  // получаем информацию о ключе
                   ak_asn1_context_get_symmetric_key_info( &oid, &number, &len, &name, &resource );
                  // содаем ключ
                   oid->func.create( &key );
                  //  присваиваем значение
                   ak_asn1_context_get_skey( content, &key.key, &ekey, &ikey );
                  // присваиваем номер ключа
                   ak_skey_context_set_number( &key.key, number, len );
                  // присваиваем реурс
                   ak_skey_context_set_resource( &key.key, &resource );

                  // теперь созданный ключ можно использовать
                   break;

              case secret_key_content: // в контейнере находится секретный ключ
                                       // асимметричного преобразования
                   break;
              default:  // нераспознанный тип контента
                   break;
          }

   } while( ak_asn1_context_next( root ));
 \endcode

 * @}*/

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-asn1-keys.c                                                                      */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_keys.c  */
/* ----------------------------------------------------------------------------------------------- */
