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

Формат структуры `SymmetricKeyParameters` определяется следующим образом.
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
/*! Функция формирует ASN.1 структуру следующего формата.
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

Формат структуры `Content` зависит от типа помещаемых данных. Для симметричных ключей
(ключей алгоритмов блочного шифрования, алгоритмов выработки имитовставки и т.п.)
описание формата структуры `Content` содержится в документации к функции
ak_asn1_context_add_symmetric_key_content().

 \param key ключ симмертричного криптографического преобразования
 \param engine тип криптографического преобразования
 \param root  уровень ASN.1 дерева, в который помещаются экспортируемые данные
 \param password пароль пользователя
 \param pass_size длина пользовательского пароля в октетах
 \param keyname пользовательское описание (имя) ключа -- null-строка,
        длина которой не должна превышать 32 октета; допускается использование null-указателя.

 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_symmetric_key_context_export_to_asn1_with_password( ak_pointer key, oid_engines_t engine,
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

  /* 4. экспортируем данные */
   if(( error = ak_asn1_context_add_symmetric_key_content( content, (ak_skey)key,
                                                         &ekey, &ikey, keyname )) != ak_error_ok ) {
     ak_asn1_context_delete( asn );
     ak_error_message( error, __func__, "incorrect creation of symmetric key content" );
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

    Пример вызова функции.
    \code
       char filemane[256];

      // сохранение ключа в файле, имя которого возвращается в переменной filename
       ak_symmetric_key_context_export_to_derfile_with_password( key, block_cipher,
                               "password", 8, "keyname", filename, sizeof( filename ));

      // сохранение ключа в файле с заданным именем
       ak_symmetric_key_context_export_to_derfile_with_password( key, hmac_function,
                                             "password", 8, "keyname", "name.key", 0 );
    \endcode

    \param key контекст экспортируемого ключа симметричного криптографического преобразования;
    контекст должен быть инициализирован ключевым значением, а поле oid должно содержать
    идентификатор алгоритма, для которого предназначен ключ.
    \param engine тип криптографичсекого преобразования, для которого предназначен ключ
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

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_symmetric_key_context_export_to_derfile_with_password( ak_pointer key,
       oid_engines_t engine, const char *password, const size_t pass_size, const char *keyname,
                                                               char *filename, const size_t size )
{
   ak_asn1 asn = NULL;
   int error = ak_error_ok;
   ak_skey skey = (ak_skey)key;

  /* необходимые проверки */
   if( key == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to symmetric key context" );
   if( skey->oid->engine != engine )
     return ak_error_message( ak_error_oid_engine, __func__,
                                              "using incorrect pointer on symmetric key context" );
  /* формируем имя файла для хранения ключа
     (данное имя в точности совпадает с номером ключа) */
   if( size ) {
     if( size < ( 5 + 2*sizeof( skey->number )) )
       return ak_error_message( ak_error_out_of_memory, __func__,
                                        "insufficent filename buffer size for secret key number" );
     memset( filename, 0, size );
     ak_snprintf( filename, size, "%s.key",
                                ak_ptr_to_hexstr( skey->number, sizeof( skey->number), ak_false ));
   }

  /* формируем ASN.1 дерево для секретного ключа */
   if(( error = ak_symmetric_key_context_export_to_asn1_with_password( key, engine,
                    asn = ak_asn1_context_new(), password, pass_size, keyname )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect export of block cipher key to asn1 context");
     goto lab1;
   }

  /* сохраняем дерево в файле */
   if(( error = ak_asn1_context_export_to_derfile( asn, filename )) != ak_error_ok )
     ak_error_message( error, __func__, "incorrect saving asn1 context to derfile");

  lab1: if( asn != NULL ) ak_asn1_context_delete( asn );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                          /* Функции импорта ключевой информации */
/* ----------------------------------------------------------------------------------------------- */
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
    содержащему секретный ключ симметричного алгоритма шифрования.

   \param content указатель на ASN.1 дерево
   \param oid идентификатор криптографического алгоритма
   \param number номер ключа
   \param name имя ключа
   \param resourse данные о ресурсе ключа
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_get_symmetric_key_info( ak_asn1 content,
                ak_oid *oid, ak_pointer *number, size_t *numlen, char **name, ak_resource resource )
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
              *name = NULL;
              break;
     case TUTF8_STRING:
              ak_tlv_context_get_utf8_string( asn->current, (ak_pointer *)name );
              break;
     default: return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                        "context has incorrect asn1 type for symmetric key name" );
   }

  /* получаем ресурс */
   ak_asn1_context_next( asn );
   if(( error = ak_tlv_context_get_resource( asn->current, resource )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect reading of symmetric key resource" );

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
/*! \param key указатель на контекст создаваемого ключа.
    \param engine тип криптографического преобразования
    \param filename имя файла в котором хранятся данные
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_symmetric_key_context_import_from_derfile( ak_pointer key,
                                                        oid_engines_t engine, const char *filename )
{
   ak_oid oid;
   size_t len = 0;
   char *name = NULL;
   int error = ak_error_ok;
   struct bckey ekey, ikey;
   ak_pointer number = NULL;
   struct resource resource;
   ak_asn1 asn = NULL, basicKey = NULL, content = NULL;

  /* стандартные проверки */
   if( key == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to symmetric key context" );
   if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to filename" );
  /* считываем ключ и преобразуем его в ASN.1 дерево */
   if(( error = ak_asn1_context_import_from_derfile( asn = ak_asn1_context_new(),
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
   if( ak_asn1_context_get_content_type( content ) != symmetric_key_content ) {
     ak_error_message( error = ak_error_invalid_asn1_content, __func__,  "incorrect key type" );
     goto lab1;
   }

  /* получаем данные: тип ключа, ресурс и т.п. */
   memset( &resource, 0, sizeof( struct resource ));
   if(( error = ak_asn1_context_get_symmetric_key_info(
                               content, &oid, &number, &len, &name, &resource )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect reading a symmetric key info" );
     goto lab1;
   }

  /* проверяем, что контейнер содержит ключ с корректным типом криптографическго алгоритма */
   if( oid->engine != engine ) {
     ak_error_message( ak_error_oid_engine, __func__, "incorrect engine of symmetric key" );
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
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_import_from_derfile( ak_bckey key, const char *filename )
{
  int error = ak_error_ok;

  if(( error = ak_symmetric_key_context_import_from_derfile( key,
                                                        block_cipher, filename )) != ak_error_ok )
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
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_context_import_from_derfile( ak_hmac key, const char *filename )
{
  int error = ak_error_ok;

  if(( error = ak_symmetric_key_context_import_from_derfile( key,
                                                       hmac_function, filename )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect creation of hmac secret key" );

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
/*                                                                                 ak_asn1_keys.c  */
/* ----------------------------------------------------------------------------------------------- */
