/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2020 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_asn1_keys.c                                                                            */
/*  - содержит описания функций, предназначенных для экспорта/импорта ключевой информации          */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_STRING_H
 #include <string.h>
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
/*! \brief Функция вырабатывает производные ключи шифрования и имитозащиты контента из пароля и
    экспортирует в ASN.1 дерево параметры ключа, необходимые для восстановления.
    \details Функция вычисляет последовательность октетов `basicKey` длиной 64 октета
    в соответствии со следующим равенством

\code
    basicKey = PBKDF2( password, salt, count, 64 )
\endcode

в котором

 - величина `salt` принимает случайное значение,
 - `count` это значение опции `pbkdf2_iteration_count`,
 - константа 64 означает длину вырабатываемого ключа в октетах

 Далее, функция определяет производные ключи шифрования и имитозащиты равенствами

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
      basicKey PBKDF2BasicKey  OPTIONAL,
                                 -- данные, необходимые для выработки и использования
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
 static int ak_asn1_add_derived_keys_from_password( ak_asn1 root, ak_oid oid , ak_bckey ekey,
                                       ak_bckey ikey, const char *password, const size_t pass_size )
{
  ak_uint8 salt[32]; /* случайное значение для генерации ключа шифрования контента */
  ak_uint8 derived_key[64]; /* вырабатываемый из пароля ключевой материал,
                               из которого формируются производные ключи шифрования и имитозащиты */
  int error = ak_error_ok;
  ak_asn1 asn1 = NULL, asn2 = NULL, asn3 = NULL;

 /* 1. вырабатываем случайное значение и производный ключевой материал */
   if(( error = ak_bckey_create_oid( ekey, oid )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of encryption cipher key" );

   ak_random_ptr( &ekey->key.generator, salt, sizeof( salt ));
   if(( error = ak_hmac_pbkdf2_streebog512(
                (ak_pointer) password,                             /* пароль */
                 pass_size,                                 /* размер пароля */
                 salt,                           /* инициализационный вектор */
                 sizeof( salt ),        /* размер инициализационного вектора */
                 (size_t) ak_libakrypt_get_option_by_name( "pbkdf2_iteration_count" ),
                 64,                         /* размер вырабатываемого ключа */
                 derived_key                   /* массив для хранения данных */
     )) != ak_error_ok ) {
      ak_bckey_destroy( ekey );
      return ak_error_message( error, __func__, "incorrect creation of derived key" );
   }

 /* 2. инициализируем контексты ключа шифрования контента и ключа имитозащиты */
   if(( error = ak_bckey_set_key( ekey, derived_key, 32 )) != ak_error_ok ) {
     ak_bckey_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to encryption key" );
   }
   if(( error = ak_bckey_create_oid( ikey, oid )) != ak_error_ok ) {
     ak_bckey_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect creation of integrity key" );
   }
   if(( error = ak_bckey_set_key( ikey, derived_key+32, 32 )) != ak_error_ok ) {
     ak_bckey_destroy( ikey );
     ak_bckey_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to integrity key" );
   }
  /* очищаем использованную память */
   ak_ptr_wipe( derived_key, sizeof( derived_key ), &ikey->key.generator );

 /* 3. собираем ASN.1 дерево - снизу вверх */
   if(( ak_asn1_create( asn3 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_destroy( ikey );
     ak_bckey_destroy( ekey );
     return ak_error_message( error, __func__,
                                         "incorrect creation of PBKDF2Parameters asn1 structure" );
   }
   ak_asn1_add_oid( asn3, ak_oid_find_by_name( "hmac-streebog512" )->id[0] );
   ak_asn1_add_octet_string( asn3, salt, sizeof( salt ));
   ak_asn1_add_uint32( asn3,
                         ( ak_uint32 )ak_libakrypt_get_option_by_name( "pbkdf2_iteration_count" ));

   if(( ak_asn1_create( asn2 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_destroy( ikey );
     ak_bckey_destroy( ekey );
     ak_asn1_delete( asn3 );
     return ak_error_message( error, __func__,
                                           "incorrect creation of PBKDF2BasicKey asn1 structure" );
   }
   ak_asn1_add_oid( asn2, oid->id[0] );
   ak_asn1_add_asn1( asn2, TSEQUENCE, asn3 );

   if(( ak_asn1_create( asn1 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_destroy( ikey );
     ak_bckey_destroy( ekey );
     ak_asn1_delete( asn2 );
     return ak_error_message( error, __func__,
                                         "incorrect creation of BasicKeyMetaData asn1 structure" );
   }
   ak_asn1_add_oid( asn1, ak_oid_find_by_name( "pbkdf2-basic-key" )->id[0] );
   ak_asn1_add_asn1( asn1, TSEQUENCE, asn2 );

  /* помещаем в основное ASN.1 дерево структуру BasicKeyMetaData */
 return ak_asn1_add_asn1( root, TSEQUENCE, asn1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для ввода пароля используется функция, на которую указывает ak_function_defaut_password_read.
    Если этот указатель не установлен (то есть равен NULL), то выполняется чтение пароля
    из терминала, владеющего текущим процессом, с помощью функции ak_password_read().

    Формат ASN.1 структуры, хранящей параметры восстановления производных ключей,
    содержится в документации к функции ak_asn1_add_derived_keys_from_password().

 \param akey контекст ASN.1 дерева, содержащий информацию о ключе (структура `BasicKeyMetaData`)
 \param ekey контекст ключа шифрования
 \param ikey контекст ключа имитозащиты
 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_get_derived_keys( ak_asn1 akey, ak_bckey ekey, ak_bckey ikey )
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
  ak_asn1_first( akey );
  if( akey->count != 2 ) return ak_error_invalid_asn1_count;

 /* проверяем параметры */
  if(( DATA_STRUCTURE( akey->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( akey->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
  ak_tlv_get_oid( akey->current, &ptr );
  oid = ak_oid_find_by_name( "pbkdf2-basic-key" );
  if( strncmp( oid->id[0], ptr, strlen( oid->id[0] )) != 0 )
    return ak_error_invalid_asn1_content;
   /* в дальнейшем, здесь вместо if должен появиться switch,
      который разделяет все три возможных способа генерации производных ключей
      сейчас поддерживается только способ генерации из пароля */

  ak_asn1_next( akey );
  if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
              ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = akey->current->data.constructed;

 /* получаем информацию о ключе и параметрах его выработки */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;

  ak_tlv_get_oid( asn->current, &ptr );
  eoid = ak_oid_find_by_id( ptr ); /* идентификатор ключа блочного шифрования */
  if(( eoid->engine != block_cipher ) || ( eoid->mode != algorithm ))
    return ak_error_invalid_asn1_tag;

 /* получаем доступ к параметрам алгоритма генерации производных ключей */
  ak_asn1_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
              ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = asn->current->data.constructed;

 /* получаем из ASN.1 дерева параметры, которые будут передаватьсяв функцию pbkdf2 */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
  ak_tlv_get_oid( asn->current, &ptr );
  oid = ak_oid_find_by_name( "hmac-streebog512" );
  if( strncmp( oid->id[0], ptr, strlen( oid->id[0] )) != 0 )
    return ak_error_invalid_asn1_content;

  ak_asn1_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING )) return ak_error_invalid_asn1_tag;
  ak_tlv_get_octet_string( asn->current, &ptr, &size ); /* инициализационный вектор */

  ak_asn1_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
  ak_tlv_get_uint32( asn->current, &u32 ); /* число циклов */

 /* вырабатываем производную ключевую информацию */
   if( ak_function_default_password_read == NULL ) {
     fprintf( stdout, "password: "); fflush( stdout );
     error = ak_password_read( password, sizeof( password ));
     fprintf( stdout, "\n" );
   } else error = ak_function_default_password_read( password, sizeof( password ));
   if( error != ak_error_ok ) return error;

 /* 1. получаем пользовательский пароль и вырабатываем производную ключевую информацию */
   error = ak_hmac_pbkdf2_streebog512( (ak_pointer) password, strlen( password ),
                                                                 ptr, size, u32, 64, derived_key );
   memset( password, 0, sizeof( password ));
   if( error != ak_error_ok ) return error;

 /* 2. инициализируем контексты ключа шифрования контента и ключа имитозащиты */
   if(( error = ak_bckey_create_oid( ekey, eoid )) != ak_error_ok ) {
     memset( derived_key, 0, sizeof( derived_key ));
     return ak_error_message( error, __func__, "incorrect creation of encryption cipher key" );
   }
   if(( error = ak_bckey_set_key( ekey, derived_key, 32 )) != ak_error_ok ) {
     ak_ptr_wipe( derived_key, sizeof( derived_key ), &ekey->key.generator );
     ak_bckey_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to encryption key" );
   }

   if(( error = ak_bckey_create_oid( ikey, eoid )) != ak_error_ok ) {
     ak_ptr_wipe( derived_key, sizeof( derived_key ), &ekey->key.generator );
     ak_bckey_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect creation of integrity key" );
   }
   if(( error = ak_bckey_set_key( ikey, derived_key+32, 32 )) != ak_error_ok ) {
     ak_ptr_wipe( derived_key, sizeof( derived_key ), &ekey->key.generator );
     ak_bckey_destroy( ikey );
     ak_bckey_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to integrity key" );
   }
  /* очищаем использованную память */
   ak_ptr_wipe( derived_key, sizeof( derived_key ), &ikey->key.generator );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                         /* Функции экспорта ключевой информации */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Формирование имени файла, в который будет помещаться секретный или открытый ключ.

     - если `fsize` равен нулю, а указатель `filename` отличен от `NULL`, то функция
       предполагает, что `filename` уже содержит имя файла и ничего не вырабатывает.
     - если `fsize` отличен от нуля, а указатель `filename` отличен от `NULL`, то функция
       предполагает, что `filename` является указателем на область памяти, в которую будем
       помещено имя файла. Размер этой памяти определеяется значением переменной `size`.

    В качестве имени файла выбирается номер ключа, содержащийся в `buffer`,
    к которому приписывается расширение, зависящее от запрашиваемого пользователем формата.

    \param buffer Указатель на номер ключа
    \param bufsize Размер номера ключа в октетах
    \param filename Указатель на область памяти для имени файл;
    указатель должен быть отличен от `NULL`
    \param fsize Размер области памяти (в октетах )
    \param format Формат, в котором сохраняются данные.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_generate_file_name_from_buffer( ak_uint8 *buffer, const size_t bufsize,
                                       char *filename, const size_t fsize, export_format_t format )
{
  const char *file_extensions[] = { /* имена параметризуются значениями типа export_format_t */
    "key",
    "pem"
  };

  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to filename buffer" );
 /* формируем имя, только если длина отлична от нуля */
  if( fsize ) {
    if( fsize < 6 ) return ak_error_message( ak_error_out_of_memory, __func__,
                                               "insufficent buffer size for secret key filename" );
     memset( filename, 0, fsize );
     ak_snprintf( filename, fsize, "%s.%s",
      ak_ptr_to_hexstr( buffer, ak_min( bufsize, fsize-5 ), ak_false ), file_extensions[format] );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует ASN.1 структуру, содержащую зашифрованное значение секретного ключа.

 Формируеммая структура определяется следующим образом.

 \code
   EncryptedContent ::= SEQUENCE {
      dataStorage DataStorage,  -- метка наличия ключа
      compability OpenSSLCompability, -- флаг формата данных,
                                         совместимого с форматом библиотеки OpenSSL
      encryptedKey OCTET STRING -- собственно ключ, в защифрованном виде
   }
 \endcode

где

 \code
   DataStorage ::= INTEGER {
        data_not_present_storage(0), -- данные не содержатся
        data_present_storage(1), -- данные в наличии
        external_file_storage(2) -- данные находятся во внешнем файле или носителе
  }

  OpenSSLCompability ::= INTEGER {
        non_compatibly (0), -- данные не совместимы
        compatibly (1)      -- данные совместимы
  }
 \endcode

  Для шифрования ключевой информации используется алгоритм KExp15,
  описанный в рекомендациях Р 1323565.1.017-2018. Данный формат описывается следующей диаграммой

 \code
     iv || key + mask  ||                imito
   |__________________| --> ak_bckey_cmac -^
          |____________________________________|
                        ak_bckey_ctr
 \endcode

 На вход данного преобразования подаются два ключа алгоритма блочного шифрования "Кузнечик",
 после чего

  - вырабатывается случайный вектор `iv`, длина которого равна половине длины блока
    алгоритма "Кузнечик", т.е. 8 байт,
  - от вектора `iv || key + mask` с использованием ключа имитозащиты вычисляется имитовставка `imito`,
    используется алгоритм выработки имитовставки ГОСТ Р 34.12-2015,
  - с использованием ключа шифрования вектор `key+mask || imito` зашифровывается в режие гаммирования
    согласно ГОСТ Р 34.12-2015.

 \param root ASN.1 структура, к которой добавляется новая структура
 \param skey секретный ключ, содержащий зашифровываемые данные
 \param ekey производный ключ шифрования
 \param ikey производный ключ имитозащиты
 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_add_skey_content( ak_asn1 root, ak_skey skey, ak_bckey ekey, ak_bckey ikey )
{
  ak_asn1 content = NULL;
  int error = ak_error_ok;
  size_t ivsize  = ekey->bsize >> 1,
         keysize = 2*skey->key_size;
  size_t len = ivsize + keysize + ikey->bsize;
             /* необходимый объем памяти:
                синхропосылка (половина блока) + ( ключ+маска ) + имитовставка (блок) */

  if(( content = ak_asn1_new( )) == NULL ) return ak_error_message( ak_error_get_value(),
                                                  __func__, "incorrect creation of asn1 context" );
  if(( error = ak_asn1_add_uint32( content, data_present_storage )) != ak_error_ok ) {
    ak_asn1_delete( content );
    return ak_error_message( error, __func__, "incorrect adding data storage identifier" );
  }
  if(( error = ak_asn1_add_uint32( content,
        ( ak_uint32 )ak_libakrypt_get_option_by_name( "openssl_compability" ))) != ak_error_ok ) {
    ak_asn1_delete( content );
    return ak_error_message( error, __func__, "incorrect adding data storage identifier" );
  }

 /* добавляем ключ: реализуем КЕexp15 для ключа и маски */
  if(( error = ak_asn1_add_octet_string( content, &len, len )) == ak_error_ok ) {
    ak_uint8 *ptr = content->current->data.primitive;

   /* формируем iv */
    memset( ptr, 0, len );
    ak_random_ptr( &ekey->key.generator, ptr, ivsize );
   /* меняем маску секретного ключа */
    skey->set_mask( skey );
   /* копируем данные:
      сохраняем их как большое целое число в big-endian кодировке */
    ak_mpzn_to_little_endian(( ak_uint64 *)skey->key,
                                             (skey->key_size >> 2), ptr+ivsize, keysize, ak_true );
   /* меняем маску секретного ключа */
    skey->set_mask( skey );
   /* вычисляем имитовставку */
    if(( error = ak_bckey_cmac( ikey, ptr, ivsize+keysize,
                                            ptr+(ivsize+keysize), ikey->bsize )) != ak_error_ok ) {
      ak_asn1_delete( content );
      return ak_error_message( error, __func__, "incorrect evaluation of cmac" );
    }
   /* шифруем данные */
    if(( error = ak_bckey_ctr( ekey, ptr+ivsize, ptr+ivsize, keysize+ikey->bsize,
                                                                  ptr, ivsize )) != ak_error_ok ) {
      ak_asn1_delete( content );
      return ak_error_message( error, __func__, "incorrect encryption of skey" );
    }
  } else {
           ak_asn1_delete( content );
           return ak_error_message( error, __func__, "incorrect adding a secret key" );
    }

 /* вставляем изготовленную последовательность и выходим */
 return ak_asn1_add_asn1( root, TSEQUENCE, content );
}

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
       keyLabel             CHOICE {
                              UTF8 STRING,
                              NULL    -- человекочитаемое имя (описание или метка) ключа,
                                         если имя не определено, то помещается NULL
                            }
       params KeyParameters,          -- параметры секретного ключа, такие как ресурс использований и
                                         временной интервал
       content EncryptedContent       -- собственно ключ, зашифрованный с помощью преобразования KExp15
    }
\endcode

Формат структуры `KeyParameters` определяется следующим образом.
\code
    KeyParameters ::= SEQUENCE {
       resourceType INTEGER, -- тип ресурса секретного ключа
       resource INTEGER,     -- значение ресурса
       validity Validity     -- временной интервал использования ключа
    }
\endcode

Структура `Validity` содержит в себе временной интервал действия ключа и
определяется стандартным для x509 образом.

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
 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_add_symmetric_key_content( ak_asn1 root, ak_skey skey,
                                                                     ak_bckey ekey, ak_bckey ikey )
{
  ak_asn1 symkey = NULL;
  int error = ak_error_ok;

 /* 1. помечаем контейнер */
   if(( error = ak_asn1_add_oid( root,
                         ak_oid_find_by_name( "symmetric-key-content" )->id[0] )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect adding contents identifier" );

 /* 2. добавляем соответствующую структуру с данными */
   if(( error = ak_asn1_add_asn1( root, TSEQUENCE, symkey = ak_asn1_new( ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context for content" );

  /* 3. создаем пять встроенных полей (данный набор специфичен только для SymmetricKeyContent
     - 3.1. - идентификатор ключа */
   if(( error = ak_asn1_add_oid( symkey, skey->oid->id[0] )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's identifier" );
   }

  /* - 3.2. - номер ключа ключа */
   if(( error = ak_asn1_add_octet_string( symkey,
                                         skey->number, sizeof( skey->number ))) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's number" );
   }

  /* - 3.3. - имя/описание ключа */
   if(( error = ak_asn1_add_utf8_string( symkey, skey->label )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's label" );
     goto labexit;
   }

  /* - 3.4. - ресурс ключа */
   if(( error = ak_asn1_add_resource( symkey, &skey->resource )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's parameters" );
     goto labexit;
   }

  /* - 3.5. - собственно зашифрованный ключ */
   if(( error = ak_asn1_add_skey_content( symkey, skey, ekey, ikey )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's parameters" );
   }

  labexit: return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Экспорт секретного ключа асимметричного криптошрафического преобразования в ASN.1 дерево.

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
       keyLabel             CHOICE {
                              UTF8 STRING,
                              NULL    -- человекочитаемое имя (описание или метка) ключа,
                                         если имя не определено, то помещается NULL
                            }
       params KeyParameters,          -- параметры секретного ключа, такие как ресурс использований и
                                         временной интервал
       curveOID OBJECT IDENTIFIER     -- идентификатор эллиптической кривой, на которой выполняются
                                         криптографические преобразования
       subjectKeyIdentifier CHOICE {
                                OBJECT IDENTIFIER
                                NULL
                            }         -- идентификатор открытого ключа, связанного с данным
                                         секретным ключом, если идентификатор не определен,
                                         то помещается NULL
       subjectName          CHOICE {
                                Name
                                NULL  -- обощенное имя владельца ключа (как в открытом ключе), если
                            }            имя не определено, то помещается NULL
       content EncryptedContent       -- собственно данные, зашифрованные с помощью преобразования KExp15
    }
\endcode

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
 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
  возвращается код ошибки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_add_signature_key_content( ak_asn1 root, ak_signkey skey,
                                                                      ak_bckey ekey, ak_bckey ikey )
{
  ak_oid eoid = NULL;
  ak_uint8 pnumber[32];
  ak_asn1 symkey = NULL;
  int error = ak_error_ok;

 /* 1. помечаем контейнер */
   if(( error = ak_asn1_add_oid( root,
                 ak_oid_find_by_name( "secret-key-content" )->id[0] )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect adding contents identifier" );

 /* 2. добавляем соответствующую структуру с данными */
   if(( error = ak_asn1_add_asn1( root, TSEQUENCE, symkey = ak_asn1_new( ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context for content" );

  /* 3. создаем восемь встроенных полей (данный набор специфичен только для SecretKeyContent

     - 3.1. - идентификатор ключа */
   if(( error = ak_asn1_add_oid( symkey, skey->key.oid->id[0] )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's identifier" );
   }

  /* - 3.2. - номер ключа ключа */
   if(( error = ak_asn1_add_octet_string( symkey,
                                skey->key.number, sizeof( skey->key.number ))) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     return ak_error_message( error, __func__, "incorrect addition of secret key's number" );
   }

  /* - 3.3. - имя/описание ключа */
   if(( error = ak_asn1_add_utf8_string( symkey, skey->key.label )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's description" );
     goto labexit;
   }

  /* - 3.4. - ресурс ключа */
   if(( error = ak_asn1_add_resource( symkey, &skey->key.resource )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
     ak_error_message( error, __func__, "incorrect creation of secret key's parameters" );
     goto labexit;
   }

  /* - 3.5. - сохраняеми идентификатор эллиптической кривой,
              поскольку мы имеем только указатель на данные, надо найти oid по заданному адресу */

     eoid = ak_oid_find_by_mode( wcurve_params );
     while( eoid != NULL ) {
       if( eoid->data == skey->key.data ) {
           if(( error = ak_asn1_add_oid( symkey, eoid->id[0] )) != ak_error_ok )
             return ak_error_message( error, __func__,
                                                    "incorrect adding elliptic curve identifier" );
           break;
       }
       eoid = ak_oid_findnext_by_mode( eoid, wcurve_params );
     }

  /* - 3.6. идентификатор открытого ключа */
   memset( pnumber, 0, sizeof( pnumber ));
   if( memcmp( pnumber, skey->verifykey_number, sizeof( skey->verifykey_number )) == 0 )
     ak_asn1_add_utf8_string( symkey, NULL );
    else ak_asn1_add_octet_string( symkey,
                                         skey->verifykey_number, sizeof( skey->verifykey_number ));

  /* - 3.7. - помещаем имя владельца ключа (эта информация используется при подписи запросов на сертификат */
   if( skey->name == NULL ) ak_asn1_add_utf8_string( symkey, NULL );
    else ak_asn1_add_tlv( symkey, ak_tlv_duplicate_global_name( skey->name ));

  /* - 3.8. - собственно зашифрованный ключ */
   if(( error = ak_asn1_add_skey_content( symkey, &skey->key, ekey, ikey )) != ak_error_ok ) {
     ak_asn1_delete( symkey );
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
 зависит от способа генерации ключей шифрования секретного ключа.
 Описание формата при использовании пароля
 содержится в документации к функции ak_asn1_add_derived_keys_from_password().

 Формат структуры `Content` зависит от типа помещаемых данных:

 -  для симметричных ключей (ключей алгоритмов блочного шифрования, алгоритмов выработки имитовставки и т.п.)
    описание формата структуры `Content` содержится в документации к функции
    ak_asn1_add_symmetric_key_content().

 -  для секретных ключей асимметричных алгоритмов, в частности, электронной подписи
    описание формата структуры `Content` содержится в документации к функции
    ak_asn1_add_signature_key_content().

 \param key секретный ключ криптографического преобразования
 \param root  уровень ASN.1 дерева, в который помещаются экспортируемые данные
 \param password пароль пользователя
 \param pass_size длина пользовательского пароля в октетах

 \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_export_to_asn1_with_password( ak_pointer key,
                                       ak_asn1 root, const char *password, const size_t pass_size )
{
  int error = ak_error_ok;
  struct bckey ekey, ikey; /* производные ключи шифрования и имитозащиты */
  ak_asn1 asn = NULL, content = NULL;


  /* выполняем проверки */
   if( key == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using null pointer to block cipher context" );
   if( root == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to root asn1 context" );
   if(( password == NULL ) || ( !pass_size ))
     return ak_error_message( ak_error_invalid_value, __func__, "using incorrect password value" );

 /* 1. помечаем контейнер */
   if(( error = ak_asn1_add_oid( asn = ak_asn1_new(),
                           ak_oid_find_by_name( "libakrypt-container" )->id[0] )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context" );

 /* 2. добавляем структуру для восстановления информации и вырабатываем два производных ключа,
       в данном случае производные ключи вырабатываются из пароля */
   if(( error = ak_asn1_add_derived_keys_from_password( asn,
        ak_oid_find_by_name( "kuznechik" ), &ekey, &ikey, password, pass_size )) != ak_error_ok ) {
     ak_asn1_delete( asn );
     return ak_error_message( error, __func__, "incorrect creation of derived secret keys" );
   }

 /* 3. добавляем соответствующую структуру с данными */
   if(( error = ak_asn1_add_asn1( asn, TSEQUENCE, content = ak_asn1_new( ))) != ak_error_ok ) {
     ak_asn1_delete( asn );
     ak_error_message( error, __func__, "incorrect creation of asn1 context for content" );
     goto labexit;
   }

  /* 4. экспортируем данные в asn1 дерево,
        перед экспортом выполняем фильтр криптографического механизма еще раз */
   switch( ((ak_skey)key)->oid->engine ) {
    /* формируем ASN.1 дерево для симметричного секретного ключа */
     case block_cipher:
     case hmac_function:
           if(( error = ak_asn1_add_symmetric_key_content( content, (ak_skey)key,
                                                                &ekey, &ikey )) != ak_error_ok ) {
              ak_asn1_delete( asn );
              ak_error_message( error, __func__, "incorrect creation of symmetric key content" );
              goto labexit;
           }
           break;

     case sign_function:
           if(( error = ak_asn1_add_signature_key_content( content, (ak_signkey)key,
                                                                &ekey, &ikey )) != ak_error_ok ) {
              ak_asn1_delete( asn );
              ak_error_message( error, __func__, "incorrect creation of symmetric key content" );
              goto labexit;
           }
          break;

     default:
           ak_asn1_delete( asn );
           ak_error_message( error = ak_error_oid_engine, __func__,
                                                         "using usupported engine of secret key" );
           goto labexit;
  }

   error = ak_asn1_add_asn1( root, TSEQUENCE, asn );
   labexit:
     ak_bckey_destroy( &ekey );
     ak_bckey_destroy( &ikey );
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! В текущей версии библиотеки допускается экспорт следующих секретных ключей

     - ключа алгоритма блочного шифрования (указатель на struct \ref skey),
     - ключа алгоритма выработки имитовставки `HMAC` (указатель на struct \ref hmac),
     - секретного ключа асимметричного алгоритма (указатель на struct \ref signkey).

    В процессе экспорта функция создает ASN.1 дерево, содержащее экспортное ( зашифрованное )
    представление секретного ключа, после чего кодирует дерево в виде der-последовательности и
    сохряняет данную последовательность в файл.

    Для шифрования ключа используются производные ключи, вырабатываемые
    из заданного пользователем пароля. Использование пароля нулевой длины или `NULL`
    указателя `password` не допускается.

    Если длина имени файла `filename_size` отлична от нуля, то функция предполагает, что имя файла
    пользователем не указано. В этом случае функция формирует имя файла (в качестве имени берется номер ключа)
    и помещает сформированную строку в переменную, на которую указывает `filename`.

    Формат ASN.1 дерева, в котором хранится
    экспортируемый ключ описывается в документации к функции ak_skey_export_to_asn1_with_password().
    В зависимости от значения параметра `format` закодированное ASN.1 дерево сохраняется
    либо в формате `der` (двоичные данные), либо в формате `pem` (текстовые данные, полученные
    путем base64-кодирования двоичных данных формате `der`)

    Пример вызова функции.
    \code
      // сохранение ключа в файле, имя которого возвращается в переменной filename
       char filemane[256];
       ak_skey_export_to_file_with_password( key,
             "password", 8, "keylabel", filename, sizeof( filename ), asn1_der_format );

      // сохранение ключа в файле с заданным именем
       ak_skey_export_to_file_with_password( key,
                            "password", 8, "keyname", "name.key", 0, asn1_pem_format );
    \endcode

    \param key контекст экспортируемого секретного ключа криптографического преобразования;
    контекст должен быть инициализирован ключевым значением, а поле oid должно содержать
    идентификатор алгоритма, для которого предназначен ключ.
    \param password пароль, используемый для генерации ключа шифрования контента
    \param pass_size длина пароля (в октетах)
    \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `fsize` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
    \param fsize  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
    \param format формат, в котором зашифрованные данные сохраняются в файл.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_export_to_file_with_password( ak_pointer key, const char *password,
               const size_t pass_size, char *filename, const size_t fsize, export_format_t format )
{
   ak_oid oid = NULL;
   ak_asn1 asn = NULL;
   int error = ak_error_ok;
   ak_skey skey = (ak_skey)key;
   crypto_content_t content = undefined_content;

  /* необходимые проверки */
   if( key == NULL )
     return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
   if( ak_oid_check( oid = skey->oid ) != ak_true )
     return ak_error_message( ak_error_invalid_value, __func__,
                                                 "using incorrect pointer to secret key context" );
   switch( oid->engine ) { /* перечисляем все поддерживаемые типы секретных ключей */
     case block_cipher:
     case hmac_function:
       content = symmetric_key_content;
       break;

     case sign_function:
       content = secret_key_content;
       break;

     default: return ak_error_message_fmt( ak_error_oid_engine, __func__,
          "using object with unsupported engine: %s", ak_libakrypt_get_engine_name( oid->engine ));
   }
   if( oid->mode != algorithm ) return ak_error_message_fmt( ak_error_oid_mode, __func__,
                "using object with unsupported mode: %s", ak_libakrypt_get_mode_name( oid->mode ));

   if(( error = ak_skey_generate_file_name_from_buffer( skey->number, sizeof( skey->number ),
                                                       filename, fsize, format )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of secret key filename" );

 /* преобразуем ключ в asn1 дерево */
  if(( error = ak_skey_export_to_asn1_with_password( key,
                                    asn = ak_asn1_new(), password, pass_size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect export of secret key to asn1 context");
    goto lab1;
  }

 /* сохраняем созданное asn1 дерево в файле */
  if(( error = ak_asn1_export_to_file( asn, filename, format, content )) != ak_error_ok )
    ak_error_message_fmt( error, __func__, "incorrect export of asn1 context" );

  lab1: if( asn != NULL ) ak_asn1_delete( asn );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                               /* Функции экспорта открытых ключей */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует фрагмент asn1 дерева, содержащий параметры открытого ключа.
   \param vk контекст открытого ключа
   \return Функция возвращает указатель на tlv узел, содержащий сформированную структуру.
   В случае ошибки возвращается `NULL`.                                                            */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_verifykey_export_to_asn1_value( ak_verifykey vk )
{
  ak_oid ec = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_tlv tlv = NULL, os = NULL;
  ak_asn1 asn = NULL, basn = NULL;
  size_t val64 = sizeof( ak_uint64 )*vk->wc->size;          /* количество октетов в одном вычете */
  ak_uint8 data[ 2*sizeof(ak_uint64)*ak_mpznmax_size ];    /* asn1 представление открытого ключа */
  ak_uint8 encode[ 4 + sizeof( data )];                             /* кодированная octet string */
  size_t sz = sizeof( encode );

  if(( error = ak_asn1_add_oid( asn = ak_asn1_new(), vk->oid->id[0] )) != ak_error_ok ) goto labex;
  if(( error = ak_asn1_add_asn1( asn, TSEQUENCE, ak_asn1_new( ))) != ak_error_ok ) goto labex;
  if(( ec = ak_oid_find_by_data( vk->wc )) == NULL ) {
    ak_error_message( ak_error_wrong_oid, __func__,
                                 "public key has incorrect pointer to elliptic curve parameters" );
    goto labex;
  }
  ak_asn1_add_oid( asn->current->data.constructed, ec->id[0] );
  ak_asn1_add_oid( asn->current->data.constructed, vk->ctx.oid->id[0] );

  if(( basn = ak_asn1_new()) == NULL ) goto labex;
  if(( error = ak_asn1_add_asn1( basn, TSEQUENCE, asn )) != ak_error_ok ) {
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }

 /* кодируем открытый ключ => готовим octet string */
  memset( data, 0, sizeof( data ));
  if(( os = ak_tlv_new_primitive( TOCTET_STRING, ( val64<<1 ), data, ak_false )) == NULL ){
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }
 /* помещаем в нее данные */
  ak_wpoint_reduce( &vk->qpoint, vk->wc );
  ak_mpzn_to_little_endian( vk->qpoint.x, vk->wc->size, data, val64, ak_false );
  ak_mpzn_to_little_endian( vk->qpoint.y, vk->wc->size, data+val64, val64, ak_false );
  if(( error = ak_tlv_encode( os, encode, &sz )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encoding of temporary tlv context" );
    if( os != NULL ) ak_tlv_delete( os );
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }
  bs.value = encode;
  bs.len = sz;
  bs.unused = 0;
  ak_asn1_add_bit_string( basn, &bs );
  if(( tlv = ak_tlv_new_constructed( TSEQUENCE^CONSTRUCTED, basn )) == NULL ) {
    ak_asn1_delete( basn );
    ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect addition the bit sting with public key value" );
  }

  ak_tlv_delete( os );
 return  tlv;

 labex:
  if( asn != NULL ) ak_asn1_delete( asn );
  ak_error_message( ak_error_get_value(), __func__,
                                         "incorrect export of public key into request asn1 tree" );
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
 static int ak_verifykey_export_to_asn1_request( ak_verifykey vk, ak_signkey sk,
                                                                   ak_random generator, ak_asn1 a )
{
  ak_asn1 asn = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_uint8 data[4096], s[128];
  size_t size = sizeof( data );
  ak_tlv tlv = NULL, pkey = NULL;

  if( a == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 context" );
  if( !ak_ptr_is_equal( vk->number, sk->verifykey_number, sizeof( vk->number )))
    return ak_error_message( ak_error_not_equal_data, __func__,
                                                     "secret key not correspondig to public key" );
  if( ak_signkey_get_tag_size( sk ) > sizeof( s ))
    ak_error_message( ak_error_wrong_length, __func__,
                                   "using digital signature algorithm with very large signature" );

 /* 1. Создаем последовательность, которая будет содержать данные запроса */
  if(( error = ak_asn1_add_asn1( a, TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new())) != ak_error_ok ) {
    if( asn != NULL ) ak_asn1_delete( asn );
    return ak_error_message( error, __func__, "incorrect creation of first level sequence");
  }

 /* 2. Создаем tlv элемент, для которого, потом, будет вычисляться электронная подпись */
   tlv = ak_tlv_new_constructed( TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new( ));
  /* добавляем ноль */
   ak_asn1_add_uint32( asn, 0 );
  /* переносим asn1 дерево с расширенным именем в asn1 дерево формируемого запроса */
   ak_asn1_add_tlv( asn, vk->name );
   vk->name = NULL;
  /* помещаем информацию об алгоритме и открытом ключе */
   ak_asn1_add_tlv( asn, pkey = ak_verifykey_export_to_asn1_value( vk ));
   if( pkey == NULL ) {
     if( tlv != NULL ) tlv = ak_tlv_delete( tlv );
     return ak_error_message( ak_error_get_value(), __func__,
                                               "incorrect export of public key into tlv context" );
   }
  /* 0x00 это помещаемое в CONTEXT_SPECIFIC значение */
   ak_asn1_add_asn1( asn, CONTEXT_SPECIFIC^0x00, ak_asn1_new( ));

  /* 3. Помещаем tlv элемент в основное дерево */
   ak_asn1_add_tlv( a->current->data.constructed, tlv );

  /* 4. Помещаем идентификатор алгоритма выработки подписи */
   ak_asn1_add_asn1( a->current->data.constructed, TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new());
   ak_asn1_add_oid( asn, sk->key.oid->id[0] );

  /* 4. Помещаем bit-string со значением подписи */
   if(( error =  ak_tlv_encode( tlv, data, &size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect encoding of asn1 context");

   memset( s, 0, sizeof( s ));
   if(( error = ak_signkey_sign_ptr( sk, generator, data, size, s, sizeof( s ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect signing internal data" );
   bs.value = s;
   bs.len = ak_signkey_get_tag_size( sk );
   bs.unused = 0;
   if(( error = ak_asn1_add_bit_string( a->current->data.constructed, &bs )) != ak_error_ok )
     ak_error_message( error, __func__, "incorrect adding a digital signature value" );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию
    и сохраняет созданное дерево в файл, который называется "запросом на сертификат".

   \note Контекст секретного ключа `sk` должен соответствовать контексту открытого ключа `vk`.
   В противном случае нельзя будет проверить электронную подпись под открытым ключом --
   запрос на сертификат, по сути, является урезанной версией самоподписанного сертификата.
   Отсюда следует, что нельзя создать запрос на сертификат ключа, который не поддерживает
   определенный библиотекой алгоритм подписи (например ключ на кривой в 640 бит).
   Такие ключи должны сразу помещаться в сертификат.

   \param vk Контекст открытого ключа
   \param sk Контекст секретного ключа
   \param generator Генератор псевдослучайных последовательностей, используемый для выработки
    электронной подписи под запросом на сертификат
   \param filename Указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
   \param size  Размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
   \param format Формат, в котором сохраняются данные - der или pem.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_export_to_request( ak_verifykey vk, ak_signkey sk, ak_random generator,
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

 /* 1. При необходимости, формируем имя файла для экспорта открытого ключа
       Формируемое имя совпадает с номером ключа и однозначно зависит от его значения */
  if( size != 0 ) {
    memset( filename, 0, size );
    if( size < 12 ) return ak_error_message( ak_error_wrong_length, __func__,
                                               "using small buffer to storing request file name" );
     else ak_snprintf( filename, size, "%s.csr",
                                   ak_ptr_to_hexstr( vk->number, sizeof( vk->number ), ak_false ));
  }

 /* 2. Создаем asn1 дерево */
  if(( error = ak_verifykey_export_to_asn1_request( vk, sk, generator,
                                                         asn = ak_asn1_new( ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation af asn1 context" );
    goto labexit;
  }

 /* 3. Сохраняем созданное дерево в файл */
  if(( error = ak_asn1_export_to_file( asn,
                                filename, format, public_key_request_content )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "incorrect export asn1 context to file %s", filename );
    goto labexit;
  }

  labexit:
    if( asn != NULL ) asn = ak_asn1_delete( asn );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция вырабатывает серийный номер сертификата.

   Данный номер (serialNumber) зависит от номера секретного ключа, подписывающего открытый ключ и,
   тем самым, может принимать различные значения для каждого из подписывающих ключей.

   Серийный номер сертификата образуют младшие 32 байта результата хеширования
   последовательной конкатенации номеров открытого и секретного ключей.
   Для хеширования используется функция, определенная в контексте секретного ключа,
   т.е.  Стрибог512 для длинной подписи и Стрибог256 для короткой.

   \code
    result[0..31] = Hash( vk->number || sk->number )
   \endcode

   \param vk контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param sk контекст ключа подписи, содержащий параметры центра сертификации
   \param serialNumber переменная, в которую помещается серийный номер.
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_generate_certificate_number( ak_verifykey vk,
                                                            ak_signkey sk, ak_mpzn256 serialNumber )
{
  ak_uint8 result[64];

 /* используем для хеширования контекст секретного ключа */
  if( ak_hash_get_tag_size( &sk->ctx ) > sizeof( result ))
    return ak_error_message( ak_error_wrong_length, __func__,
                                                      "using secret key with huge signature tag" );
  memset( result, 0, sizeof( result ));
  ak_hash_clean( &sk->ctx );
  ak_hash_update( &sk->ctx, vk->number, sizeof( vk->number ));
  ak_hash_finalize( &sk->ctx, sk->key.number, sizeof( sk->key.number ), result, sizeof( result ));
  ak_mpzn_set_little_endian( serialNumber, ak_mpzn256_size, result, 32, ak_true );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание tlv узла, содержащего структуру TBSCertificate версии 3 (без расширений)
    в соответствии с Р 1323565.1.023-2018.

   Структура `tbsCertificate` определяется следующим образом

   \code
    TBSCertificate  ::=  SEQUENCE  {
        version         [0]  Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  Extensions OPTIONAL
                             -- If present, version MUST be v3 --  }
   \endcode

   \param vk контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param sk контекст ключа подписи, содержащий параметры центра сертификации
   \param opts набор опций, формирующих помещаемые в сертификат расширения
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_verifykey_export_to_tbs( ak_verifykey vk,
                                                          ak_signkey sk, ak_certificate_opts opts )
{
  ak_mpzn256 serialNumber;
  ak_tlv tbs = NULL, tlv = NULL;
  ak_asn1 asn = NULL, tbasn = NULL;

  if( vk == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to public key" );
    return NULL;
  }
  if(( tbs = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
   else tbasn = tbs->data.constructed;

 /* теперь создаем дерево сертификата в соответствии с Р 1323565.1.023-2018
    version: начинаем с размещения версии сертификата, т.е. ветки следующего вида
     ┐
     ├[0]┐
     │   └INTEGER 2 (величина 2 является максимально возможным значением ) */

  ak_asn1_add_asn1( tbasn, CONTEXT_SPECIFIC^0x00, asn = ak_asn1_new( ));
  if( asn != NULL ) ak_asn1_add_uint32( asn, 2 );
    else {
      ak_error_message( ak_error_get_value(), __func__,
                                              "incorrect creation of certificate version context");
      goto labex;
    }

 /* serialNumber: вырабатываем и добавляем номер сертификата */
  ak_verifykey_generate_certificate_number( vk, sk, serialNumber );
  ak_asn1_add_mpzn( tbasn, serialNumber, ak_mpzn256_size );

 /* signature: указываем алгоритм подписи (это будет повторено еще раз при выработке подписи) */
  ak_asn1_add_tlv( tbasn, tlv = ak_tlv_new_sequence( ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                          "incorrect generation of digital signature identifier" );
    goto labex;
  }
  ak_asn1_add_oid( tlv->data.constructed, sk->key.oid->id[0] );

 /* issuer: вставляем информацию о расширенном имени лица, подписывающего ключ
    (эмитента, выдающего сертификат) */
  ak_asn1_add_tlv( tbasn, ak_tlv_duplicate_global_name( sk->name ));

 /* validity: вставляем информацию в времени действия ключа */
  ak_asn1_add_validity( tbasn, sk->key.resource.time.not_before, sk->key.resource.time.not_after );

 /* subject: вставляем информацию о расширенном имени владельца ключа  */
  ak_asn1_add_tlv( tbasn, ak_tlv_duplicate_global_name( vk->name ));

 /* subjectPublicKeyInfo: вставляем информацию об открытом ключе */
  ak_asn1_add_tlv( tbasn, tlv = ak_verifykey_export_to_asn1_value( vk ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                               "incorrect generation of subject public key info" );
    goto labex;
  }

 /* вставляем перечень расширений
    0x03 это помещаемое в CONTEXT_SPECIFIC значение */
  ak_asn1_add_asn1( tbasn, CONTEXT_SPECIFIC^0x03, asn = ak_asn1_new( ));
  if( asn == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                      "incorrect creation of certificate extensions asn1 context");
    goto labex;
  }
  ak_asn1_add_tlv( asn, ak_tlv_new_sequence( ));
  asn = asn->current->data.constructed;

 /* в обязательном порядке добавляем номер открытого ключа */
  ak_asn1_add_tlv( asn,
                    tlv = ak_tlv_new_subject_key_identifier( vk->number, sizeof( vk->number )));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
    goto labex;
  }

 /* теперь мы принимаем решение - сертификат самоподписанный или нет
    выполняются две проверки:
      - совпадение subjectKeyIdentifier (номера открытого ключа)
      - совпадение имен. */
  if( ak_ptr_is_equal( sk->verifykey_number, vk->number, sizeof( vk->number )) == ak_true ) {

    int error = ak_error_ok;
    ak_uint8 skname[2048], vkname[2048]; /* это искусственное ограничение */
    size_t sklen = sizeof( skname ), vklen = sizeof( vkname );

   /* совпали идентификаторы, должны совпасть и имена */
    if(( error = ak_tlv_encode( sk->name, skname, &sklen )) != ak_error_ok ) {
      ak_error_message( error, __func__, "creation certificate with incorrect name of issuer" );
      goto labex;
    }
    if(( error = ak_tlv_encode( vk->name, vkname, &vklen )) != ak_error_ok ) {
      ak_error_message( error, __func__, "creation certificate with incorrect name of owner" );
      goto labex;
    }
    if( vklen != sklen ) {
      ak_error_message( error, __func__,
                       "creation certificate with different length of names of issuer and owner" );
      goto labex;
    }
    if( ak_ptr_is_equal( skname, vkname, sklen ) != ak_true ) {
      ak_error_message( error, __func__,
                                 "creation certificate with different names of issuer and owner" );
      goto labex;
    }
   /* теперь добавляем расширение с флагом, что сертификат является самоподписанным */
    ak_asn1_add_tlv( asn,
      tlv = ak_tlv_new_basic_constraints( opts->ca , opts->pathlenConstraint ));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
      goto labex;
    }
  }

 /* если определены флаги keyUsage, то мы добавляем соответствующее расширение */
  if( opts->keyUsageBits ) {
    ak_asn1_add_tlv( asn, tlv = ak_tlv_new_key_usage( opts->keyUsageBits ));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
      goto labex;
    }
  }

 return tbs;

  labex: if( tbs != NULL ) tbs = ak_tlv_delete( tbs );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает asn1 дерево, содержащее сертификат открытого ключа.

   \param vk контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param sk контекст ключа подписи, содержащий параметры центра сертификации
   \param generator геератор случайных последовательностей, используемый для подписи сертификата
   \param opts набор опций, формирующих помещаемые в сертификат расширения
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 static ak_asn1 ak_verifykey_export_to_asn1_certificate( ak_verifykey vk, ak_signkey sk,
                                                    ak_random generator, ak_certificate_opts opts )
{
  size_t len = 0;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_asn1 certificate = NULL;
  ak_uint8 encode[4096], out[128];
  ak_tlv tlv = NULL, ta = NULL, tbs = NULL;

 /* создаем контейнер для сертификата */
  if(( error = ak_asn1_add_tlv( certificate = ak_asn1_new(),
                                         tlv = ak_tlv_new_sequence( ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect addition of tlv context" );
    goto labex;
  }
  if( tlv == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "incorrect creation of tlv context" );
    goto labex;
  }

 /* создаем поле tbsCertificate */
  if(( tbs = ak_verifykey_export_to_tbs( vk, sk, opts )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                  "incorrect creation of tbsCertificate element" );
    goto labex;
  }

 /* вставляем в основное дерево созданный элемент */
  ak_asn1_add_tlv( tlv->data.constructed, tbs );
 /* добавляем информацию о алгоритме подписи */
  ak_asn1_add_tlv( tlv->data.constructed, ta = ak_tlv_new_sequence( ));
  if( ta == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                          "incorrect generation of digital signature identifier" );
    goto labex;
  }
  ak_asn1_add_oid( ta->data.constructed, sk->key.oid->id[0] );

 /* вырабатываем подпись */
  len = sizeof( encode );
  if(( error = ak_tlv_encode( tbs, encode, &len )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encoding of tbsCertificate element" );
    goto labex;
  }
  if(( error = ak_signkey_sign_ptr( sk, generator,
                                               encode, len, out, sizeof( out ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect generation of digital signature" );
    goto labex;
  }

 /* добавляем подпись в основное дерево */
  bs.value = out;
  bs.len = ak_signkey_get_tag_size( sk );
  bs.unused = 0;
  if(( error = ak_asn1_add_bit_string( tlv->data.constructed, &bs )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect adding a digital signature value" );
    goto labex;
  }

 return certificate;

  labex: if( certificate != NULL ) certificate = ak_asn1_delete( certificate );
 return NULL;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию,
    помещает в это же asn1 дерево информацию о подписывающем лице и правилах применения ключа.
    После этого сформированное дерево сохраняется в файл в заданном пользователем формате.

   \param vk контекст открытого ключа, который помещается в сертификат; контекст должен содержать
   информацию о лице (subject), владеющем открытым ключом.
   \param sk контекст секретного ключа, с помощью которого подписывается создааваемый сертификат;
   контекст должен содержать информацию о лице (issuer), владеющем секретным ключом.
   \param generator геератор слечайных последовательностей, используемый для подписи сертификата.
   \param opts набор опций, формирующих помещаемые в сертификат расширения
   \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `filename_size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
   \param size  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
   \param format формат, в котором сохраняются данные, допутимые значения
   \ref asn1_der_format или \ref asn1_pem_format.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_export_to_certificate( ak_verifykey vk, ak_signkey sk, ak_random generator,
              ak_certificate_opts opts, char *filename, const size_t size, export_format_t format )
{
  ak_mpzn256 serialNumber;
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
  if(( certificate = ak_verifykey_export_to_asn1_certificate( vk, sk, generator, opts )) == NULL )
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
    ak_verifykey_generate_certificate_number( vk, sk, serialNumber );
    ak_snprintf( filename, size, "%s.%s",
          ak_mpzn_to_hexstr( serialNumber, ak_mpzn256_size ), file_extensions[format] );
  }

 /* сохраняем созданное дерево в файл */
  if(( error = ak_asn1_export_to_file( certificate, filename,
                                        format, public_key_certificate_content )) != ak_error_ok )
    ak_error_message_fmt( error, __func__,
                              "incorrect export asn1 context to file %s in pem format", filename );

  labex: if( certificate != NULL ) certificate = ak_asn1_delete( certificate );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                    /* Функции импорта секретной ключевой информации */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет, что данный узел ASN.1 дерева является контейнером. */
/*! В случае успешной проверки, функция присваивает двум своим аргументам ссылки на поддеревья,
    содержащие информацию о процедуре выработки производных ключей (basicKey) и собственно
    зашифрованных данных (content).

    Использование узла tlv позволяет вызывать эту функцию в цикле, т.е.
    реализовывать следующую схему

  \code
    ak_asn1_first( asn );
    do {
      if( ak_tlv_check_libakrypt_container( asn->current, ... )) {
        ...
      }
    } while( ak_asn1_next( asn ));
  \endcode

    \param tlv узел ASN.1 дерева.
    \param basicKey указатель, в который помещается ссылка на дерево секретного ключа
    \param content указатель, в который помещается ссылка на дерево с данными
    \return Функция возвращает истину, если количество ключей в контейнере отлично от нуля.
    В противном случае возвращается ложь.                                                          */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_tlv_check_libakrypt_container( ak_tlv tlv, ak_asn1 *basicKey, ak_asn1 *content )
{
  ak_asn1 asn = NULL;
  ak_pointer str = NULL;
  const char *id = ak_oid_find_by_name( "libakrypt-container" )->id[0];

  if( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) return ak_false;
  asn = tlv->data.constructed;

 /* проверяем количество узлов */
  if( asn->count != 3 ) return ak_false;

 /* проверяем наличие фиксированного id */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
        ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_false;

 /* проверяем совпадение идентификаторов */
  ak_tlv_get_oid( asn->current, &str );
  if( strncmp( str, id, strlen( id )) != 0 ) return ak_false;

 /* получаем доступ к структурам */
  ak_asn1_next( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) return ak_false;
   else *basicKey = asn->current->data.constructed;

  ak_asn1_next( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) return ak_false;
   else *content = asn->current->data.constructed;

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция инициализирует секретный ключ значениями, расположенными в ASN.1 контейнере. */
/*! \param akey контекст ASN.1 дерева, содержащий информацию о ключе
    \param skey контекст ключа, значение которого считывается из ASN.1 дерева
    \param ekey контекст ключа шифрования
    \param ikey контекст ключа имитозащиты
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_get_skey_content( ak_asn1 akey, ak_skey skey, ak_bckey ekey, ak_bckey ikey )
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
   ak_asn1_last( akey );
   if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
                ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
     else asn = akey->current->data.constructed;

   ak_asn1_last( asn );
   if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
                ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
     else asn = asn->current->data.constructed;

  /* теперь мы на уровне дерева, который содержит
     последовательность ключевых данных */

  /* проверяем значения полей дерева */
   ak_asn1_first( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   ak_tlv_get_uint32( asn->current, &u32 );
   if( u32 != data_present_storage ) return ak_error_invalid_asn1_content;

   ak_asn1_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   ak_tlv_get_uint32( asn->current, &u32 );  /* теперь u32 содержит флаг совместимости с openssl */
   if( u32 !=  (oc = ( ak_uint32 )ak_libakrypt_get_option_by_name( "openssl_compability" ))) /* текущее значение */
     ak_libakrypt_set_openssl_compability( u32 );

  /* расшифровываем и проверяем имитовставку */
   ak_asn1_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING )) return ak_error_invalid_asn1_tag;
   ak_tlv_get_octet_string( asn->current, (ak_pointer *)&ptr, &size );
   if( size != ( ivsize + keysize + ikey->bsize )) /* длина ожидаемых данных */
     return ak_error_invalid_asn1_content;

  /* расшифровываем */
   if(( error = ak_bckey_ctr( ekey, ptr+ivsize, ptr+ivsize, keysize+ikey->bsize,
                                                                  ptr, ivsize )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect decryption of skey" );
     goto labexit;
   }

  /* вычисляем имитовставку */
   memset(out, 0, sizeof( out ));
   if(( error = ak_bckey_cmac( ikey, ptr, ivsize+keysize,
                                                     out, ikey->bsize )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect evaluation of cmac" );
     goto labexit;
   }
  /* теперь сверяем значения */
   if( !ak_ptr_is_equal( out, ptr+(ivsize+keysize), ikey->bsize )) {
     ak_error_message( error = ak_error_not_equal_data, __func__,
                                                             "incorrect value of integrity code" );
     goto labexit;
   }

  /* теперь копируем данные,
     поскольку мы полностью уверенны, что данные, хранящиеся в ASN.1 дереве содержат значение ключа */
   ak_mpzn_set_little_endian( (ak_uint64 *)(skey->key),
                                              (skey->key_size >>2), ptr+ivsize, keysize, ak_true );
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

  /* для ключей блочного шифрования выполняем развертку раундовых ключей */
   if( skey->oid->engine == block_cipher ) {
     if( ((ak_bckey)skey)->schedule_keys != NULL ) {
       if(( error = ((ak_bckey)skey)->schedule_keys( skey )) != ak_error_ok )
         ak_error_message( error, __func__, "incorrect execution of key scheduling procedure" );
     }
   }

  /* восстанавливаем изначальный режим совместимости и выходим */
   labexit: if( u32 != oc ) ak_libakrypt_set_openssl_compability( oc );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция считывает информацию о секретном ключе из заданного файла, созданного
    при помощи функции ak_skey_export_to_file().

   Эта очень длинная функция позволяет инициализировать статически созданные ключи,
   а также динамически создавать ключи в оперативной памяти. За это отвечает параметр `engine`:

   - если значение `engine` равно `undefined engine`, то сначала мы выделяем память под
     объект с помощью функции, указанной в его `oid`, а потом инициализируем объект значениями из файла;
   - если значение `engine` содержит осознанное значение, то мы считаем, что объект уже
     размещен в памяти и его тип определен значением `engine`; если содержащийся в файле тип
     криптографического преобразования совпадает с запрашиваемым, то ключ инициалищируется.

   Функция также позволяет выбирать: надо ли считывать и устанавливать ключевую информацию
   или не нужно. За это отвечает параметр `basicKey`:

   - если значение `basicKey` отлично от `NULL`, то производится считывание и
     помещение ключевой информации в контекст секретного ключа; информация о ключе доступа находится
     в asn1 дереве `basicKey`.
   - если значение `basicKey` равно NULL, то считывание не производится.


   \param key Указатель на контекст секретного ключа
   \param engine Тип ожидаемого криптографического механизма
   \param basicKey Указатель на ASN.1 структуру с информацией для восстановления ключа
    шифрования контента
   \param content Указатель на ASN.1 структуру, соержащую данные
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_skey_create_form_asn1_content( ak_pointer *key, oid_engines_t engine,
                                                                ak_asn1 basicKey, ak_asn1 content )
{
  size_t len = 0;
  ak_oid oid = NULL;
  ak_asn1 asn = NULL;
  ak_pointer ptr = NULL;
  struct bckey ekey, ikey;
  int error = ak_error_ok;
  crypto_content_t content_type = undefined_content;

 /* получаем структуру с параметрами, необходимыми для восстановления ключа */
  ak_asn1_first( content );
  if(( DATA_STRUCTURE( content->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( content->current->tag ) != TOBJECT_IDENTIFIER )) return undefined_content;

 /* получаем oid контента и проверяем, что он нам подходит */
  if(( error = ak_tlv_get_oid( content->current, &ptr )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect asn1 structure of content" );
    return undefined_content;
  }
  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message( ak_error_undefined_value, __func__, "incorrect content type" );
  if(( oid->engine != identifier ) || ( oid->mode != parameter ))
    return ak_error_message( ak_error_wrong_oid, __func__,
                                                         "incorrect value of content identifier" );
 /* определяем тип контента ( нас интересует только хранение секретных ключей ) */
  switch( content_type = (crypto_content_t) oid->data ) {
    case symmetric_key_content:
    case secret_key_content:
      break;
    default: return ak_error_message( ak_error_invalid_asn1_content, __func__,
                                                    "unsupported content type for this function" );
  }

 /* получаем указатель на дерево, содержащее параметры ключа и его зашифрованное значение */
  ak_asn1_next( content );
  if(( asn = content->current->data.constructed ) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__,
                                                      "unexpected null pointer to asn1 sequence" );
 /* получаем идентификатор ключа */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER ))
     return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                          "context has'nt object identifer for crypto algorithm" );

  ak_tlv_get_oid( asn->current, &ptr );
  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message( ak_error_invalid_asn1_content, __func__,
                                           "object identifier for crypto algorithm is not valid" );
  if( oid->mode != algorithm )
    return ak_error_message( ak_error_oid_mode, __func__, "wrong mode for object identifier" );

 /* теперь мы реализуем действия, зависящие от значения engine . */
  if( engine == undefined_engine ) { /* мы создаем новый объект  */
    if(( *key = ak_oid_new_object( oid )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__,
                                                  "incorrect creation of new secret key context" );
  } else { /* проверяем, что считанный тип совпадает с ожидаемым */
      if( oid->engine != engine )
        return ak_error_message_fmt( error = ak_error_oid_engine, __func__,
           "unexpected engine (%s) of object identifier (must be: %s)",
              ak_libakrypt_get_engine_name( oid->engine ), ak_libakrypt_get_engine_name( engine ));
      if(( error = oid->func.first.create( *key )) != ak_error_ok )
        return ak_error_message( ak_error_get_value(), __func__,
                                                  "incorrect creation of new secret key context" );
    }

 /* в текущий момент объект создан и мы
     1. можем присваивать значения его полям
     2. экстренный выход из функции должен обеспечивать очистку созданного контекста

    мы начинаем с полей, общих как для symmetric_key_content, так и для secret_key_content */

  /* - 3.2. получаем номер ключа */
   ak_asn1_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING )) {
      ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                      "context has incorrect asn1 type for symmetric key number" );
      goto lab1;
   }
   if(( error = ak_tlv_get_octet_string( asn->current, &ptr, &len )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect reading of symmetric key number");
     goto lab1;
   }
   if(( error = ak_skey_set_number( *key, ptr, len )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assigning a key number");
     goto lab1;
   }

  /* - 3.3. получаем имя/название/метку ключа */
   ak_asn1_next( asn );
   if( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) {
     ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                        "context has incorrect asn1 type for symmetric key name" );
     goto lab1;
   }
   switch( TAG_NUMBER( asn->current->tag )) {
     case TNULL: /* параметр опционален, может быть null */
              ptr = NULL;
              break;
     case TUTF8_STRING:
              ak_tlv_get_utf8_string( asn->current, &ptr );
              ak_skey_set_label( (ak_skey)*key, ptr, 0 );
              break;
     default: ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                        "context has incorrect asn1 type for symmetric key name" );
              goto lab1;
   }

  /* - 3.4. получаем ресурс ключа */
   ak_asn1_next( asn );
   if(( error = ak_tlv_get_resource( asn->current, &((ak_skey)*key)->resource )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect reading of secret key resource" );
     goto lab1;
   }

 /* для секретных ключей асимметричных алгоритмов надо считать дополнительные данные */
  if( content_type == secret_key_content ) {
    ak_oid curvoid = NULL;

    /* - 3.5  получаем идентификатор кривой */
     ak_asn1_next( asn );
     ak_tlv_get_oid( asn->current, &ptr );
     if(( curvoid = ak_oid_find_by_id( ptr )) == NULL ) {
       ak_error_message( error = ak_error_invalid_asn1_content, __func__,
                                             "object identifier for elliptic curve is not valid" );
       goto lab1;
     }
     if(( error = ak_signkey_set_curve( *key, (ak_wcurve)curvoid->data )) != ak_error_ok ) {
       ak_error_message( error, __func__, "using unapplicabale elliptic curve" );
       goto lab1;
     }

    /* - 3.5 получаем идентификатор открытого ключа */
     ak_asn1_next( asn );
     if( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) {
       ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                   "context has constructed context for subject key identifier" );
       goto lab1;
     }

     memset( ((ak_signkey)*key)->verifykey_number, 0, 32 );
     if( TAG_NUMBER( asn->current->tag ) != TNULL ) {
       if( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING ) {
         ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                    "context has incorrect asn1 type for subject key identifier" );
         goto lab1;
       }
       if(( error = ak_tlv_get_octet_string( asn->current, &ptr, &len )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect reading of symmetric key number");
         goto lab1;
       }
       memcpy( ((ak_signkey)*key)->verifykey_number, ptr, ak_min( 32, len ));
     }

    /* - 3.6 получаем обобщенное имя владельца ключа */
     ak_asn1_next( asn );
     if( DATA_STRUCTURE( asn->current->tag ) == PRIMITIVE ) {
       if( TAG_NUMBER( asn->current->tag ) == TNULL ) ((ak_signkey)*key)->name = NULL;
       else {
              ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                 "context has unexpected primitive asn1 type for subject's name" );
              goto lab1;
            }
     } else {
        if( TAG_NUMBER( asn->current->tag ) == TSEQUENCE )
          /* здесь мы вынимаем созданный tlv узел
             и перемещаем его во владение секретного ключа */
          ((ak_signkey)*key)->name = ak_asn1_exclude( asn );
         else {
               ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                              "context has unexpected constructed asn1 type for subject's name" );
              }
       }

  } /* конец  if(  content_type == secret_key_content ) */

 /* в завершение всех дел, можно считать значение секретного ключа,
    это происходит только в том случае, когда указатель basicKey отличен от NULL */
  if( basicKey != NULL ) {

   /* получаем производные ключи шифрования и имитозащиты */
    if(( error = ak_asn1_get_derived_keys( basicKey, &ekey, &ikey )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect creation of derived keys" );
      goto lab1;
    }
    if(( error = ak_asn1_get_skey_content( content, *key, &ekey, &ikey )) != ak_error_ok )
      ak_error_message( error, __func__, "incorrect assigning a seсret key value");

    ak_bckey_destroy( &ekey );
    ak_bckey_destroy( &ikey );
  }

 /* удаляем память, если нужно и выходим */
  lab1:
   if( error != ak_error_ok ) {
    /* удаляем объект */
     if( engine == undefined_engine ) ak_oid_delete_object( ((ak_skey)*key)->oid, *key );
   }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция последовательно выполняет следующие действия
     - создает объект (аналог действия `new`)
     - инициализирует контекст (аналог действия `create`)
     - присваивает ключевое значение (аналог действия `set_key`)

    \param filename Имя файла в котором хранятся данные
    \return Функция возвращает указатель на созданный контекст ключа. В случае ошибки возвращается
    а `NULL`, а код ошибки может быть получен с помощью вызова функции ak_error_get_value().       */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_skey_load_from_file( const char *filename )
{
  ak_pointer key = NULL;
  int error = ak_error_ok;
  ak_asn1 asn = NULL, basicKey = NULL, content = NULL;

   if( filename == NULL ) {
     ak_error_message( ak_error_null_pointer, __func__, "using null pointer to filename" );
     return NULL;
   }
  /* считываем ключ и преобразуем его в ASN.1 дерево */
   if(( error = ak_asn1_import_from_file( asn = ak_asn1_new(), filename )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
     goto lab1;
   }
  /* проверяем контейнер на формат хранящихся данных */
   ak_asn1_first( asn );
   if( !ak_tlv_check_libakrypt_container( asn->current, &basicKey, &content )) {
     ak_error_message( error = ak_error_invalid_asn1_content, __func__,
                                                      "incorrect format of secret key container" );
     goto lab1;
   }
  /* создаем ключ и считываем его значение */
   if(( error = ak_skey_create_form_asn1_content(
                   &key,     /* указатель на создаваемый объект */
                             /* проверку ожидаемого типа механизма не проводим */
                   undefined_engine,  /* и создаем объект в оперативной памяти */
                   basicKey, /* после создания будем присваивать ключ */
                   content   /* указатель на ключевые данные */
       )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of a new secret key");
     goto lab1;
   }

   lab1: if( asn != NULL ) ak_asn1_delete( asn );
 return key;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция последовательно выполняет следующие действия
     - создает объект (аналог действия `new`)
     - инициализирует контекст (аналог действия `create`)

    \note Значение ключа в созданный контекст не перемещается.

    \param filename Имя файла в котором хранятся данные
    \return Функция возвращает указатель на созданный контекст ключа. В случае ошибки возвращается
    а `NULL`, а код ошибки может быть получен с помощью вызова функции ak_error_get_value().       */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_skey_new_from_file( const char *filename )
{
  ak_pointer key = NULL;
  int error = ak_error_ok;
  ak_asn1 asn = NULL, basicKey = NULL, content = NULL;

   if( filename == NULL ) {
     ak_error_message( ak_error_null_pointer, __func__, "using null pointer to filename" );
     return NULL;
   }
  /* считываем ключ и преобразуем его в ASN.1 дерево */
   if(( error = ak_asn1_import_from_file( asn = ak_asn1_new(), filename )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
     goto lab1;
   }
  /* проверяем контейнер на формат хранящихся данных */
   ak_asn1_first( asn );
   if( !ak_tlv_check_libakrypt_container( asn->current, &basicKey, &content )) {
     ak_error_message( error = ak_error_invalid_asn1_content, __func__,
                                                      "incorrect format of secret key container" );
     goto lab1;
   }
  /* создаем ключ и считываем его значение */
   if(( error = ak_skey_create_form_asn1_content(
                   &key,     /* указатель на создаваемый объект */
                             /* проверку ожидаемого типа механизма не проводим */
                   undefined_engine,  /* и создаем объект в оперативной памяти */
                   NULL,     /* после создания ключ присваивать не будем */
                   content   /* указатель на ключевые данные */
       )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of a new secret key");
     goto lab1;
   }

   lab1: if( asn != NULL ) ak_asn1_delete( asn );
 return key;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция последовательно выполняет следующие действия
     - инициализирует контекст (аналог действия `create`)
     - присваивает ключевое значение (аналог действия `set_key`)

    \param ctx Контекст секретного ключа, должен быть не инициализирован до вызова функции
    \param engine Тип криптографического алгоритма, для которого создается контекст.
    Если это значение отлично от типа, хранящегося в ключевом контейнере, то возбуждается ошибка
    \param filename Имя файла в котором хранятся данные
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_import_from_file( ak_pointer ctx,
                                                      oid_engines_t engine, const char *filename )
{
  int error = ak_error_ok;
  ak_asn1 asn = NULL, basicKey = NULL, content = NULL;

   if( filename == NULL )
     return ak_error_message( ak_error_null_pointer, __func__, "using null pointer to filename" );

  /* считываем ключ и преобразуем его в ASN.1 дерево */
   if(( error = ak_asn1_import_from_file( asn = ak_asn1_new(), filename )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
     goto lab1;
   }

  /* проверяем контейнер на формат хранящихся данных */
   ak_asn1_first( asn );
   if( !ak_tlv_check_libakrypt_container( asn->current, &basicKey, &content )) {
     ak_error_message( error = ak_error_invalid_asn1_content, __func__,
                                                      "incorrect format of secret key container" );
     goto lab1;
   }
  /* создаем ключ и считываем его значение */
   if(( error = ak_skey_create_form_asn1_content(
                   &ctx,     /* указатель на инициализируемый объект */
                   engine,   /* ожидаем объект заданного типа */
                   basicKey, /* после инициализации будем присваивать ключ */
                   content   /* указатель на ключевые данные */
       )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of a new secret key");
     goto lab1;
   }

   lab1: if( asn != NULL ) ak_asn1_delete( asn );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                     /* Функции импорта открытой ключевой информации */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция получает значение открытого ключа из запроса на сертификат,
    разобранного в ASN.1 дерево, и создает контекст открытого ключа.

    Функция считывает oid алгоритма подписи и проверяет, что он соответствует ГОСТ Р 34.12-2012,
    потом функция считывает параметры эллиптической кривой и проверяет, что библиотека поддерживает
    данные параметры. В заключение функция считывает открытый ключ и проверяет,
    что он принадлежит кривой со считанными ранее параметрами.

    После выполнения всех проверок, функция создает (действие `create`) контекст открытого ключа,
    а также присваивает (действие `set_key`) ему считанное из asn1 дерева значение.

    \param vkey контекст создаваемого открытого ключа асимметричного криптографического алгоритма
    \param asnkey считанное из файла asn1 дерево
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_import_from_asn1_request( ak_verifykey vkey, ak_asn1 asnkey )
{
  size_t size = 0;
  ak_oid oid = NULL;
  struct bit_string bs;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;
  ak_asn1 asn = asnkey, asnl1; /* копируем адрес */
  ak_uint32 val = 0, val64 = 0;

 /* проверяем, то первым элементом содержится ноль */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TINTEGER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                          "the first element of root asn1 context be an integer" );
  ak_tlv_get_uint32( asn->current, &val );
  if( val != 0 ) return ak_error_message( ak_error_invalid_asn1_content, __func__ ,
                                              "the first element of asn1 context must be a zero" );
 /* второй элемент содержит имя владельца ключа.
    этот элемент должен быть позднее перенесен в контекст открытого ключа */
  ak_asn1_next( asn );

 /* третий элемент должен быть SEQUENCE с набором oid и значением ключа */
  ak_asn1_next( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
             "the third element of root asn1 context must be a sequence with object identifiers" );
  asn = asn->current->data.constructed;
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                               "the first next level element must be a sequence" );
  asnl1 = asn->current->data.constructed;

 /* получаем алгоритм электронной подписи */
  ak_asn1_first( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOBJECT_IDENTIFIER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                          "the first element of child asn1 context must be an object identifier" );
  if(( error = ak_tlv_get_oid( asnl1->current, &ptr )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect reading an object identifier" );

  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message_fmt( ak_error_oid_id, __func__,
                                                   "using unsupported object identifier %s", ptr );
  if(( oid->engine != verify_function ) || ( oid->mode != algorithm ))
    return ak_error_message( ak_error_oid_engine, __func__, "using wrong object identifier" );

 /* получаем параметры элиптической кривой */
  ak_asn1_next( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
             "the second element of child asn1 context must be a sequence of object identifiers" );
  asnl1 = asnl1->current->data.constructed;

  ak_asn1_first( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOBJECT_IDENTIFIER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                     "the first element of last child asn1 context must be an object identifier" );
  if(( error = ak_tlv_get_oid( asnl1->current, &ptr )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect reading an object identifier" );

  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message_fmt( ak_error_oid_id, __func__,
                            "import an unsupported object identifier %s for elliptic curve", ptr );
  if(( oid->engine != identifier ) || ( oid->mode != wcurve_params ))
    return ak_error_message( ak_error_oid_engine, __func__, "using wrong object identifier" );

 /* создаем контекст */
  asnl1 = NULL;
  if(( error = ak_verifykey_create( vkey, (const ak_wcurve )oid->data )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect creation of verify key context" );

 /* получаем значение открытого ключа */
  ak_asn1_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_get_bit_string( asn->current, &bs )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect reading a bit string" );
    goto lab1;
  }

 /* считали битовую строку, проверяем что это der-кодировка некоторого целого числа */
  if(( error = ak_asn1_decode( asnl1 = ak_asn1_new(),
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
  ak_tlv_get_octet_string( asnl1->current, &ptr, &size );
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

  if( asnl1 != NULL ) ak_asn1_delete( asnl1 );
 return ak_error_ok;

 lab1:
  if( asnl1 != NULL ) ak_asn1_delete( asnl1 );
  ak_verifykey_destroy( vkey );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция считывает из заданного файла запрос на получение сертификата. Запрос хранится в виде
    asn1 дерева, определяемого Р 1323565.1.023-2018.
    Собственно asn1 дерево может быть храниться в файле в виде обычной der-последовательности,
    либо в виде der-последовательности, дополнительно закодированной в `base64` (формат `pem`).

    \note Функция является конструктором контекста ak_verifykey.
    После считывания asn1 дерева  функция проверяет подпись под открытым ключом и,
    в случае успешной проверки, создает контекст `vkey` и инициирует его необходимыми значениями.

    \param vkey контекст создаваемого открытого ключа асимметричного криптографического алгоритма
    \param filename имя файла
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_import_from_request( ak_verifykey vkey, const char *filename )
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
  if(( error = ak_asn1_import_from_file( root = ak_asn1_new(), filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
    goto lab1;
  }

 /* здесь мы считали asn1, декодировали и должны убедиться, что это то самое дерево */
  ak_asn1_first( root );
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
  ak_asn1_first( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) {
    ak_error_message( ak_error_invalid_asn1_tag, __func__, "incorrect structure of asn1 context" );
    goto lab1;
  }
  if(( error = ak_verifykey_import_from_asn1_request( vkey,
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
  ak_asn1_first( asn );
  if(( error = ak_tlv_encode( asn->current, buffer, &size )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                 "incorrect encoding of asn1 context contains of %u octets", (unsigned int) size );
    goto lab1;
  }

 /* 2. Теперь получаем значение подписи из asn1 дерева и сравниваем его с вычисленным значением */
  ak_asn1_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_get_bit_string( asn->current, &bs )) != ak_error_ok ) {
    ak_error_message( error , __func__ , "incorrect value of bit string in root asn1 context" );
    goto lab1;
  }

 /* 3. Только сейчас проверяем подпись под данными */
  if( ak_verifykey_verify_ptr( vkey, buffer, size, bs.value ) != ak_true ) {
    ak_error_message( error = ak_error_get_value(), __func__, "digital signature isn't valid" );
    goto lab1;
  }

 /* 4. На основе считанных данных формируем номер ключа */
  if(( error = ak_verifykey_set_number( vkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation on public key number" );
    goto lab1;
  }

 /* 5. В самом конце, после проверки подписи,
    изымаем узел, содержащий имя владельца открытого ключа -- далее этот узел будет перемещен
    в сертификат открытого ключа.
    Все проверки пройдены ранее и нам точно известна структура asn1 дерева. */
  ak_asn1_first( asn );
  asn = asn->current->data.constructed;
  ak_asn1_first( asn );
  ak_asn1_next( asn ); /* нужен второй узел */
  vkey->name = ak_asn1_exclude( asn );

  lab1: if( root != NULL ) ak_asn1_delete( root );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_verifykey_load_from_request( const char *filename )
{
  ak_pointer vkey = NULL;
  int error = ak_error_ok;

  if(( error = ak_verifykey_import_from_request( vkey = malloc( sizeof( struct verifykey )),
                                                                    filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                         "incorrect loading a public key from %s file", filename );
    if( vkey != NULL ) {
      ak_verifykey_destroy( vkey );
      free( vkey );
    }
  }

 return vkey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example aktool-key.c                                                                          */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_keys.c  */
/* ----------------------------------------------------------------------------------------------- */
