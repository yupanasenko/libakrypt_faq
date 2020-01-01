/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 by Anton Sakharov                                                           */
/*  Copyright (c) 2020 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_asn1_keys.c                                                                            */
/*  - содержит реализацию функций,                                                                 */
/*    используемых для базового кодирования/декодированя ASN.1 структур                            */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_asn1.h>
 #include <ak_skey.h>
 #include <ak_tools.h>

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
 #include <ak_asn1.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает `SEQUENCE`, которая содержит два примитивных элемента -
    начало и окончание временного интервала.

   \param asn1 указатель на текущий уровень ASN.1 дерева.
   \param not_before начало временного интервала
   \param not_before окончание временного интервала
   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_add_time_validity( ak_asn1 asn1, time_t not_before, time_t not_after )
{
  int error = ak_error_ok;
  ak_asn1 asn_validity = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
  if(( error = ak_asn1_context_create( asn_validity =
                                                 malloc( sizeof( struct asn1 )))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of asn1 context" );

  if(( error = ak_asn1_context_add_utc_time( asn_validity, not_before )) != ak_error_ok ) {
    ak_asn1_context_delete( asn_validity );
    return ak_error_message( error, __func__, "incorrect adding \"not before\" time" );
  }
  if(( error = ak_asn1_context_add_utc_time( asn_validity, not_after )) != ak_error_ok ) {
    ak_asn1_context_delete( asn_validity );
    return ak_error_message( error, __func__, "incorrect adding \"not after\" time" );
  }

 return ak_asn1_context_add_asn1( asn1, TSEQUENCE, asn_validity );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param asn1 указатель на текущий уровень ASN.1 дерева.
    \param skey контекст секретного ключа; контекст должен быть инициализирован ключевым значением,
    а поле oid должно содержать идентификатор алгоритма, для которого предназначен ключ.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_add_skey_metadata( ak_asn1 asn1, ak_skey skey )
{
  int error = ak_error_ok;
  ak_asn1 asn_meta = NULL, asn_down = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 element" );
  if( skey == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( skey->oid == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                     "using secret key context with undefined object identifier" );

  if(( error = ak_asn1_context_create( asn_meta = malloc( sizeof( struct asn1 )))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
  if(( error = ak_asn1_context_add_oid( asn_meta, skey->oid->id )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect adding secret key object identifier" );
    goto labexit;
  }
  if(( error = ak_asn1_context_add_octet_string( asn_meta,
                                         skey->number, sizeof( skey->number ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect adding secret key number" );
    goto labexit;
  }
 /* создаем новый уровень и вкладываем его в вышестоящий уровень */
  if(( error = ak_asn1_context_create(
                                    asn_down = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of asn1 context" );
    goto labexit;
  } else ak_asn1_context_add_asn1( asn_meta, TSEQUENCE, asn_down );

  if(( error = ak_asn1_context_add_uint32( asn_down,
                                                   skey->resource.value.type )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect adding secret key resource type" );
    goto labexit;
  }
  if(( error = ak_asn1_context_add_uint32( asn_down,
                                    (ak_uint32) skey->resource.value.counter )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect adding secret key resource value" );
    goto labexit;
  }
  if(( error = ak_asn1_context_add_time_validity( asn_down,
               skey->resource.time.not_before, skey->resource.time.not_after )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect adding secret key time validity" );
    goto labexit;
  }
 /* вставляем изготовленную последовательность и выходим */
  return ak_asn1_context_add_asn1( asn1, TSEQUENCE, asn_meta );

 /* выход в случае неудачи */
  labexit: ak_asn1_context_delete( asn_meta );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает ключ шифрования контента из пароля и экспортирует параметры ключа,
    необходимые для восстановления.

    \param root уровень ASN.1 дерева
    \param bkey контекст ключа шифрования контекста
    \param password пароль, используемый для генерации ключа шифрования контента
    \param pass_size длина пароля (в октетах)

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_context_add_kek_from_password( ak_asn1 root, ak_bckey bkey,
                                                    const char *password, const size_t pass_size )
{
  ak_uint8 salt[32]; /* случайное значение для генерации ключа шифрования контента */
  int error = ak_error_ok;
  ak_asn1 asn1 = NULL, asn2 = NULL;

 /* инициализируем контекст ключа шифрования контента */
   if(( error = ak_bckey_context_create_kuznechik( bkey )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of block cipher key" );

 /* вырабатываем случайное значение ключа шифрования контента */
   ak_random_context_random( &bkey->key.generator, salt, sizeof( salt ));
   ak_bckey_context_set_key_from_password( bkey, (ak_pointer) password, pass_size,
                                                                             salt, sizeof( salt ));
 /* собираем ASN.1 дерево */
   if(( ak_asn1_context_create( asn2 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
   }
   ak_asn1_context_add_oid( asn2, bkey->key.oid->id );

   if(( ak_asn1_context_create( asn1 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_asn1_context_delete( asn2 );
     return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
   }
   ak_asn1_context_add_oid( asn1, ak_oid_context_find_by_name( "hmac-streebog512" )->id );
   ak_asn1_context_add_octet_string( asn1, salt, sizeof( salt ));
   ak_asn1_context_add_uint32( asn1,
                                 ( ak_uint32 )ak_libakrypt_get_option( "pbkdf2_iteration_count" ));
   ak_asn1_context_add_asn1( asn2, TSEQUENCE, asn1 );

   if(( ak_asn1_context_create( asn1 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_asn1_context_delete( asn2 );
     return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
   }
   ak_asn1_context_add_uint32( asn1, password_based_encryption_key );
   ak_asn1_context_add_asn1( asn1, TSEQUENCE, asn2 );

  /* помещаем в основное ASN.1 дерево структуру KeyEncryptionKeyParameters */
 return ak_asn1_context_add_asn1( root, TSEQUENCE, asn1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция добавляет зашифрованный секретный ключ `skey` в текущий уровень ASN.1 дерева.

    \param root уровень ASN.1 дерева
    \param bkey контекст ключа шифрования контекста
    \param skey контекст сохраняемого ключа

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_context_add_skey( ak_asn1 root, ak_bckey bkey, ak_skey skey )
{
  size_t len = 0;
  ak_uint8 iv[16]; /* синхропосылка, используемая для шифрования контента */
  ak_asn1 asn = NULL, asn1 = NULL;
  int error = ak_error_ok;

 /* проверяем длины */
  if((( len = 2*skey->key_size )%bkey->bsize ) != 0 )
    return ak_error_message( ak_error_wrong_length, __func__,
                               "using cbc encryption mode with unsupported length of secret key" );
 /* указываем тип контента */
  if(( error = ak_asn1_context_create( asn = malloc( sizeof( struct asn1 )))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
  ak_asn1_context_add_uint32( asn, secret_key_content );

 /* добавляем параметры шифрования */
  ak_random_context_random( &bkey->key.generator, iv, sizeof( iv ));
  if(( error = ak_asn1_context_create( asn1 = malloc( sizeof( struct asn1 )))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
  ak_asn1_context_add_oid( asn1, "1.1.1.1.1.1.1.1.1.1.1.1" ); /* режим шифрования */
  ak_asn1_context_add_octet_string( asn1, iv, sizeof( iv ));
  ak_asn1_context_add_uint32( asn1, ( ak_uint32 )ak_libakrypt_get_option( "openssl_compability" ));
  ak_asn1_context_add_asn1( asn, TSEQUENCE, asn1 );

 /* добавляем ключевые метаданные */
  ak_asn1_context_add_skey_metadata( asn, skey );

 /* зашифровываем данные */
  if(( error = ak_asn1_context_create( asn1 = malloc( sizeof( struct asn1 )))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
  ak_asn1_context_add_uint32( asn1, data_present_storage );
  ak_asn1_context_add_octet_string( asn1, iv, len );
  if(( error = ak_bckey_context_encrypt_cbc( bkey, skey->key, asn1->current->data.primitive,
                                                         len, iv, sizeof( iv ))) != ak_error_ok ) {
    ak_asn1_context_delete( asn1 );
    return error;
  }
  ak_asn1_context_add_asn1( asn, TSEQUENCE, asn1 );

 return ak_asn1_context_add_asn1( root, TSEQUENCE, asn );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция вычисляет имитовставку для der-представления ASN.1 дерева `asn` и записывает
    ее значение в корневое ASN.1 дерево.

    \param root корневой уровень ASN.1 дерева
    \param asn уровень ASN1.дерева, для которого вычисляется имитовставка
    \param bkey ключ имитозащиты

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_context_add_asn1_cmac( ak_asn1 root, ak_asn1 asn, ak_bckey bkey )
{
  ak_asn1 asn_cmac = NULL;
  int error = ak_error_ok;
  ak_uint8 out[16], derbuf[1024]; /* буффера, куда будут помещены данные */
  size_t len = sizeof( derbuf );

  memset( derbuf, 0, sizeof( derbuf ));
  if(( error = ak_asn1_context_encode( asn, derbuf, &len )) != ak_error_ok ) {
    if( error == ak_error_wrong_length )
      return ak_error_message_fmt( error, __func__,
                          "not enough internal memory to accommodate %u octets", (ak_uint32) len );
     else return ak_error_message( error, __func__, "incorrect encoding of asn1 structure" );
  }

  memset( out, 0, sizeof( out ));
  if(( error = ak_bckey_context_cmac( bkey, derbuf, len, out, bkey->bsize )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect calculation of cmac" );
  }
   else {
     if(( ak_asn1_context_create( asn_cmac = malloc( sizeof( struct asn1 )))) == ak_error_ok ) {
       ak_asn1_context_add_oid( asn_cmac, "2.2.2.2.2.2.2.2.2.2" );
       ak_asn1_context_add_octet_string( asn_cmac, out, bkey->bsize );
       ak_asn1_context_add_asn1( root, TSEQUENCE, asn_cmac );
     }
   }

  ak_ptr_context_wipe( derbuf, sizeof( derbuf ), &bkey->key.generator );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! При экспорте секретного ключа выполняется следующая последовательность действий:
     - из заданного пользователем пароля формируется секретный ключ шифрования контента
     (kek, key encryption key);
     - формируется ASN.1 структура, содержащая параметры восстановления ключа kek,
     параметры экспортируемого ключа, а также сам экспортируемый ключ (включая маску ключа),
     в зашифрованном виде;
     - вычисляется имитовставка от сформированных данных и добавляется к ASN.1 структуре;
     - полученная структура кодируется в der-последовательность и помещается в
     заданный пользователем буффер.

    \param skey контекст экспортируемого секретного ключа; контекст должен быть инициализирован
    ключевым значением, а поле oid должно содержать идентификатор алгоритма, для которого
    предназначен ключ.
    \param password пароль, используемый для генерации ключа шифрования контента
    \param pass_size длина пароля (в октетах)
    \param buffer буффер, куда будут помещен экспортируемый ключ; память под буффер должна быть
    выработана заранее
    \param buffer_size размер выделенной памяти; до начала выполнения функции переменная должна содержать
    размер выделенной памяти; в процессе выполнения функции в данную переменную помещается
    размер сформированной der-последовательности.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_export_to_der_from_password( ak_skey skey, const char *password,
                                     const size_t pass_size, ak_uint8 *buffer, size_t *buffer_size )
{
  struct asn1 root; /* вершина создаваемого ASN.1 дерева */
  ak_asn1 asn = NULL;
  struct bckey bkey; /* ключ шифрования контента */
  int error = ak_error_ok;

  if( skey == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( skey->oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using undefined secret key context" );
  if(( password == NULL ) || ( !pass_size ))
    return ak_error_message( ak_error_invalid_value, __func__, "incorrect password" );
  if(( buffer == NULL ) || ( !buffer_size ))
    return ak_error_message( ak_error_invalid_value, __func__, "incorrect output buffer" );

 /* 1. создаем основное дерево, в которое будет помещен секретный ключ */
   if(( error = ak_asn1_context_create( asn = malloc( sizeof( struct asn1 )))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
   ak_asn1_context_add_oid( asn, "1.2.643.2.52.1.127.1.2" ); /* помечаем контейнер */

  /* 2. вырабатываем ключ шифрования контента и помещаем информацию о нем в ASN.1 дерево */
   if(( error = ak_asn1_context_add_kek_from_password( asn, &bkey,
                                                          password, pass_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of key encryption key" );
     goto labexit;
   }

  /* зашифровываем секретный ключ и помещаем информацию об этом в ASN.1 дерево */
   if(( error = ak_asn1_context_add_skey( asn, &bkey, skey )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation of key encryption key" );
     goto labexit;
   }
  /* изменяем маску секретного ключа */
   if(( error = skey->set_mask( skey )) != ak_error_ok )
     ak_error_message( error, __func__, "wrong changing a mask on secret key" );

  /* содаем корень и помещаем в него: */
   ak_asn1_context_create( &root );
   ak_asn1_context_add_asn1( &root, TSEQUENCE, asn ); /* собранное ранее дерево */
                                            /* и имитовставку собранного дерева */
   if(( error = ak_asn1_context_add_asn1_cmac( &root, asn, &bkey )) != ak_error_ok )
     ak_error_message( error, __func__, "export secret key without integrity code" );

  /* кодируем полное дерево */
   if(( error = ak_asn1_context_encode( &root, buffer, buffer_size )) != ak_error_ok )
     ak_error_message( error, __func__, "wrong encoding of asn1 context" );

   labexit:
     ak_asn1_context_destroy( &root );
     ak_bckey_context_destroy( &bkey );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_keys.c  */
/* ----------------------------------------------------------------------------------------------- */
