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
/*! \brief Функция инициализирует ключи шифрования и имитозащиты контента из пароля и экспортирует
    в ASN.1 дерево параметры ключа, необходимые для восстановления ключей.

    \param root уровень ASN.1 дерева
    \param ekey контекст ключа шифрования контекста
    \param ekey контекст ключа имитозащиты
    \param password пароль, используемый для генерации ключа шифрования контента
    \param pass_size длина пароля (в октетах)

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_context_add_derived_keys_from_password( ak_asn1 root, ak_bckey ekey,
                                       ak_bckey ikey, const char *password, const size_t pass_size )
{
  ak_uint8 salt[32]; /* случайное значение для генерации ключа шифрования контента */
  ak_uint8 derived_key[64]; /* вырабатываемый из пароля ключевой материал,
                               из которого формируются производные ключи шифрования и имитозащиты */
  int error = ak_error_ok;
  ak_asn1 asn1 = NULL, asn2 = NULL;

 /* 1. вырабатываем случайное значение и производный ключевой материал */
   if(( error = ak_bckey_context_create_kuznechik( ekey )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of encryption cipher key" );

   ak_random_context_random( &ekey->key.generator, salt, sizeof( salt ));
   if(( error = ak_hmac_context_pbkdf2_streebog512( (ak_pointer) password, pass_size,
                salt, sizeof( salt ), (size_t) ak_libakrypt_get_option( "pbkdf2_iteration_count" ),
                                                               64, derived_key )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of derived key" );

 /* 2. инициализируем контексты ключа шифрования контента и ключа имитозащиты */
   if(( error = ak_bckey_context_set_key( ekey, derived_key, 32 )) != ak_error_ok ) {
     ak_bckey_context_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to encryption key" );
   }
   if(( error = ak_bckey_context_create_kuznechik( ikey )) != ak_error_ok ) {
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

 /* 3. собираем ASN.1 дерево */
   if(( ak_asn1_context_create( asn2 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_context_destroy( ikey );
     ak_bckey_context_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
   }
   ak_asn1_context_add_oid( asn2, ekey->key.oid->id ); /* сохраняем oid базового алгоритма */

   if(( ak_asn1_context_create( asn1 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_context_destroy( ikey );
     ak_bckey_context_destroy( ekey );
     ak_asn1_context_delete( asn2 );
     return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
   }
   ak_asn1_context_add_oid( asn1, ak_oid_context_find_by_name( "hmac-streebog512" )->id );
   ak_asn1_context_add_uint32( asn1, sizeof( derived_key ));
   ak_asn1_context_add_octet_string( asn1, salt, sizeof( salt ));
   ak_asn1_context_add_uint32( asn1,
                                 ( ak_uint32 )ak_libakrypt_get_option( "pbkdf2_iteration_count" ));
   ak_asn1_context_add_asn1( asn2, TSEQUENCE, asn1 );

   if(( ak_asn1_context_create( asn1 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
     ak_bckey_context_destroy( ikey );
     ak_bckey_context_destroy( ekey );
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
 static int ak_asn1_context_add_skey( ak_asn1 root, ak_skey skey, ak_bckey ekey, ak_bckey ikey )
{
  size_t ivsize  = ekey->bsize >> 1,
         keysize = 2*skey->key_size;
  size_t len = ivsize + keysize + ikey->bsize;
             /* необходимый объем памяти:
                синхропосылка (половина блока) + ( ключ+маска ) + имитовставка (блок) */
  ak_asn1 asn = NULL, asn1 = NULL;
  int error = ak_error_ok;

 /* указываем тип контента */
  if(( error = ak_asn1_context_create( asn = malloc( sizeof( struct asn1 )))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
  ak_asn1_context_add_uint32( asn, secret_key_content );

 /* добавляем ключевые метаданные */
  ak_asn1_context_add_skey_metadata( asn, skey );

 /* выделяем память для хранения  */
  if(( error = ak_asn1_context_create( asn1 = malloc( sizeof( struct asn1 )))) != ak_error_ok ) {
    ak_asn1_context_delete( asn );
    return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
  }
  ak_asn1_context_add_uint32( asn1, data_present_storage ); /* данные присутствуют и находятся ниже */
  ak_asn1_context_add_uint32( asn1, ( ak_uint32 )ak_libakrypt_get_option( "openssl_compability" ));

 /* добавляем ключ: реализуем КЕexp15 для ключа и маски */
  if(( error = ak_asn1_context_add_octet_string( asn1, &len, len )) == ak_error_ok ) {
    ak_uint8 *ptr = asn1->current->data.primitive;

   /* формируем iv */
    memset( ptr, 0, len );
    ak_random_context_random( &ekey->key.generator, ptr, ivsize );
   /* меняем маску секретного ключа */
    skey->set_mask( skey );
   /* копируем данные:
      сохраняем их как большое целое число в big-endian кодировке */
    ak_mpzn_to_little_endian( ( ak_uint64 *)skey->key,
                                             (skey->key_size >> 2), ptr+ivsize, keysize, ak_true );
   /* меняем маску секретного ключа */
    skey->set_mask( skey );
   /* вычисляем имитовставку */
    if(( error = ak_bckey_context_cmac( ikey, ptr, ivsize+keysize,
                                            ptr+(ivsize+keysize), ikey->bsize )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect evaluation of cmac" );
      ak_asn1_context_delete( asn1 );
      return error;
    }
   /* шифруем данные */
    if(( error = ak_bckey_context_ctr( ekey, ptr+ivsize, ptr+ivsize, keysize+ikey->bsize,
                                                                  ptr, ivsize )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect encryption of skey" );
      ak_asn1_context_delete( asn1 );
      return error;
    }
  } else return ak_error_message( error, __func__, "incorrect adding a secret key" );

  ak_asn1_context_add_asn1( asn, TSEQUENCE, asn1 );
 return ak_asn1_context_add_asn1( root, TSEQUENCE, asn );
}

/* ----------------------------------------------------------------------------------------------- */
/*! При экспорте секретного ключа выполняется следующая последовательность действий:
     - из заданного пользователем пароля формируются два ключа
        -  секретный ключ шифрования контента (kek, key encryption key);
        -  секретный ключ имитозащиты (kak, key authentication key )
     - формируется ASN.1 структура, содержащая параметры восстановления секретных ключей kek и kak,
       параметры экспортируемого ключа, а также сам экспортируемый ключ (включая маску ключа),
       в зашифрованном виде;
     - вычисляется имитовставка от сформированных данных и добавляется к ASN.1 структуре;
     - полученная структура кодируется в der-последовательность и помещается в
     заданный пользователем буффер.

    \param skey контекст экспортируемого секретного ключа; контекст должен быть инициализирован
    ключевым значением, а поле oid должно содержать идентификатор алгоритма, для которого
    предназначен ключ.
    \param root контекст ASN.1 дерева; должен быть создан заранее с помощью
    вызова функции ak_asn1_context_create()
    \param password пароль, используемый для генерации ключа шифрования контента
    \param pass_size длина пароля (в октетах)

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_export_to_asn1_with_password( ak_skey skey, ak_asn1 root,
                                                      const char *password, const size_t pass_size )
{
  ak_asn1 asn = NULL;
  struct bckey ekey, ikey; /* производные ключи шаирования и имитозащиты */
  int error = ak_error_ok;


  if( skey == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( skey->oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using undefined secret key context" );
  if(( password == NULL ) || ( !pass_size ))
    return ak_error_message( ak_error_invalid_value, __func__, "incorrect password" );

 /* 1. создаем основное дерево, в которое будет помещен секретный ключ */
   if(( error = ak_asn1_context_create( asn = malloc( sizeof( struct asn1 )))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context" );
   ak_asn1_context_add_oid( asn, "1.2.643.2.52.1.127.1.2" ); /* помечаем контейнер */

 /* 2. создаем ключи шифрования и имитозащиты контента и помещаем информацию о них в ASN.1 дерево */
   if(( error = ak_asn1_context_add_derived_keys_from_password( asn, &ekey, &ikey,
                                                          password, pass_size )) != ak_error_ok ) {
     ak_asn1_context_delete( asn );
     return ak_error_message( error, __func__, "incorrect creation of derived keys" );
   }

 /* 3. зашифровываем секретный ключ и помещаем информацию об этом в ASN.1 дерево */
   if(( error = ak_asn1_context_add_skey( asn, skey, &ekey, &ikey )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect addition of secret key" );
     goto labexit;
   }
  /* изменяем маску секретного ключа */
   if(( error = skey->set_mask( skey )) != ak_error_ok )
     ak_error_message( error, __func__, "wrong mask changing on secret key" );

 /* 4.помещаем в корень созданное дерево */
   ak_asn1_context_add_asn1( root, TSEQUENCE, asn ); /* собранное ранее дерево */
                                            /* и имитовставку собранного дерева */
   labexit:
     ak_bckey_context_destroy( &ekey );
     ak_bckey_context_destroy( &ikey );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает ASN.1 дерево, содержащее экспортное представление секретного ключа,
    после чего кодирует дерево в виде der-последовательности и сохряняет
    данную последовательность в файл.

    Примеры вызова функции
    \code
       char filemane[256];

      // сохранение ключа в файле, имя которого возвращается в переменной filename
       ak_skey_context_export_to_derfile_with_password( skey, filename, sizeof( filename ),
                                                                                   "password", 8 );
      // сохранение ключа в файле с заданным именем
       ak_skey_context_export_to_derfile_with_password( skey, "key.file", 0, "password", 8 );
    \endcode

    \param skey контекст экспортируемого секретного ключа; контекст должен быть инициализирован
    ключевым значением, а поле oid должно содержать идентификатор алгоритма, для которого
    предназначен ключ.
    \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ.
    Если параметр `size` отличен от нуля ,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
    \param size размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
    \param password пароль, используемый для генерации ключа шифрования контента
    \param pass_size длина пароля (в октетах)

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_context_export_to_derfile_with_password( ak_skey skey, char *filename,
                                  const size_t size, const char *password, const size_t pass_size )
{
  struct file fp;
  struct asn1 root;
  ssize_t wbb = 0;
  size_t len = 0, wb = 0;
  int error = ak_error_ok;
  ak_uint8 *buffer = NULL;

  /* формируем имя файла для хранения ключа
     (данное имя в точности совпадает с номером ключа) */
   if( size ) {
     if( size < ( 5 + 2*sizeof( skey->number )) )
       return ak_error_message( ak_error_out_of_memory, __func__,
                                               "insufficent memory size for secret key filename" );
     memset( filename, 0, size );
     ak_snprintf( filename, size, "%s.key",
                                 ak_ptr_to_hexstr( skey->number, sizeof(skey->number), ak_false ));
   }

  /* создаем ASN.1 дерево */
   if(( error = ak_asn1_context_create( &root )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of asn1 context");
   if((error = ak_skey_context_export_to_asn1_with_password( skey, &root,
                                                          password, pass_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "wrong export a secret key to asn1 context" );
     goto lab1;
   }
   ak_asn1_context_evaluate_length( &root, &len );

  /* кодируем */
   if(( buffer = malloc( len )) == NULL )  {
     ak_error_message( ak_error_out_of_memory, __func__,
                                                  "incorrect memory allocation for der-sequence" );
     goto lab1;
   }
   if(( error = ak_asn1_context_encode( &root, buffer, &len )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect encoding of asn1 context" );
     goto lab2;
   }

  /* сохраняем */
   if(( error = ak_file_create_to_write( &fp, filename )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect creation a file for secret key" );
     goto lab2;
   }
   do{
     wbb = ak_file_write( &fp, buffer, len );
     if( wbb == -1 ) {
       ak_error_message( error = ak_error_get_value(), __func__ ,
                                                     "incorrect writing an encoded data to file" );
       goto lab3;
     }
      else wb += (size_t) wbb;
   } while( wb < len );

   lab3: ak_file_close( &fp );
   lab2: free( buffer );
   lab1: ak_asn1_context_destroy( &root );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает ASN.1 дерево, содержащее экспортное представление секретного ключа
    алгоритма блочного шифрования, после чего кодирует дерево в виде der-последовательности и
    сохряняет данную последовательность в файл.

    Примеры вызова функции
    \code
       char filemane[256];

      // сохранение ключа в файле, имя которого возвращается в переменной filename
       ak_bckey_context_export_to_derfile_with_password( bkey, filename, sizeof( filename ),
                                                                                   "password", 8 );
      // сохранение ключа в файле с заданным именем
       ak_bckey_context_export_to_derfile_with_password( bkey, "key.file", 0, "password", 8 );
    \endcode

    \param bkey контекст экспортируемого секретного ключа блочного алгоритма шифрования;
    контекст должен быть инициализирован ключевым значением.
    \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ.
    Если параметр `size` отличен от нуля ,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
    \param size размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
    \param password пароль, используемый для генерации ключа шифрования контента
    \param pass_size длина пароля (в октетах)

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_export_to_derfile_with_password( ak_bckey bkey, char *filename,
                                 const size_t size, const char *password, const size_t pass_size )
{
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                "using null pointer to block cipher key context" );
  if(( password == NULL ) || ( pass_size == 0 ))
    return ak_error_message( ak_error_wrong_length, __func__, "using incorrect password" );

 return ak_skey_context_export_to_derfile_with_password( &bkey->key,
                                                            filename, size, password, pass_size );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_export_to_derfile_with_password( ak_signkey sk, char *filename,
                                 const size_t size, const char *password, const size_t pass_size )
{
  if( sk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                    "using null pointer to digital signature secret key context" );
  if(( password == NULL ) || ( pass_size == 0 ))
    return ak_error_message( ak_error_wrong_length, __func__, "using incorrect password" );

 return ak_skey_context_export_to_derfile_with_password( &sk->key,
                                                            filename, size, password, pass_size );
}

/* ----------------------------------------------------------------------------------------------- */
                            /* Функции для импорта ключевых контейнеров */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция считывает der-последовательность из файла и раскодирует ее в заданный asn1 контекст.
    Память под asn1 контекст должна быть выделена заранее.

    \param asn указатель ASN.1 дерево.
    \param filename указатель на строку, содержащую имя файла.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_create_from_derfile( ak_asn1 asn, const char *filename )
{
  size_t len = 0;
  ak_uint8 *ptr = NULL;
  int error = ak_error_ok;

 /* считываем данные */
   if(( ptr = ak_ptr_load_from_file( ptr, &len, filename )) == NULL )
    return ak_error_message_fmt( ak_error_get_value(), __func__,
                                        "incorrect loading an ASN.1 data from file %s", filename );
 /* создаем контекст */
  if(( error = ak_asn1_context_create( asn )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of asn1 context" );
    goto exitlab;
  }

 /* декодируем данные */
  if(( error = ak_asn1_context_decode( asn, ptr, len, ak_true )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect decoding of der-sequence" );
    goto exitlab;
  }

  exitlab: free( ptr );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_tlv_context_check_key_container( ak_tlv tlv )
{
  ak_asn1 asn = NULL;
  ak_pointer str = NULL;

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
  if( strncmp( str, "1.2.643.2.52.1.127.1.2", 22 ) != 0 ) return ak_false;

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param roor указатель на структуру ASN.1 дерева.
    \param count переменная, в которой возвращается количество ключей, содержащихся в контейнере.

    \return Функция возвращает истину, если количество ключей в контейнере отдично от нуля.
    В противном случае возвращается ложь.                                                          */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_context_check_key_container( ak_asn1 root, size_t *count )
{
  if( root == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 context" );
    return ak_false;
  }

 /* обходим верхний уровень дерева и проверяем общее количество SEQUENCE,
    которые являются ключевыми контейнерами  */
  *count = 0;
  ak_asn1_context_first( root );
  do{
     if( ak_tlv_context_check_key_container( root->current )) (*count)++;
  } while( ak_asn1_context_next( root ));

  if( *count ) return ak_true;
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param root Исходное ASN.1 дерево, в котором ищется ключ с заданным номером
    \param akey Поддерево, содержащее информацию о конкретном ключе
    \param number Номер ключа в исходном дереве
    \param oid Идентификатор алгоритма, для которог предназначен ключ

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_get_asn1_key_from_container( ak_asn1 root,
                                                         ak_asn1 *akey, size_t number, ak_oid *oid )
{
  size_t count = 0;
  if( root == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 context" );
    return ak_false;
  }

 /* далее аццкий код прямого доступа */
  ak_asn1_context_first( root );
  do{
     if( ak_tlv_context_check_key_container( root->current )) {
       if( number == count ) { /* получаем информацию о ключе */
         ak_asn1 asn = NULL;
         ak_pointer str = NULL;
         ak_uint32 value = undefined_content;
         *akey = root->current->data.constructed;

         /* теперь надо достать информацию о сохраненном ключе
            получаем asn1 уровень, на котором лежит oid ключа */
         ak_asn1_context_last( *akey );
         if(( DATA_STRUCTURE( (*akey)->current->tag ) != CONSTRUCTED ) ||
            ( TAG_NUMBER( (*akey)->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
          else asn = (*akey)->current->data.constructed;

        /* проверяем тип ключа */
         ak_asn1_context_first( asn );
         if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;

         ak_tlv_context_get_uint32( asn->current, &value );
         /* на данном этапе мы умеем разбирать только секретные ключи */
         if( value != secret_key_content ) return ak_error_invalid_asn1_content;

        /* спускаемся на 1 уровень ниже */
         ak_asn1_context_next( asn );
         if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
            ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
         asn = asn->current->data.constructed;

        /* только теперь получаем oid */
         ak_asn1_context_first( asn );
         if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
         ak_tlv_context_get_oid( asn->current, &str );
         if(( *oid = ak_oid_context_find_by_id( str )) == NULL ) return ak_error_oid_id;

         return ak_error_ok;
       }
        else count++;
     }
  } while( ak_asn1_context_next( root ));

  return ak_error_wrong_index;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает номер ключа, а также его ресурс и временной интервал.

    \param akey контекст ASN.1 дерева, содержащий информацию о ключе
    \param skey контекст секретного ключа
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_get_skey_metadata( ak_asn1 akey, ak_skey skey )
{
  size_t size = 0;
  ak_uint32 u32 = 0;
  ak_asn1 asn = NULL;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;

  /* получаем доступ к поддереву с ключевыми данными */
   ak_asn1_context_last( akey );
   if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
               ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = akey->current->data.constructed;

  /* спускаемся ниже к метаданным */
   ak_asn1_context_first( asn );
   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
                ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = asn->current->data.constructed;

  /* устанавливаем номер ключа */
   ak_asn1_context_first( asn );
   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING )) return ak_error_invalid_asn1_tag;
   ak_tlv_context_get_octet_string( asn->current, &ptr, &size );
   memset( skey->number, 0, sizeof( skey->number ));
   if( ptr != NULL ) memcpy( skey->number, ptr, ak_min( sizeof( skey->number ), size ));

  /* переходим к ресурсу */
   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
                ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = asn->current->data.constructed;

  /* тип */
   ak_asn1_context_first( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   ak_tlv_context_get_uint32( asn->current, &u32 );
   skey->resource.value.type = u32;

  /* значение */
   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   ak_tlv_context_get_uint32( asn->current, &u32 );
   skey->resource.value.counter = u32;

  /* время */
   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
                ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
    else asn = asn->current->data.constructed;

   ak_asn1_context_first( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TUTCTIME )) return ak_error_invalid_asn1_tag;
    else ak_tlv_context_get_utc_time( asn->current, &skey->resource.time.not_before );
   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TUTCTIME )) return ak_error_invalid_asn1_tag;
    else ak_tlv_context_get_utc_time( asn->current, &skey->resource.time.not_after );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param function Обработчик операции чтения пароля.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_set_password_read_function( ak_function_password_read *function )
{
  if( function == NULL )
    return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to password read function" );
  ak_function_default_password_read = function;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция вырабатывает производные ключи на основе информации, хранящейся в ASN.1 дереве
    с использованием пароля, введенного пользователем.

    Для ввода пароля используется функция, на которую указывает ak_function_defaut_password_read.
    Если этот указатель не установлен (то есть равен NULL), то выполняется чтение пароля
    из терминала.

    \param akey контекст ASN.1 дерева, содержащий информацию о ключе
    \param ekey контекст ключа шифрования
    \param ikey контекст ключа имитозащиты
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_context_get_derived_keys_with_password( ak_asn1 akey,
                                                                      ak_bckey ekey, ak_bckey ikey )
{
  size_t size = 0;
  ak_uint32 u32 = 0;
  ak_asn1 asn = NULL;
  ak_uint8 derived_key[64]; /* вырабатываемый из пароля ключевой материал,
                               из которого формируются производные ключи шифрования и имитозащиты */
  char password[256];
  ak_pointer ptr = NULL;
  int error = ak_error_ok;

  /* получаем структуру с параметрами, необходимыми для восстановления ключа */
   ak_asn1_context_first( akey );
   if(( DATA_STRUCTURE( akey->current->tag ) != PRIMITIVE ) ||
      ( TAG_NUMBER( akey->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
   ak_asn1_context_next( akey );
   if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
               ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
     else asn = akey->current->data.constructed;

  /* проверяем параметры */
   ak_asn1_context_first( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
      ( TAG_NUMBER( asn->current->tag ) != TOBJECT_IDENTIFIER )) return ak_error_invalid_asn1_tag;
   ak_tlv_context_get_oid( asn->current, &ptr );
   if( strncmp( "1.2.643.7.1.1.4.2", ptr, 17 ) != 0 ) return ak_error_invalid_asn1_content;

   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
      ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   ak_tlv_context_get_uint32( asn->current, &u32 );
   if( u32 != 64 ) return ak_error_invalid_asn1_content;

   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
      ( TAG_NUMBER( asn->current->tag ) != TOCTET_STRING )) return ak_error_invalid_asn1_tag;
   ak_tlv_context_get_octet_string( asn->current, &ptr, &size );

   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
      ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   ak_tlv_context_get_uint32( asn->current, &u32 );

   if( ak_function_default_password_read == NULL ) {
     fprintf( stdout, "password: "); fflush( stdout );
     error = ak_password_read( password, sizeof( password ));
     fprintf( stdout, "\n" );
   } else error = ak_function_default_password_read( password, sizeof( password ));
   if( error != ak_error_ok ) return error;

 /* получаем пользовательский пароль и вырабатываем производную ключевую информацию */
   error = ak_hmac_context_pbkdf2_streebog512( (ak_pointer) password, strlen( password ),
                                                                 ptr, size, u32, 64, derived_key );
   memset( password, 0, sizeof( password ));
   if( error != ak_error_ok ) return error;

 /* 2. инициализируем контексты ключа шифрования контента и ключа имитозащиты */
   if(( error = ak_bckey_context_create_kuznechik( ekey )) != ak_error_ok ) {
     memset( derived_key, 0, sizeof( derived_key ));
     return ak_error_message( error, __func__, "incorrect creation of encryption cipher key" );
   }
   if(( error = ak_bckey_context_set_key( ekey, derived_key, 32 )) != ak_error_ok ) {
     ak_ptr_context_wipe( derived_key, sizeof( derived_key ), &ekey->key.generator );
     ak_bckey_context_destroy( ekey );
     return ak_error_message( error, __func__, "incorrect assigning a value to encryption key" );
   }

   if(( error = ak_bckey_context_create_kuznechik( ikey )) != ak_error_ok ) {
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
/*! \brief Функция вырабатывает производные ключи на основе информации, хранящейся в ASN.1 дереве
    \param akey контекст ASN.1 дерева, содержащий информацию о ключе
    \param ekey контекст ключа шифрования
    \param ikey контекст ключа имитозащиты
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_context_get_derived_keys( ak_asn1 akey, ak_bckey ekey, ak_bckey ikey )
{
  ak_asn1 asn = NULL;
  ak_uint32 choice = 0;

  /* получаем дерево с параметрами ключей шифрования и имитозащиты */
   ak_asn1_context_first( akey );
   ak_asn1_context_next( akey );
   if(( DATA_STRUCTURE( akey->current->tag ) != CONSTRUCTED ) ||
                ( TAG_NUMBER( akey->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
     else asn = akey->current->data.constructed;

  /* получаем тип механизма выработки ключевой пары */
   ak_asn1_context_first( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
            ( TAG_NUMBER( asn->current->tag ) != TINTEGER )) return ak_error_invalid_asn1_tag;
   ak_tlv_context_get_uint32( asn->current, &choice );

  /* теперь собственно параметры алгоритма */
   ak_asn1_context_next( asn );
   if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
                ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE )) return ak_error_invalid_asn1_tag;
     else asn = asn->current->data.constructed;

   switch( choice ) {
     case password_based_encryption_key :
       return ak_asn1_context_get_derived_keys_with_password( asn, ekey, ikey );
     default:
       return ak_error_invalid_value;
   }

 return ak_error_invalid_value;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция расшифровывает ключевое значение и помещает его в контекст секретного ключа.

    \param akey контекст ASN.1 дерева, содержащий информацию о ключе
    \param skey контекст ключа, значение которого считывается из ASN.1 дерева
    \param ekey контекст ключа шифрования
    \param ikey контекст ключа имитозащиты
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_asn1_context_get_skey( ak_asn1 akey, ak_skey skey, ak_bckey ekey, ak_bckey ikey )
{
  size_t size = 0;
  size_t ivsize  = ekey->bsize >> 1,
         keysize = 2*skey->key_size;
  ak_uint8 out[64];
  ak_asn1 asn = NULL;
  ak_uint8 *ptr = NULL;
  int error = ak_error_ok;
  ak_uint32 oc = 0, u32 = 0;

  /* проверяем наличие памяти  */
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
/*! \param bkey контекст создаваемого ключа алгоритма блочного шифрования
    \param asn контекст ASN.1 дерева, содержащий информацию о создаваемом ключе
    \param oid идентификатор алгоритма блочного шифрования

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_context_create_asn1( ak_bckey bkey, ak_asn1 akey, ak_oid oid )
{
  int error = ak_error_ok;
  struct bckey ekey, ikey; /* ключи шифрования и имитозащиты контента */

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to block cipher key" );
 /* создаем контекст ключа */
  if(( error = ak_bckey_context_create_oid( bkey, oid )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect creation of block cipher key" );

 /* получаем метаданные создаваемого ключа */
  if(( error = ak_asn1_context_get_skey_metadata( akey, &bkey->key )) != ak_error_ok ) {
   ak_bckey_context_destroy( bkey );
   return ak_error_message( error, __func__, "incorrect assigning metadata for block cipher key");
  }

 /* вырабатываем производные ключи шифрования и имитозащиты */
  if(( error = ak_asn1_context_get_derived_keys( akey, &ekey, &ikey )) != ak_error_ok ) {
   ak_bckey_context_destroy( bkey );
   return ak_error_message( error, __func__, "incorrect construction of derived secret keys");
  }

 /* расшифровываем данные и проверяем имитовставку */
  if(( error = ak_asn1_context_get_skey( akey, &bkey->key, &ekey, &ikey )) != ak_error_ok ) {
    ak_bckey_context_destroy( bkey );
    ak_error_message( error, __func__, "incorrect assigneng a secret key value" );
  }
   else {
       /* выполняем развертку раундовых ключей */
        if( bkey->schedule_keys != NULL ) {
          if(( error = bkey->schedule_keys( &bkey->key )) != ak_error_ok )
            ak_error_message( error, __func__, "incorrect execution of key scheduling procedure" );
        }
   }

 /* уничтожаем производные ключи */
  ak_bckey_context_destroy( &ekey );
  ak_bckey_context_destroy( &ikey );
 return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_keys.c  */
/* ----------------------------------------------------------------------------------------------- */
