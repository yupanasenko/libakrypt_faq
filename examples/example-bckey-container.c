 #include <stdio.h>
 #include <ak_bckey.h>
 #include <ak_tools.h>
 #include <ak_compress.h>
 #include <ak_context_manager.h>

 #include <KeyValue.h>
 #include <KeyContainer.h>

/* ----------------------------------------------------------------------------------------------- */
 void print_bckey( ak_bckey bkey )
{
  char *str = NULL;

  printf("key ---> %s (%s)\n",
                 ak_buffer_get_str( &bkey->key.oid->name ), ak_buffer_get_str(& bkey->key.oid->id ));
  printf("  number: %s\n", str = ak_buffer_to_hexstr( &bkey->key.number )); free( str );
  printf("   flags: %016llx\n", bkey->key.flags );
  printf(" counter: %016llx (%llu)\n", bkey->key.resource.counter, bkey->key.resource.counter );
  printf("     key: %s\n", str = ak_ptr_to_hexstr( bkey->key.key.data, 32, ak_false )); free( str );
  printf("    mask: %s\n", str = ak_ptr_to_hexstr( bkey->key.mask.data, 32, ak_false )); free( str );
 /* real key? */
  printf("real key: ");
  if( bkey->key.set_mask == ak_skey_set_mask_additive ) { /* снимаем аддитивную маску и получаем ключ */
    int idx = 0;
    for( idx = 0; idx < 8; idx++ ) printf("%08x",
     (ak_uint32)(((ak_uint32 *)bkey->key.key.data)[idx] - ((ak_uint32 *)bkey->key.mask.data)[idx]) );
  }
  printf("\n   icode: %s", str = ak_ptr_to_hexstr( bkey->key.icode.data, 8, ak_false )); free( str );
  if( bkey->key.check_icode( &bkey->key )) printf(" is Ok\n");
   else printf(" is Wrong\n");

  printf(" ivector: %s\n", str = ak_buffer_to_hexstr( &bkey->ivector )); free( str );
}


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование OID библиотеки в ASN1 представление. */
 int ak_oid_to_asn1_object_identifier( ak_oid , OBJECT_IDENTIFIER_t * );

/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание. Структура OBJECT_IDENTIFIER_t должна быть предварительно создана.

    @param oid Идентификтор объекта, содержащий символьное (строковое) представление OID
    @param oidt Контекст типа OBJECT_IDENTIFIER_t, используемый в ASN1 нотациях
    @return В случае успеха возвращается \ref ak_error_ok. В противном случае,
    возвращается код ошибки, в частности, если символьное представление OID содержит
    более 24 разделенных точками чисел, то возбуждается ошибка.                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oid_to_asn1_object_identifier( ak_oid oid, OBJECT_IDENTIFIER_t *oidt )
{
  int cnt = 0;
  long arcs[24]; /* массив для хранения временных значений */

  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                      "using null pointer to OID");
  if( oidt == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to OBJECT_IDENTIFIER_t");
  if(( cnt = OBJECT_IDENTIFIER_parse_arcs( oid->id.data, -1, arcs, 24, NULL )) < 0 )
    return ak_error_message( ak_error_oid_id, __func__,
                             "incorrect transformation of OID's constant value to array of longs");
  if(( cnt = OBJECT_IDENTIFIER_set_arcs( oidt, arcs, sizeof( arcs[0] ), cnt )) < 0 )
    return ak_error_message( ak_error_oid_id, __func__,
                                "incorrect transformation array of longs to OBJECT_IDENTIFIER_t" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выделяет память для указателя OCTET_STRING_t и копирует в нее данные, хранящиеся в ptr */
 int ak_ptr_to_asn1_octet_string( const ak_pointer , const size_t , OCTET_STRING_t * );

/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr Данные, помещаемые в ASN1 структуру
    @param size Раззмер данных,помещаемых в ASN1 структуру (в байтах)
    @param ost Указатель на переменную типа OCTET_STRING_t, которая инициализируется данными,
    на которые указывает ptr.

    @return В случае успеха функция возвращает \ref ak_error_ok. В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_ptr_to_asn1_octet_string( const ak_pointer ptr, const size_t size, OCTET_STRING_t *ost )
{
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to source data");
  if( size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                                "using zero length source data");
  if( ost == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer OCTET_STRING_t");
  if(( ost->buf = malloc( size )) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation");
  memcpy( ost->buf, ptr, size );
  ost->size = size;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция для итерационного вычисления хеш-кода от der-представления ключа */
 static int ak_skey_der_encode_update( const void *buffer, size_t size, void *app_key )
{
  return ak_compress_update(( ak_compress )app_key,
                                       ( const ak_pointer )buffer, size ) != ak_error_ok ? -1 : 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Преобразование ключа блочного алгоритма шифрования в ASN1 структуру. */
/*! Перед преобразованием контекст ключа должен быть инициализирован и содержать
    в себе ключевое значение. В результате выполнения функции создается структура `SecretKeyData`,
    за удаление которой отвечает пользователь, вызвавший данную функцию.

    @param bkey Контекст ключа блочного алгоритма шифрования, который будет преобразован
           в ASN1 структуру.
    @param pass Пароль, представленный в виде строки символов в формате utf8.
    @param pass_size Длина пароля в байтах.
    @param description Человекочитаемое описание ключа (если описание не определено,
           должен передаваться NULL).

    @return В случае успеха возвращается указатель на созданную структуру. В случае ошибки
    возвращается NULL. Код ошибки модет быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 SecretKeyData_t *ak_skey_to_asn1_secret_key( ak_skey skey,
                            const ak_pointer pass, const size_t pass_size, const char *description )
{
 #define temporary_size (1024)

 ak_uint8 salt[64]; /* массив для хранения случайных инициализационных данных */
 asn_enc_rval_t ec;
 KeyValue_t keyValue;
 struct hmac hmacKey;
 int error = ak_error_ok;
 struct bckey encryptionKey; /* ключ шифрования */
 ak_uint8 temporary[temporary_size]; /* массив для хранения EncodedKeyValue */
 SecretKeyData_t *secretKeyData = NULL;

 /* проверяем входные данные */
  if( skey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                        "using null pointer to block cipher key context" );
    return NULL;
  }
  if( pass == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to password" );
    return NULL;
  }
  if( pass_size == 0 ) {
    ak_error_message( ak_error_zero_length, __func__ , "using password with zero length" );
    return NULL;
  }
  if( skey->key.size + skey->mask.size + 6 > temporary_size ) {
    ak_error_message( ak_error_wrong_length, __func__ ,
                  "size of internal temporary buffer is small for this block cipher key" );
    return NULL;
  }

 /* перемаскируем текущее значение сохраняемого ключа */
  if( skey->remask == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                   "using not masked bclock cipher key (internal error)" );
    return NULL;
  } else skey->remask( skey );

 /* вырабатываем случайное значение,
  * которое будет использовано для определения всех инициализационных векторов */
  if(( error = skey->generator.random( &skey->generator, salt, 64 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong generation a temporary salt value" );
    return NULL;
  }

 /* создаем ключ шифрования ключа (алгоритм Магма) */
  if(( error = ak_bckey_create_magma( &encryptionKey )) != ak_error_ok ) {
    ak_error_message( error , __func__ ,
                            "wrong initialization of temporary block cipher key context" );
    return NULL;
  }
  if(( error = ak_bckey_context_set_password( &encryptionKey, pass, pass_size,
                                                              salt, 16 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong generation a temporary block cipher value" );
    ak_bckey_destroy( &encryptionKey );
    return NULL;
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
    ak_error_message( ak_error_wrong_asn1_encode, __func__,
                                            "incorect KeyValue's ASN1 structure encoding");
    ak_ptr_wipe( temporary, temporary_size, &encryptionKey.key.generator );
    ak_bckey_destroy( &encryptionKey );
    return NULL;
  }

  /* зашифровываем вектор в режиме гаммирования и уничтожаем ключ защиты */
  if(( error = ak_bckey_context_xcrypt( &encryptionKey,
                          temporary, temporary, ec.encoded, salt+32, 4 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong encryption of temporary buffer" );
    ak_bckey_destroy( &encryptionKey );
    return NULL;
  }
  ak_bckey_destroy( &encryptionKey );

 /* последний этап - формирование ASN1 структуры */
  if(( secretKeyData = malloc( sizeof( struct SecretKeyData ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__,
                             "incorrect memory allocation for secret key asn1 structure" );
    return NULL;
  }
  memset( secretKeyData, 0, sizeof( struct SecretKeyData ));

 /* добавляем зашифрованный ключ */
  if(( error = ak_ptr_to_asn1_octet_string( temporary,
                                ec.encoded, &secretKeyData->data.value )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong assignment a secret key to asn1 structure" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

 /* устанавливаем engine */
  if(( error = ak_oid_to_asn1_object_identifier( skey->oid,
                   (OBJECT_IDENTIFIER_t *) &secretKeyData->data.engine )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                               "incorrect secret key engine assigning to asn1 structure" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

 /* устанавливаем номер ключа */
  if(( error = ak_ptr_to_asn1_octet_string( skey->number.data,
                    skey->number.size, &secretKeyData->data.number )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                             "incorrect secret key's number assigning to asn1 structure" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

 /* устанавливаем ресурс ключа */
  secretKeyData->data.resource = malloc( sizeof( struct KeyResource ));
  memset( secretKeyData->data.resource, 0 , sizeof( struct KeyResource ));
  /* TODO: здесь надо проверить, что ресурс содержит либо численное значение,
   * либо не временной интервал - в зависимости от типа ключа */
  secretKeyData->data.resource->counter = malloc( sizeof( unsigned long ));
  *(secretKeyData->data.resource->counter) = skey->resource.counter;

 /* устанавливаем описание ключа */
  if( description != NULL ) {
    secretKeyData->data.description = malloc( sizeof( struct OCTET_STRING ));
    memset( secretKeyData->data.description, 0, sizeof( struct OCTET_STRING ));
    /* внимание, оно может быть непредусмотрительно длинным! */
    if(( error = ak_ptr_to_asn1_octet_string( (void *)description,
                strlen( description ), secretKeyData->data.description )) != ak_error_ok ) {
      ak_error_message( error, __func__,
                        "incorrect secret key's description assigning to asn1 structure" );
      SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
      return NULL;
    }
  }

 /* устанавливаем параметры алгоритма защиты */
  /* 1. число итераций алгоритма PBKDF2 */
  secretKeyData->data.parameters.iterationCount =
                                       ak_libakrypt_get_option( "pbkdf2_iteration_count" );

  /* 2. инициализационный вектор для PBKDF2 (ключ шифрования) */
  if(( error = ak_ptr_to_asn1_octet_string( salt, 16,
                        &secretKeyData->data.parameters.encryptionSalt )) != ak_error_ok ) {
    ak_error_message( error, __func__,
      "incorrect initial vector for PBKDF2 assigning to asn1 structure (encryption key)" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

  /* 3. инициализационный вектор для PBKDF2 (ключ имитозащиты) */
  if(( error = ak_ptr_to_asn1_octet_string( salt+16, 16,
                         &secretKeyData->data.parameters.integritySalt )) != ak_error_ok ) {
    ak_error_message( error, __func__,
       "incorrect initial vector for PBKDF2 assigning to asn1 structure (integrity key)" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

  /* 4. блочный шифр */
  if(( error = ak_oid_to_asn1_object_identifier(
                  ak_handle_get_context( ak_oid_find_by_name( "magma" ), oid_engine ),
        (OBJECT_IDENTIFIER_t *) &secretKeyData->data.parameters.cipher )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                             "incorrect block cipher engine assigning to asn1 structure" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

  /* 5. режим работы блочного шифра */
  if(( error = ak_oid_to_asn1_object_identifier(
                  ak_handle_get_context( ak_oid_find_by_name( "counter" ), oid_engine ),
          (OBJECT_IDENTIFIER_t *) &secretKeyData->data.parameters.encryptionMode )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                                  "incorrect encryption mode assigning to asn1 structure" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

  /* 6. инициализационный вектор для режима шифрования */
  if(( error = ak_ptr_to_asn1_octet_string( salt+32, 4,
                          &secretKeyData->data.parameters.encryptionIV )) != ak_error_ok ) {
    ak_error_message( error, __func__,
          "incorrect assignment of initial vector for encryption mode to asn1 structure" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

  /* 7. алгоритм вычисления имитовставки */
  if(( error = ak_oid_to_asn1_object_identifier(
            ak_handle_get_context( ak_oid_find_by_name( "hmac-streebog256" ), oid_engine ),
              (OBJECT_IDENTIFIER_t *) &secretKeyData->data.parameters.integrityMode )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                                  "incorrect integrity mode assigning to asn1 structure" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

  /* 8. инициализационный вектор для режима имитозащиты */

 /* вычисляем имитовставку */
  /* 1. формируем ключ имитозащиты */
  if(( error = ak_hmac_create_streebog256( &hmacKey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of integrity key" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

  if(( error = ak_hmac_context_set_key_password( &hmacKey,
                                          pass, pass_size, salt+16, 16 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong generation of integrity key value" );
    ak_hmac_destroy( &hmacKey );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

//  /* 2. вычисляем вектор для контроля целостности */
//  memset( temporary, 0, temporary_size );
//  ec = der_encode_to_buffer(  &asn_DEF_SecretKey, &secretKeyData->data,
//                                                               temporary, temporary_size );
//  if( ec.encoded < 0 ) {
//    ak_error_message( ak_error_wrong_asn1_encode, __func__,
//                                       "incorect SecretKeyData's ASN1 structure encoding");
//    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
//    return NULL;
//  }

//  /* 3. вычисляем имитовставку */

//  char *str = NULL;
//  printf("t %s\n", str = ak_ptr_to_hexstr( temporary, ec.encoded, ak_false )); free( str );

//  ak_hmac_context_ptr( &hmacKey, temporary, ec.encoded, temporary );
//  error = ak_error_get_value( );
// // ak_hmac_destroy( &hmacKey );

//  if( error != ak_error_ok ) {
//    ak_error_message( error, __func__, "wrong generation of integrity code" );
//    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
//    return NULL;
//   }

//  printf("t %s\n", str = ak_ptr_to_hexstr( temporary, 32, ak_false )); free( str );

//  ak_uint8 result[32];
//  memset( result, 0, 32 );

  struct compress ctx;
  ak_compress_create_hmac( &ctx, &hmacKey );
  ak_compress_clean( &ctx );
  ec = der_encode( &asn_DEF_SecretKey, &secretKeyData->data, ak_skey_der_encode_update, &ctx );
  ak_compress_finalize( &ctx, NULL, 0, temporary );
  ak_compress_destroy( &ctx );

//  printf("r %s\n", str = ak_ptr_to_hexstr( result, 32, ak_false )); free( str );


  /* 4. присваиваем значение */
  if(( error = ak_ptr_to_asn1_octet_string( temporary, 32,
                                         &secretKeyData->integrityCode )) != ak_error_ok ) {
    ak_error_message( error, __func__,
                              "incorrect assignment of integrity code to asn1 structure" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    return NULL;
  }

 /* на-последок, выполняем проверку созданной структуры */
  if( asn_check_constraints( &asn_DEF_SecretKeyData, secretKeyData, NULL, NULL ) < 0 ) {
    ak_error_message( ak_error_wrong_asn1_encode, __func__,
                                              "unsuccessful checking the asn1 structure" );
    SEQUENCE_free( &asn_DEF_SecretKeyData, secretKeyData, 0 );
    /* так тоже можно освобождать память - более универсальный способ из документации
      asn_DEF_SecretKeyData.free_struct( &asn_DEF_SecretKeyData, secretKeyData, 0); */
    return NULL;

  }

 return secretKeyData;
}

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
 ak_bckey bkey = NULL; /* ключ, который будет сохраняться в контейнере */
 char password[64]; /* пароль */
 ak_uint8 buffer[1024];

 /* инициализируем библиотеку */
  ak_libakrypt_create( ak_function_log_stderr );
 /* инициализируем ключ */
  printf("key creation: %d\n",
   ak_bckey_create_magma( bkey = malloc( sizeof( struct bckey ))));
 /* присваиваем ключу константное значение */
  printf("key asigning value: %d\n",
   ak_bckey_context_set_password( bkey, "password1234", 12, "salt", 4 ));
   bkey->key.resource.counter -= 97; /* немного подправим ресурс ключа */

 /* выводим текущее значение ключа */
  printf("key before transformation:\n");
  print_bckey( bkey );


 /* вводим пароля для защиты созданного ключа */
  printf("password: "); fflush( stdout );
  if( ak_password_read( password, 64 ) != ak_error_ok ) goto exit;
  printf("(pass %s, len: %ld)\n\n", password, strlen( password ));

  SecretKeyData_t *secretKeyData =
    ak_skey_to_asn1_secret_key( &bkey->key, password, strlen( password ), "This is my first key" );

 //  asn_fprint( stdout, &asn_DEF_SecretKeyData, secretKeyData );

  KeyContainer_t *keyContainer = malloc ( sizeof( struct KeyContainer ));
  memset( keyContainer, 0, sizeof( struct KeyContainer ));

  /* устанавливаем версию */
  keyContainer->version = malloc( sizeof( long ));
  *(keyContainer->version) = 1;

  asn_set_add( &keyContainer->keys.list, secretKeyData );

  secretKeyData =
    ak_skey_to_asn1_secret_key( &bkey->key, password, strlen( password ), "This is my second key jhdgl\
ehg lkhgq sv qwlhgflqwkhgl kwhgf lkhwgef    l   whegf     l    whgf lk wdlfjkwerf wf e werg ewrgwerge\
qwi8763284716234786129738461928364519286354129364512795419275419723459127451927451927354912745912745921754291374\
qwyertquewtrquiwtriquwtrqiwugrkjdhbkjqhwqwefqjwvfqjwvflqjwvfljqwhvflqjwhfvqljwhfvlqjwfvlqjwfvqlwjhfvlqwjfvlqjwhfv\
qkhfdkqwfdkqwejqkwhefqwefqwefqwef.mqwef.,mqwf.,mqwef.,mqwf.,mwqf.,wmf.,wmf.,wfm.,wqefm.q,wefm.q,wefm.q,wefm.qw,efm.q,\
qwhehfqlwhfqwfmnqwmfnqw fqw feqwef,.n   wqefljkqwef,mbn,qwmefnq,m.wfn.qwnf.qwmfn.qwmfn.qmwnf.qmwfn.qwmfn.qwmfn.qwmfn\
q,fnq,wfmbq,wfbq,wfmbq,wfb,qwfb,qwnfbq,wnfbqw,nfbwq,nfb,qwnefbqw,nefb,qwnefb,qnwfb,qwnfb,wqnfb,nwfb,qwnbf,nwqfb,qwnfb" );

  asn_set_add( &keyContainer->keys.list, secretKeyData );
  asn_fprint( stdout, &asn_DEF_KeyContainer, keyContainer );

  asn_enc_rval_t ec;
  FILE *fp = fopen( "twokeycontainer.key", "wb" );
  ec = der_encode_to_buffer(  &asn_DEF_KeyContainer, keyContainer, buffer, 1024);
  fwrite( buffer, 1, ec.encoded, fp );
  fclose(fp);

  SEQUENCE_free( &asn_DEF_KeyContainer, keyContainer, 0 );
  memset( buffer, 0, 1024 );


/* теперь создаем файл с защищенным ключом */
  fp = fopen( "twokeycontainer.key", "rb" );
  size_t len = fread( buffer, 1, 1024, fp );
  printf("\n\n loaded len: %ld\n", len );
  fclose(fp);

  keyContainer = malloc ( sizeof( struct KeyContainer ));
  memset( keyContainer, 0, sizeof( struct KeyContainer ));

  asn_dec_rval_t ret = ber_decode( 0, &asn_DEF_KeyContainer, (void **)&keyContainer, buffer, len );
  if( ret.consumed != len || ret.code != RC_OK ) printf("decoding error\n");

  asn_fprint( stdout, &asn_DEF_KeyContainer, keyContainer );
  printf("count of keys: %d\n", keyContainer->keys.list.count );

  SEQUENCE_free( &asn_DEF_KeyContainer, keyContainer, 0 );
  memset( buffer, 0, 1024 );
  //free( keyContainer );


/* выводим ключ сохраненный */
//  printf("\nkey after transformation:\n");
//  print_bckey( bkey );


/* освобождаем пямять и завершаем работу */
 exit:
 bkey = ak_bckey_delete( bkey );
 printf("key destroying: %d\n", ak_error_get_value( ));

 return ak_libakrypt_destroy();
}
