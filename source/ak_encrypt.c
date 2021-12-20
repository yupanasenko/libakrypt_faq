/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2021 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_encrypt.c                                                                              */
/*  - содержит реализацию схемы асимметричного шифрования                                          */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
/*                                 процедуры зашифрования информации                              */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция проверяет, поддерживается ли библиотекой указанная схема асимметричного шифрования */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_encrypt_file_is_scheme_valid( scheme_t scheme )
{
 /* в текущей версии библиотеки мы поддерживаем только базовую гибридную схему */
  if( scheme == ecies_scheme ) return ak_true;

 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_encrypt_file_create_header( const char *filename,
       ak_encryption_set set, ak_pointer scheme_key, ak_uint8 *buffer, size_t *len, size_t *head );

 static int ak_encrypt_assign_container_key( ak_bckey kcont, ak_uint8 *salt, size_t salt_size,
                                  ak_uint8 *iv, size_t iv_size, ak_uint8 *vect, size_t vect_size,
                                                    const char *password, const size_t pass_size );

 static int ak_encrypt_assign_encryption_keys( ak_pointer kenc, ak_pointer kauth,
                               ak_encryption_set set, ak_pointer scheme_key, ak_random generator,
                                  ak_uint8 *salt, size_t salt_size, ak_uint8 *iv, size_t iv_size,
                                 ak_uint8 *vect, size_t vect_size, ak_uint8 *buffer, size_t head );

/* ----------------------------------------------------------------------------------------------- */
/*! Для зашифрования данных используется открытый ключ получателя. Для доступа к контейнеру с данными
    используется пароль.

    @return В случае успеха функция возвращает ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_encrypt_file( const char *filename, ak_encryption_set set,
                 ak_pointer scheme_key, char *outfile, const size_t outsize, ak_random generator,
                                                    const char *password, const size_t pass_size )
{
  struct bckey kcont;
  struct file ifp, ofp;
  ak_uint8 buffer[1024];
  int error = ak_error_ok;
  ak_uint8 salt[32], iv[16], vect[32];
  size_t len = sizeof( buffer ), head = 0;
  ak_int64 total = 0, maxlen = 0, value = 0, sum = 0;
  ak_pointer encryptionKey = NULL, authenticationKey = NULL;

  /* выполняем многочисленные начальные проверки */
   if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "using null pointer to the name of the input file" );
   if( set == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                          "using null pointer to encryption set" );
   if( !ak_encrypt_file_is_scheme_valid( set->scheme ))
     return ak_error_message( ak_error_encrypt_scheme, __func__,
                                                           "using unsupported encryption scheme" );
   if( set->mode->mode != aead ) return ak_error_message( ak_error_oid_mode, __func__,
                                                       "using non aead mode for data encryption" );
   if( scheme_key == NULL ) return ak_error_message( ak_error_oid_mode, __func__,
                                                              "using null pointer to encrypted " );
   if( outfile == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                             "using null pointer to the name of the output file" );
   if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to random number generator" );
   if( password == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to password" );
   if( pass_size == 0 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                               "using password with zero length" );
  /* инициализируем ключ доступа к контейнеру */
   if(( error = ak_bckey_create_kuznechik( &kcont )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of container's secret key" );
   ak_random_ptr( generator, salt, 14 );
   if(( error = ak_encrypt_assign_container_key( &kcont, /* устанавливаем первичное значение ключа */
                              salt, 14, iv, 8, vect, 16, password, pass_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assign value of container's secret key" );
     goto lab_exit;
   }

  /* формируем файловые дескрипторы */
   if( outsize > 0 ) {
     if( outsize < 12 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                      "buffer for output file name is too small" );
     ak_random_ptr( &kcont.key.generator, outfile, 12 );
     strncpy( outfile, ak_ptr_to_hexstr( outfile, 12, ak_false ), outsize );
   }
   if(( error = ak_file_open_to_read( &ifp, filename )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__, "wrong open an existing file (%s)", filename );
     goto lab_exit;
   }
   if(( error = ak_file_create_to_write( &ofp, outfile )) != ak_error_ok ) {
     ak_error_message_fmt( error, __func__, "wrong creation of a new file (%s)", outfile );
     ak_file_close( &ifp );
     goto lab_exit;
   }

  /* формируем заголовок контейнера, зашифровываем и сохраняем */
   if(( error = ak_encrypt_file_create_header( filename,
                                        set, scheme_key, buffer, &len, &head )) != ak_error_ok ) {
     ak_error_message( error, __func__, "header of encrypted file cannot be created" );
     goto lab_exit2;
   }
   if(( error = ak_bckey_ctr( &kcont, buffer, buffer, len, iv, 8 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect encryption of header" );
     goto lab_exit2;
   }
   memcpy( buffer, salt, 14 );
   ak_file_write( &ofp, buffer, len );

  /* создаем ключи шифрования и имитозащиты данных */
   if(( encryptionKey = ak_oid_new_object( set->mode )) == NULL ) {
     ak_error_message( error, __func__, "incorrect memory allocation for encryption key" );
     goto lab_exit2;
   }
   if(( authenticationKey = ak_oid_new_second_object( set->mode )) == NULL ) {
     ak_oid_delete_object( set->mode, encryptionKey );
     ak_oid_delete_second_object( set->mode, authenticationKey );
     ak_error_message( error, __func__, "incorrect memory allocation for authentictionkey" );
     goto lab_exit2;
   }

  /* выполняем фрагментацию входного файла на фрагменты длины
     от 4096 байт до maxlen, где maxlen определяется
     ресурсом секретного ключа */
   total = ifp.size;
   if(( value = set->fraction.value ) == 0 ) value = 10; /* количество фрагментов по-умолчанию */
   if( strstr( set->mode->name[0], "kuznechik" ) != NULL )
     maxlen = 16*ak_libakrypt_get_option_by_name( "kuznechik_cipher_resource" );
    else maxlen = 8*ak_libakrypt_get_option_by_name( "magma_cipher_resource" );

   if( set->fraction.mechanism == count_fraction ) {
     maxlen = ak_max( 4096, ak_min( total/value, maxlen ));
   }
   if( set->fraction.mechanism == size_fraction ) {
     maxlen = ak_max( 4096, ak_min( value, maxlen ));
   }

  /* основной цикл разбиения входных данных */
   while( total > 0 ) {
    ak_int64 current = maxlen;
    if( set->fraction.mechanism == random_size_fraction ) {
      ak_random_ptr( generator, &current, 4 ); /* нам хватит 4х октетов */
      current %= ifp.size;
      if( current > maxlen ) current = maxlen; /* не очень большая */
      current = ak_max( 4096, current );     /* не очень маленькая */
    }
    current = ak_min( current, total );
    if(((total - current) > 0 ) && ((total - current) < 4096 )) current = total;
    /* теперь мы можем зашифровать фрагмент входных данных, длина которого определена current */
    /* начинаем с того, что вырабатываем ключи и заголовок фрагмента */
     if(( error = ak_encrypt_assign_encryption_keys(
            encryptionKey,
            authenticationKey,
            set,
            scheme_key,
            generator,
            vect,
            16,
            iv,
            16,
            salt,
            32,
            buffer,
            head )) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect creation of input data encryption keys" );
        break;
     }
    /* добавляем в буффер значение current, зашифровываем его и сохраняем в файл (head = len + 8) */
     buffer[head -8] = ( current >> 56 )&0xFF;
     buffer[head -7] = ( current >> 48 )&0xFF;
     buffer[head -6] = ( current >> 40 )&0xFF;
     buffer[head -5] = ( current >> 32 )&0xFF;
     buffer[head -4] = ( current >> 24 )&0xFF;
     buffer[head -3] = ( current >> 16 )&0xFF;
     buffer[head -2] = ( current >>  8 )&0xFF;
     buffer[head -1] = current&0xFF;
     ak_bckey_ctr( &kcont, buffer, buffer, head, NULL, 0 );
     ak_file_write( &ofp, buffer, len );
    /* только теперь шифруем входящие даные */

    /* вырабатываем новое значение ключа для доступа к контейнеру */

    /* зашифровываем и сохраняем имитоставку */

    /* уточняем оставшуюся длину входных данных */
    total -= current;
    sum += current;
   }
   if( sum != ifp.size ) ak_error_message( error = ak_error_wrong_length, __func__,
                         "the length of encrypted data is not equal to the length of plain data" );

  /* очищием файловые дескрипторы, ключевые контексты, промежуточные данные и выходим */
   ak_oid_delete_object( set->mode, encryptionKey );
   ak_oid_delete_second_object( set->mode, authenticationKey );

  lab_exit2:
   ak_file_close( &ofp );
   ak_file_close( &ifp );

  lab_exit:
   ak_ptr_wipe( salt, sizeof( salt ), &kcont.key.generator );
   ak_ptr_wipe( iv, sizeof( iv ), &kcont.key.generator );
   ak_ptr_wipe( vect, sizeof( vect ), &kcont.key.generator );
   ak_ptr_wipe( buffer, sizeof( buffer ), &kcont.key.generator );
   ak_bckey_destroy( &kcont) ;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция зашифровывает заданный файл с использованием асимметричной схемы шифрования.
    Доступ к контейнеру, хранящему зашифрованные данные, закрывается с использованием заданого
    секретного ключа.

    @return В случае успеха функция возвращает ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_encrypt_file_with_key( const char *filename, ak_encryption_set set,
        ak_pointer scheme, char *outfile, const size_t outsize, ak_random generator, ak_skey key )
{
  int error = ak_error_ok;

  if( key == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "using null pointer to container's encryption key" );
  if(( key->flags&key_flag_set_key ) == 0 ) return ak_error_message( ak_error_key_value, __func__,
                                                   "using unassigned container's encryption key" );
 /* отправляем массив ключевой информации в качестве пароля для шифрования файла */
  if(( error = key->unmask( key )) != ak_error_ok ) return ak_error_message( error, __func__,
                                                                   "error key unmasking process" );
  error = ak_encrypt_file( filename, set, scheme, outfile, outsize,
                                               generator, ( const char *)key->key, key->key_size );
  if( key->set_mask( key ) != ak_error_ok ) ak_error_message( error, __func__,
                                                                     "error key masking process" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает asn1 sequence, помещаемую в заголовок зашифрованного файла
    и содержащую информацию, необходимую для расшифрования файла.                                   */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_encrypt_create_public_key_sequence( scheme_t scheme, ak_pointer scheme_key )
{
  ak_tlv sq2 = NULL;

  switch( scheme ) {
    case ecies_scheme:
      if(( sq2 = ak_tlv_new_sequence( )) == NULL ) {
        ak_error_message( ak_error_out_of_memory,  __func__, "wrong creation of asn1 sequence" );
      }
       else {
         ak_ecies_scheme ecs = scheme_key;
         ak_asn1_add_octet_string( sq2->data.constructed,
                                 ecs->recipient.vkey.number, ecs->recipient.vkey.number_length );
         ak_asn1_add_octet_string( sq2->data.constructed,
                           ecs->recipient.opts.serialnum, ecs->recipient.opts.serialnum_length );
       }
      break;

    default:
      ak_error_message( ak_error_encrypt_scheme, __func__, "using unsupported encryption scheme" );
  }

 return sq2;
}

/* ----------------------------------------------------------------------------------------------- */
 static size_t ak_encrypt_public_key_size( scheme_t scheme, ak_pointer scheme_key )
{
  switch( scheme ) {
    case ecies_scheme:
      return 2*sizeof( ak_uint64 )*((( ak_ecies_scheme)scheme_key)->recipient.vkey.wc->size );

    default:
      ak_error_message( ak_error_encrypt_scheme, __func__, "using unsupported encryption scheme" );
  }

 return 0;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_encrypt_file_create_header( const char *filename,
       ak_encryption_set set, ak_pointer scheme_key, ak_uint8 *buffer, size_t *len, size_t *head )
{
   int error = ak_error_ok;
   ak_asn1 header = ak_asn1_new();
   ak_tlv sequence = NULL, sq2 = NULL;

  /* формируем заголовок контейнера */
   if( header == NULL ) return ak_error_message( ak_error_out_of_memory,
                                                   __func__, "incorrect creation os asn1 header" );
   ak_asn1_add_tlv( header, sequence = ak_tlv_new_sequence( ));
   if( sequence == NULL ) {
     ak_asn1_delete( header );
     return ak_error_message( ak_error_out_of_memory,  __func__,
                                                     "incorrect creation of first asn1 sequence" );
   }
  /* a. схема шифрования */
   ak_asn1_add_uint32( sequence->data.constructed, set->scheme );
  /* b. параметры открытого ключа используемой схемы */
   if(( sq2 = ak_encrypt_create_public_key_sequence( set->scheme, scheme_key )) == NULL ) {
     ak_asn1_delete( header );
     return ak_error_message( ak_error_out_of_memory,  __func__,
                                                    "incorrect creation of second asn1 sequence" );
   }
    else ak_asn1_add_tlv( sequence->data.constructed, sq2 );
  /* c. режим шифрования данных */
   ak_asn1_add_algorithm_identifier( sequence->data.constructed, set->mode , NULL );
  /* d. имя файла после расшифрования */
   ak_asn1_add_utf8_string( sequence->data.constructed, filename );
  /* e. размер служебного заголовка в байтах */
   ak_asn1_add_uint32( sequence->data.constructed,
                               *head = ak_encrypt_public_key_size( set->scheme, scheme_key ) + 8 );

  /* кодируем содуржимое заголовка */
   memset( buffer, 0, *len );
   if(( error = ak_asn1_encode( header, buffer +16, len )) == ak_error_ok ) {
     buffer[15] = *len&0xFF;
     buffer[14] = (*len - buffer[15])&0xFF;
     *len += 16; /* добавляем к длине 16 октетов  */
   }
   ak_asn1_delete( header );
   if( error != ak_error_ok ) return ak_error_message( error, __func__,
                                                      "encorrect encrypted file header encoding" );
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_encrypt_assign_container_key( ak_bckey kcont, ak_uint8 *salt, size_t salt_size,
                                  ak_uint8 *iv, size_t iv_size, ak_uint8 *vect, size_t vect_size,
                                                    const char *password, const size_t pass_size )
{
   ak_uint8 value[32];
   struct kdf_state state;
   int error = ak_error_ok;

   if(( error = ak_kdf_state_create( &state, (ak_uint8 *)password, pass_size,
                    hmac_hmac512_kdf, NULL, 0, salt, salt_size, NULL, 0, 256 )) != ak_error_ok ) {
    return ak_error_message( error, __func__, "wrong generation of initial secret key" );
   }
   if(( error = ak_kdf_state_next( &state, iv, iv_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect generation of initial vector" );
     goto ex;
   }
   if(( error = ak_kdf_state_next( &state, vect, vect_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect generation of additional vector" );
     goto ex;
   }
   if(( error = ak_kdf_state_next( &state, value, 32 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect generation of secret vector" );
     goto ex;
   }
   if(( error = ak_kdf_state_destroy( &state )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect destroying of internal state" );
     goto ex;
   }

  /* delme )) */
   printf("\nKEY: %s\n", ak_ptr_to_hexstr( value, 32, ak_false ));

   if(( error = ak_bckey_set_key( kcont, value, 32 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assigning a secret value to container's key" );
   }
   ex:
   ak_ptr_wipe( value, 32, &kcont->key.generator );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_encrypt_assign_encryption_keys( ak_pointer kenc, ak_pointer kauth,
                               ak_encryption_set set, ak_pointer scheme_key, ak_random generator,
                                  ak_uint8 *salt, size_t salt_size, ak_uint8 *iv, size_t iv_size,
                                 ak_uint8 *vect, size_t vect_size, ak_uint8 *buffer, size_t head )
{
  ak_mpznmax xi;
  size_t cnt = 0;
  struct wpoint U, W;
  ak_wcurve wc = NULL;
  struct kdf_state state;
  int error = ak_error_ok;
  ak_ecies_scheme ecs = (ak_ecies_scheme) scheme_key;

  switch( set->scheme ) {
    case ecies_scheme:
      /* упрощаем доступ */
       wc = ecs->recipient.vkey.wc;
       cnt = sizeof( ak_uint64 )*wc->size;
       if( head != ( 2*wc->size*sizeof( ak_uint64 ) +8 )) {
         ak_error_message( error = ak_error_wrong_length, __func__,
                                                       "using unexpected length of chunk header" );
         break;
       }
      /* вырабатываем случайное число */
       ak_mpzn_set_random_modulo( xi, wc->q, wc->size, generator );
      /* вырабатываем точку W, которая будет использована для генерации ключевой информации */
       ak_wpoint_set_as_unit( &W, wc );
       ak_wpoint_pow( &W, &ecs->recipient.vkey.qpoint, xi, wc->size, wc );
       ak_wpoint_reduce( &W, wc );
       ak_mpzn_to_little_endian( W.x, wc->size, buffer, cnt, ak_true );
       ak_mpzn_to_little_endian( W.y, wc->size, buffer + cnt, cnt, ak_true );

     /* delme :)) */
       printf(" buffer[\n"
              "    W.x: %s\n", ak_ptr_to_hexstr( buffer, cnt, ak_false ));
       printf("    W.y: %s\n", ak_ptr_to_hexstr( buffer + cnt, cnt, ak_false ));
       printf("       ]\n");

      /* вырабатываем необходимую производную информацию */
       if(( error = ak_kdf_state_create( &state, buffer, 2*cnt,
                    hmac_hmac512_kdf, NULL, 0, salt, salt_size, NULL, 0, 256 )) != ak_error_ok ) {
         ak_error_message( error, __func__, "wrong generation of initial secret key" );
         break;
       }
       if(( error = ak_kdf_state_next( &state, iv, iv_size )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect generation of initial vector" );
       }
        else {
          if(( error = ak_kdf_state_next( &state, vect, vect_size )) != ak_error_ok ) {
            ak_error_message( error, __func__, "incorrect generation of additional vector" );
          }
           else {
              if(( error = ak_kdf_state_next( &state, buffer, 64 )) != ak_error_ok )
                ak_error_message( error, __func__, "incorrect generation of secret vector" );
           }
        }
       ak_kdf_state_destroy( &state );
       if( error != ak_error_ok ) break;
      /* присваиваем ключевые значения */
       if(( error = set->mode->func.first.set_key( kenc, buffer, 32 )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect assigning of secret key" );
         break;
       }
       if(( error = set->mode->func.second.set_key( kauth, buffer+32, 32 )) != ak_error_ok ) {
         ak_error_message( error, __func__, "incorrect assigning of authentication key" );
         break;
       }
      /* вырабатываем точку U, которая будет помещена в buffer */
       ak_wpoint_set_as_unit( &U, wc );
       ak_wpoint_pow( &U, &wc->point, xi, wc->size, wc );
       ak_wpoint_reduce( &U, wc );
       ak_mpzn_to_little_endian( U.x, wc->size, buffer, sizeof( ak_uint64 )*wc->size, ak_true );
       ak_mpzn_to_little_endian( U.y, wc->size, buffer+sizeof( ak_uint64 )*wc->size,
                                                           sizeof( ak_uint64 )*wc->size, ak_true );
      break;

    default:
      ak_error_message( error = ak_error_encrypt_scheme, __func__,
                                                           "using unsupported encryption scheme" );
  }
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 процедуры расшифрования информации                              */
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
 int ak_decrypt_file( const char *filename, const char *password, const size_t pass_size )
{
  ak_asn1 asn;
  struct file ifp;
  size_t len, head;
  ak_uint8 buffer[1024];
  int error = ak_error_ok;
  struct bckey kcont, kenc, kauth;
  ak_uint8 salt[32], iv[16], vect[32];

  /* проверяем корректность аргументов функции */
   if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to name of encrypted file" );
   if( password == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to password" );
   if( pass_size == 0 ) return ak_error_message( ak_error_wrong_length,
                                                     __func__, "using password with zero length" );

 /* 1. Считываем заголовок и проверяем, наше ли это добро */
   if(( error = ak_file_open_to_read( &ifp, filename )) != ak_error_ok ) {
     return ak_error_message_fmt( error, __func__, "wrong open an input file (%s)", filename );
   }
   if( ak_file_read( &ifp, salt, 16 ) != 16 ) {
     ak_error_message( error = ak_error_read_data, __func__,
                                                        "wrong reading the first part of header" );
     goto lab_exit;
   }
   if(( error = ak_bckey_create_kuznechik( &kcont )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect creation of container's secret key" );
   if(( error = ak_encrypt_assign_container_key( &kcont, /* устанавливаем первичное значение ключа */
                              salt, 14, iv, 8, vect, 16, password, pass_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect assign value of container's secret key" );
     goto lab_exit2;
   }
   memcpy( buffer, salt, 16 );
   if(( error = ak_bckey_ctr( &kcont, buffer, buffer, 16, iv, 8 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect decryption of the first part of the header" );
     goto lab_exit2;
   }
   if(( len = buffer[14]*256 + buffer[15] ) > 1024 ) {
     ak_error_message( error = ak_error_wrong_length, __func__, "incorrect length of the header" );
     goto lab_exit2;
   }
   ak_file_read( &ifp, buffer, len );
   if(( error = ak_bckey_ctr( &kcont, buffer, buffer, len, NULL, 0 )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect decryption of the second part of the header" );
     goto lab_exit2;
   }

  /* 2. Проверяем корректность считанных из заголовка параметров */
   if(( error = ak_asn1_decode( asn = ak_asn1_new(), buffer, len, ak_false )) != ak_error_ok ) {
     if( asn ) ak_asn1_delete( asn );
     ak_error_message( error, __func__, "incorrect decoding of the header" );
     goto lab_exit2;
   }

  /* delme :)) */
   ak_asn1_print(asn);
   ak_asn1_delete(asn);

  lab_exit2:
   ak_bckey_destroy( &kcont );

  lab_exit:
   ak_file_close( &ifp );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_decrypt_file_with_key( const char *filename, ak_skey key )
{
  int error = ak_error_ok;

  if( key == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "using null pointer to container's encryption key" );
  if(( key->flags&key_flag_set_key ) == 0 ) return ak_error_message( ak_error_key_value, __func__,
                                                   "using unassigned container's encryption key" );
 /* отправляем массив ключевой информации в качестве пароля для расшифрования файла */
  if(( error = key->unmask( key )) != ak_error_ok ) return ak_error_message( error, __func__,
                                                                   "error key unmasking process" );
  error = ak_decrypt_file( filename, ( const char *)key->key, key->key_size );
  if( key->set_mask( key ) != ak_error_ok ) ak_error_message( error, __func__,
                                                                     "error key masking process" );
 return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_encrypt.c  */
/* ----------------------------------------------------------------------------------------------- */
