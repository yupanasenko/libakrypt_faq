/* ----------------------------------------------------------------------------------------------- */
/* Даннная прогрмамма тестирует все допустимые алгоритмы сохранения и восстановления
   секретного ключа из файла. Тестируются не только корректность сохранения/чтения,
   но и использование различных криптографических преобразований.                                  */
/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <ak_skey.h>
 #include <ak_bckey.h>
 #include <ak_tools.h>
 #include <ak_compress.h>
 #include <ak_context_manager.h>

 #include <KeyValue.h>
 #include <KeyContainer.h>

/* ----------------------------------------------------------------------------------------------- */
/* предварительные описания */
 void print_bckey( char *, ak_bckey );
 void test_saved_key( char * );

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
 int error = ak_error_ok;
 ak_oid cipher, mode, mac;
 ak_bckey storedkey = NULL; /* ключ, который будет сохраняться в контейнере */
 char filename[1024], code[256];
 struct hash hctx;

 /* инициализируем библиотеку */
  ak_libakrypt_create( ak_function_log_stderr );
 /* инициализируем ключ, который будет помещаться в контейнер */
  printf("key creation: %d\n",
   ak_bckey_create_magma( storedkey = malloc( sizeof( struct bckey ))));
 /* присваиваем ключу константное значение */
  printf("key asigning value: %d\n",
   ak_bckey_context_set_password( storedkey, "password1234", 12, "salt", 4 ));
  storedkey->key.resource.counter -= 113; /* немного подправим ресурс ключа */
 /* выводим текущее значение ключа */
  print_bckey( "key before transformation:\n", storedkey );

  /* контекст вычисления хеш-кода файла */
  ak_hash_create_streebog256( &hctx );

  /* перебираем все возможные комбинации криптографических алгоритмов */
  cipher = ak_oid_find_by_engine( block_cipher );
  do{
     if( cipher->mode == algorithm ) {
       mode = ak_oid_find_by_engine( block_cipher );
       do{
          if( mode->mode != algorithm ) {
            mac = ak_oid_find_by_engine( hmac_function );
            do{
              /* устанавливаем найденные oid соответствующих алгоритмов */
               if( ak_libakrypt_set_key_export_algorithm_oids( cipher, mode, mac ) == ak_error_ok ) {
                 /* формируем имя файла */
                  ak_snprintf( filename, 1024, "simple-%s-%s-%s.key",
                                                 cipher->name, mode->name, mac->name );
                 /* сохраняем ключ в заданном файле */
                  printf("file \"%s\" stored ", filename );
                  if(( error = ak_skey_to_der_file( &storedkey->key,
                              filename, "password", 8, "abc" )) != ak_error_ok ) printf("wrong\n");
                   else { /* мы успешно сохранили файл, теперь выводим контрольную сумму */
                          memset( code, 0, 128 );
                          ak_hash_context_file( &hctx, filename, code );
                          ak_ptr_to_hexstr_static( code, hctx.hsize, code+64, 192, ak_false );
                          printf("Ok (%s)\n", code+64 );
                          /* тестируем сохраненный ключ */
                          test_saved_key( filename );
                        }
               } else ak_error_set_value( ak_error_ok );
            } while(( mac = ak_oid_findnext_by_engine( mac, hmac_function )) != NULL );
          }
       } while(( mode = ak_oid_findnext_by_engine( mode, block_cipher )) != NULL );
     }
  } while(( cipher = ak_oid_findnext_by_engine( cipher, block_cipher )) != NULL );
  ak_hash_destroy( &hctx );


  storedkey = ak_bckey_delete( storedkey );
  printf("key destroying: %d\n", ak_error_get_value( ));
 return ak_libakrypt_destroy();
}

 static int ak_skey_der_encode_update( const void *buffer, size_t size, void *app_key )
{
  return ak_compress_update(
               ( ak_compress )app_key, ( const ak_pointer ) buffer, size ) != ak_error_ok ? -1 : 0;
}


/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_create_file( ak_bckey bkey, const char *filename, const ak_pointer pass, const size_t pass_size )
{
  #define temporary_size (1024)

  ak_oid oid = NULL;
  asn_enc_rval_t ec;
  struct hmac hmacKey;
  int error = ak_error_ok;
  struct compress compressCtx; /* структура для итеративного сжатия */
  SecretKeyData_t secretKeyData;
  ak_uint8 temporary[temporary_size]; /* массив для хранения временных данных */


 /* Создаем asn1 структуру, считывая ее из файла */
  memset( &secretKeyData, 0, sizeof( struct SecretKeyData ));
  if(( error = ak_asn1_load_from_der_file( &asn_DEF_SecretKeyData,
                                                      &secretKeyData, filename )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__,
                          "incorrect loading SecretKeyData structure from \"%s\" file", filename );

 /* delme */ asn_fprint( stdout, &asn_DEF_SecretKeyData, &secretKeyData );

 /* Проверяем, подходит ли нам структура по типу криптографического преобразования
    только эта часть специфична для bckey, остальное должно быть универсально */
  if(( oid = ak_oid_find_by_object_identifier( &secretKeyData.data.engine )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                         "using undefined engine oid in SecretKeyData structure" );
    goto exit;
  }
  if(( oid->engine != block_cipher ) || ( oid->mode != algorithm )) {
    ak_error_message( ak_error_oid_engine, __func__,
                                         "using non block cipher oid in SecretKeyData structure" );
    goto exit;
  }

  /* Проверяем, корректность кода целостности */

  /* 1. формируем ключ имитозащиты */
  if(( oid = ak_oid_find_by_object_identifier( &secretKeyData.data.parameters.hmacIntegrity )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                 "using undefined integrity mode oid in SecretKeyData structure" );
    goto exit;
  }
  if(( error = ((ak_function_hmac_create *)oid->func)( &hmacKey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of integrity key" );
    goto exit;
  }

  if(( error = ak_hmac_context_set_key_password( &hmacKey,
        pass, pass_size,
          secretKeyData.data.parameters.integritySalt.buf,
          secretKeyData.data.parameters.integritySalt.size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong generation of integrity key value" );
    ak_hmac_destroy( &hmacKey );
    goto exit;
  }

  /* 2. создаем структуру для итеративного вычисления значений функции hmac */
  if(( error = ak_compress_create_hmac( &compressCtx, &hmacKey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong hmac compress structure creation" );
    ak_hmac_destroy( &hmacKey );
    goto exit;
  }

  /* 3. кодируем данные и одновременно вычисляем имитовставку */
  ak_compress_clean( &compressCtx );
  ec = der_encode( &asn_DEF_SecretKey, &secretKeyData.data,
                                             ak_skey_der_encode_update, &compressCtx );
  /* результат вычислений помещается в temporary */
  memset( temporary, 0, temporary_size );
  ak_compress_finalize( &compressCtx, NULL, 0, temporary );
  ak_compress_destroy( &compressCtx );
  ak_hmac_destroy( &hmacKey );

  if( ec.encoded < 0 ) {
    ak_error_message( ak_error_wrong_asn1_encode, __func__, "wrong integrity code calculation" );
    goto exit;
  }

  /* 4. проверяем совпадение имитовставок */
  if( !ak_ptr_is_equal( temporary,
                              secretKeyData.integrityCode.buf, secretKeyData.integrityCode.size )) {
    ak_error_message( ak_error_not_equal_data, __func__,
                                                    "key container has different integrity code" );
    goto exit;
  }

  /* delme*/ printf("integrity code is Ok\n");


  exit:
  SEQUENCE_free( &asn_DEF_SecretKeyData, &secretKeyData, 1 );
  memset( &secretKeyData, 0, sizeof( struct SecretKeyData ));
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 void test_saved_key( char *filename )
{
 struct bckey loadedKey;

  ak_bckey_create_file( &loadedKey, filename, "password", 8 );


}

/* ----------------------------------------------------------------------------------------------- */
 void print_bckey( char *s, ak_bckey bkey )
{
  char *str = NULL;

  printf("%skey ---> %s (%s)\n", s, bkey->key.oid->name, bkey->key.oid->id );
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
