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

  printf("key ---> %s (%s)\n", bkey->key.oid->name, bkey->key.oid->id );
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

/* ----------------------------------------------------------------------------------------------- */



/* ----------------------------------------------------------------------------------------------- */
 int ak_bckey_create_file( ak_bckey bkey, const char *filename )
{
  ak_oid oid = NULL;
  int error = ak_error_ok;
  SecretKeyData_t secretKeyData;

 /* создаем asn1 структуру, считывая ее из файла */
  memset( &secretKeyData, 0, sizeof( struct SecretKeyData ));
  if(( error = ak_asn1_load_from_der_file( &asn_DEF_SecretKeyData,
                                                      &secretKeyData, filename )) != ak_error_ok )
    return ak_error_message_fmt( error, __func__,
                          "incorrect loading SecretKeyData structure from \"%s\" file", filename );

 /* если чтение прошло успешно, определяем тип ключа */
  if(( oid = ak_oid_find_by_object_identifier( &secretKeyData.data.engine )) == NULL ) {
    ak_error_message( error = ak_error_get_value(), __func__,
                                                         "incorrect searchin a secret key engine");
    goto exit;
  }

  if(( oid->engine != block_cipher ) || ( oid->mode != algorithm )) {
    ak_error_message( error = ak_error_oid_engine, __func__,
                                                       "using a secret key oid with wrong engine");
    goto exit;
  }

  /* delme */ asn_fprint( stdout, &asn_DEF_SecretKeyData, &secretKeyData );

  /* вот здесь нужно писать create_oid */
//  собственно разборщик где?

  /* создать структуру секретного ключа */
  /* закрыть файл */
  /* проверить, что это bckey */
  /* создать ключ по oid алгоритма блочного шифрования +  */

  exit:
  SEQUENCE_free( &asn_DEF_SecretKeyData, &secretKeyData, 1 );
  memset( &secretKeyData, 0, sizeof( struct SecretKeyData ));
 return error;
}


/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
 char password[64]; /* пароль */
 ak_bckey storedkey = NULL; /* ключ, который будет сохраняться в контейнере */
 struct bckey loadedkey;

 /* инициализируем библиотеку */
  ak_libakrypt_create( ak_function_log_stderr );
 /* инициализируем ключ */
  printf("key creation: %d\n",
   ak_bckey_create_magma( storedkey = malloc( sizeof( struct bckey ))));
 /* присваиваем ключу константное значение */
  printf("key asigning value: %d\n",
   ak_bckey_context_set_password( storedkey, "password1234", 12, "salt", 4 ));
  storedkey->key.resource.counter -= 113; /* немного подправим ресурс ключа */

 /* выводим текущее значение ключа */
  printf("key before transformation:\n");
  print_bckey( storedkey );

 /* присваиваем паролю какое-то значение */
  memset( password, 0, sizeof( password ));
  memcpy( password, "hello", 5 );

 /* сохраняем ключ в заданном файле */
  ak_skey_to_der_file( &storedkey->key, "simple.key", password, strlen( password ),
                                         "The little description of simple key" );
 /* освобождаем память */
  storedkey = ak_bckey_delete( storedkey );
  printf("key destroying: %d\n", ak_error_get_value( ));

 /* создаем новый контекст */

  ak_bckey_create_file( &loadedkey, "simple.key" );

 /* выводим текущее значение ключа */
  printf("key after loading from file:\n");
//  print_bckey( &loadedkey );

// SecretKeyData_t *secretKeyData =
//    ak_skey_to_asn1_secret_key( &bkey->key, password, strlen( password ), "This is my first key" );

// asn_fprint( stdout, &asn_DEF_SecretKeyData, secretKeyData );
// asn_DEF_SecretKeyData.free_struct( &asn_DEF_SecretKeyData, secretKeyData, 0);

//  /* delme */ asn_fprint( stdout, &asn_DEF_SecretKeyData, &secretKeyData );



// exit:
 return ak_libakrypt_destroy();
}
