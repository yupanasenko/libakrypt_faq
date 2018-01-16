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
 // printf("password: "); fflush( stdout );
 // if( ak_password_read( password, 64 ) != ak_error_ok ) goto exit;
 memset( password, 0, 64 );
 memcpy( password, "hello dolly", 11 );
 printf("\npass: %s, (len: %ld)\n\n", password, strlen( password ));

 ak_skey_to_der_file( &bkey->key, "simple.key", password, strlen( password ),
                                    "The little description of simple key" );


// SecretKeyData_t *secretKeyData =
//    ak_skey_to_asn1_secret_key( &bkey->key, password, strlen( password ), "This is my first key" );

// asn_fprint( stdout, &asn_DEF_SecretKeyData, secretKeyData );
// asn_DEF_SecretKeyData.free_struct( &asn_DEF_SecretKeyData, secretKeyData, 0);



/* освобождаем пямять и завершаем работу */
 bkey = ak_bckey_delete( bkey );
 printf("key destroying: %d\n", ak_error_get_value( ));

 return ak_libakrypt_destroy();
}
