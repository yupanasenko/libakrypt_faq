 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <ak_asn1.h>
 #include <ak_asn1_keys.h>
 #include <ak_hash.h>
 #include <ak_tools.h>

 int bckey_test( ak_oid );
 int hmac_test( ak_oid );
 int signkey_test( ak_oid );

/* определяем функцию, которая будет имитировать чтение пароля пользователя */
 int get_user_password( char *password, size_t psize )
{
  memset( password, 0, psize );
  ak_snprintf( password, psize, "password" );
 return ak_error_ok;
}

/* --------------------------------------------------------------------------------------------- */
 int main(void)
{
 ak_oid oid = NULL;
 int result = EXIT_SUCCESS;

 /* Инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();
  ak_libakrypt_set_openssl_compability( ak_false );

  /* начинаем с того, что определяем функцию чтения пароля */
   ak_libakrypt_set_password_read_function( get_user_password );

  /* тестируем ключи алгоритмов блочного шифрования */
   if(( result = bckey_test( ak_oid_context_find_by_name( "kuznechik" ))) != EXIT_SUCCESS ) goto lab1;
   if(( result = bckey_test( ak_oid_context_find_by_name( "magma" ))) != EXIT_SUCCESS ) goto lab1;
   if(( result = hmac_test( ak_oid_context_find_by_name( "hmac-streebog256" ))) != EXIT_SUCCESS ) goto lab1;
   if(( result = hmac_test( ak_oid_context_find_by_name( "hmac-streebog512" ))) != EXIT_SUCCESS ) goto lab1;

  /* тестируем ключи алгоритма ЭП для нескольких кривых */
   oid = ak_oid_context_find_by_engine( identifier );
   while( oid != NULL ) {
     if( oid->mode == wcurve_params ) {
       if(( result = signkey_test( oid )) != EXIT_SUCCESS ) goto lab1;
     }
     oid = ak_oid_context_findnext_by_engine( oid, identifier );
   }

   lab1:
  return ak_libakrypt_destroy();
}

/* --------------------------------------------------------------------------------------------- */
 int bckey_test( ak_oid oid )
{
  struct bckey bkey;
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38 };
  ak_uint8 testdata[31] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x79, 0x6a, 0x5b, 0x4c, 0x3d, 0x2e, 0x1f };
  ak_uint8 out[31], out2[31], im[16], im2[16];
  char filename[128], name[64];
  char *keyname = NULL;

   /* создаем ключ, который будет помещаться в контейнер */
    ak_bckey_context_create_oid( &bkey, oid );
   /* присваиваем ключу константное значение */
    ak_bckey_context_set_key( &bkey, testkey, sizeof( testkey ));    
   /* для отладки - выводим сформированную структуру в консоль
    ak_skey_context_print_to_file( &bkey.key, stdout );
    printf("\n"); */

   /* шифруем тестируемые данные */
    ak_bckey_context_ctr( &bkey, testdata, out, sizeof( testdata ), testkey, bkey.bsize );
   /* вычисляем имитовставку от тестируемых данных */
    ak_bckey_context_cmac( &bkey, testdata, sizeof( testdata ), im, bkey.bsize );
     printf("%-10s: %s ", bkey.key.oid->names[0], ak_ptr_to_hexstr( out, sizeof(out), ak_false ));
     printf("(cmac: %s)\n", ak_ptr_to_hexstr( im, bkey.bsize, ak_false ));
     ak_snprintf( name, sizeof( name ), "key-%s-%03u", oid->names[0], bkey.key.number[0] ); /* имя ключа */

   /* экпортируем ключ в файл (в der-кодировке) */
    ak_key_context_export_to_derfile_with_password( &bkey, block_cipher,
                                              "password", 8, name, filename, sizeof( filename ));
   /* удаляем ключ */
    ak_bckey_context_destroy( &bkey );
   /* импортируем ключ из файла */
    ak_bckey_context_import_from_derfile( &bkey, filename, &keyname );
   /* для отладки - выводим сформированную структуру в консоль
    ak_skey_context_print_to_file( &bkey.key, stdout );
    printf("\n"); */
    printf("keyname: %s\n", keyname );
    if( keyname != NULL ) free( keyname );

   /* шифруем тестируемые данные еще раз*/
    ak_bckey_context_ctr( &bkey, testdata, out2, sizeof( testdata ), testkey, bkey.bsize );
   /* вычисляем имитовставку от тестируемых данных */
    ak_bckey_context_cmac( &bkey, testdata, sizeof( testdata ), im2, bkey.bsize );
     printf("%-10s: %s ", bkey.key.oid->names[0], ak_ptr_to_hexstr( out2, sizeof(out2), ak_false ));
     printf("(cmac: %s)\n", ak_ptr_to_hexstr( im2, bkey.bsize, ak_false ));

   /* удаляем ключ */
    if( ak_ptr_is_equal_with_log( out, out2, sizeof( testdata ))) printf("encryption: Ok\n");
      else { printf("encryption: Wrong\n"); return EXIT_FAILURE; }
    if( ak_ptr_is_equal_with_log( im, im2, bkey.bsize )) printf("cmac: Ok\n\n");
      else { printf("cmac: Wrong\n\n"); return EXIT_FAILURE; }
    ak_bckey_context_destroy( &bkey );

 return EXIT_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
 int hmac_test( ak_oid oid )
{
  struct hmac hctx;
  ak_uint8 testkey[64] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x79, 0x6a, 0x5b, 0x4c, 0x3d, 0x2e, 0x1f, 0x00 };

  ak_uint8 data[12] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
  ak_uint8 out[64], out2[64];
  char filename[128];
  char *keyname = NULL;

   /* создаем ключ, который будет помещаться в контейнер */
    ak_hmac_context_create_oid( &hctx, oid );
   /* присваиваем ключу константное значение */
    ak_hmac_context_set_key( &hctx, testkey, sizeof( testkey ));
   /* для отладки - выводим сформированную структуру в консоль
    ak_skey_context_print_to_file( &hctx.key, stdout );
    printf("\n"); */

   /* вычисляем имитовставку */
    ak_hmac_context_ptr( &hctx, data, sizeof( data ), out, sizeof( out ));
    printf("hmac: %s\n", ak_ptr_to_hexstr( out, ak_hmac_context_get_tag_size( &hctx ), ak_false ));
   /* экпортируем ключ в файл (в der-кодировке) */
    ak_key_context_export_to_derfile_with_password( &hctx, hmac_function,
                                      "password", 8, "hmac keyname", filename, sizeof( filename ));

   /* удаляем ключ */
    ak_hmac_context_destroy( &hctx );
   /* импортируем ключ из файла */
    ak_hmac_context_import_from_derfile( &hctx, filename, &keyname );
   /* для отладки - выводим сформированную структуру в консоль
    ak_skey_context_print_to_file( &hctx.key, stdout );
    printf("\n"); */
    printf("keyname: %s\n", keyname );
    if( keyname != NULL ) free( keyname );

    ak_hmac_context_ptr( &hctx, data, sizeof( data ), out2, sizeof( out2 ));
    printf("hmac: %s", ak_ptr_to_hexstr( out2, ak_hmac_context_get_tag_size( &hctx ), ak_false ));

    if( ak_ptr_is_equal_with_log( out, out2, ak_hmac_context_get_tag_size( &hctx )))
      printf(" Ok\n\n");
      else { printf(" Wrong\n\n"); return EXIT_FAILURE; }
    ak_hmac_context_destroy( &hctx );

 return EXIT_SUCCESS;
}

/* --------------------------------------------------------------------------------------------- */
 int signkey_test( ak_oid curvoid )
{
  int result = EXIT_SUCCESS;
  ak_uint8 testkey[64] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88, 0x79, 0x6a, 0x5b, 0x4c, 0x3d, 0x2e, 0x1f, 0x00 };
  ak_uint8 sign[128];
  char filename[128], tname[256], *keyname = NULL;
  struct signkey skey;
  struct verifykey vkey;

   if(( curvoid->engine == identifier ) && ( curvoid->mode == wcurve_params )) {
     switch( ((ak_wcurve)curvoid->data)->size ) {
       case ak_mpzn256_size:
         ak_signkey_context_create_streebog256_with_curve( &skey, (ak_wcurve)curvoid->data );
         ak_signkey_context_set_key( &skey, testkey, 32 );
         break;

       case ak_mpzn512_size:
         ak_signkey_context_create_streebog512_with_curve( &skey, (ak_wcurve)curvoid->data );
         ak_signkey_context_set_key( &skey, testkey, 64 );
         break;

       default: printf("boreken oid\n"); return EXIT_FAILURE;
     }
   } else return EXIT_FAILURE;
   printf("---- oid: %s (%s)\n", curvoid->id, curvoid->names[0] );

  /* подписываем данные */
   ak_signkey_context_sign_ptr( &skey, testkey, 13, sign, sizeof( sign ));
   printf("signature: %s\n", ak_ptr_to_hexstr( sign,
                                       ak_signkey_context_get_tag_size( &skey ), ak_false ));

  /* создаем необязательное имя для ключа */
   ak_snprintf( tname, sizeof( tname ), "DSkey-%s-%03u", curvoid->names[0], skey.key.number[0] );
  /* сохраняем ключ */
   ak_key_context_export_to_derfile_with_password( &skey, sign_function,
                                             "password", 8, tname, filename, sizeof( filename ));
  /* уничтожаем ключ */
   ak_signkey_context_destroy( &skey );

  /* считываем ключ */
   ak_signkey_context_import_from_derfile( &skey, filename, &keyname );
   /* для отладки - выводим сформированную структуру в консоль
    ak_skey_context_print_to_file( &skey.key, stdout );
    printf("\n"); */
    printf("keyname: %s\n", keyname );
    if( keyname != NULL ) free( keyname );

  /* создаем открытый */
   ak_verifykey_context_create_from_signkey( &vkey, &skey );
   printf("verify: ");
   if( ak_verifykey_context_verify_ptr( &vkey, testkey, 13, sign )) printf("Ok\n\n");
     else { printf("Wrong\n\n"); result = EXIT_FAILURE; }

  /* уничтожаем ключи */
   ak_signkey_context_destroy( &skey );
   ak_verifykey_context_destroy( &vkey );
 return result;
}

//  ak_uint8 out[31], out2[31], im[16], im2[16];
//  char filename[128];


//   /* выводим дерево */
//    ak_asn1_context_print( root, stdout );
//   /* проверяем дерево */
//    if( root->count ) {
//     /* перемещаемся в начало */
//      ak_asn1_context_first( root );
//      do{
//          ak_asn1 basicKey, content;
//          ak_oid oid;
//          size_t len = 0;
//          char *name = NULL;
//          ak_pointer number = NULL;
//          struct resource resource;
//          struct bckey key;

//          if( ak_tlv_context_check_libakrypt_container( root->current, &basicKey, &content )) { /* контейнер найден */
//            struct bckey ekey, ikey;

//             ak_asn1_context_get_derived_keys( basicKey, &ekey, &ikey );
//             switch( ak_asn1_context_get_content_type( content )) {
//               case symmetric_key_content: /* в контейнере находится секретный ключ */
//                   if(( ak_asn1_context_get_symmetric_key_info(
//                           content, &oid, &number, &len, &name, &resource )) != ak_error_ok ) break;
//                   if((( ak_function_bckey_create *)oid->func.create )( &key ) != ak_error_ok ) break;

//                   ak_asn1_context_get_skey( content, &key.key, &ekey, &ikey );
//                   ak_skey_context_set_number( &key.key, number, len );
//                   ak_skey_context_set_resource( &key.key, &resource );
//                   ak_skey_context_print_to_file( &key.key, stdout );
//                   ak_bckey_context_destroy( &key );
//                 break;

//               default:
//                 printf("unsupported content\n");
//                 break;
//             }


//             ak_bckey_context_destroy( &ekey );
//             ak_bckey_context_destroy( &ikey );

//            /*
//             получить тип (для create)
//             создать
//            */
//          }
//      } while( ak_asn1_context_next( root )); /* перебираем все возможные узлы */
//    }

//   /* удаляем дерево */
//    ak_asn1_context_delete( root );

