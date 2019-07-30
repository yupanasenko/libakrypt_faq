/* Пример, позволяющий генерировать тестовые примеры для алгоритма MGM
   (на примере блочного шифра Кузнечик).

   Внимание! Используются неэкспортируемые функции библиотеки.
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_mgm.h>
 #include <ak_bckey.h>

 int main( int argc, char *argv[] )
{
  bool_t oneKeyFlag = ak_true;
  bool_t fixedKeyFlag = ak_false;
  bool_t testFlag = ak_false;

  size_t i, j, blen, bcount = 0;
  char str[4096], *filename = NULL;
  FILE *fp = NULL, *fs = NULL;
  struct random rnd;
  struct mgm_ctx mgm;
  struct bckey encryptionKey;
  struct bckey authenticationKey;
  ak_bckey eKey = &encryptionKey, aKey = &authenticationKey; /* указатели на ключи */
  ak_uint8 ivin[413], out[2176], im[16], *p = NULL, kt[16], iv[16];

  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

  if( argc < 2 ) {
    printf("usage: test_internal_mgm05 [file] [-2] [-r] [-t]\n");
    printf("where\n");
    printf("  file  -  name of file with initial vector (16 bytes) + plain data\n");
    printf("    -2  -  use two separate keys for encryption and authentication\n");
    printf("    -r  -  use random initial vector and random plain data\n");
    printf("    -t  -  use fixed encryption key from GOST R 34.12-2015\n");
    return EXIT_SUCCESS;
  }
  for( i = 1; i < (size_t)argc; i++ ) {
     if( strncmp( "-2", argv[i], 2 ) == 0 ) {
       oneKeyFlag = ak_false;
       continue;
     }
     if( strncmp( "-t", argv[i], 2 ) == 0 ) {
       fixedKeyFlag = ak_true;
       continue;
     }
     if( strncmp( "-r", argv[i], 2 ) == 0 ) {
       filename = NULL;
       continue;
     }
     filename = argv[i];
  }

  if( ak_libakrypt_create( NULL ) != ak_true ) return ak_libakrypt_destroy();

 /* создаем случайные параметры: синхропосылку и данные */
  ak_random_context_create_lcg( &rnd );

 /* создаем ключи */
  if(( ak_bckey_context_create_kuznechik( eKey ) != ak_error_ok )) goto lexit;
  if( fixedKeyFlag ) ak_bckey_context_set_key( eKey, testkey, 32, ak_true );
    else ak_bckey_context_set_key_random( eKey, &rnd );

  if( oneKeyFlag ) aKey = eKey;
    else {
           if(( ak_bckey_context_create_kuznechik( aKey ) != ak_error_ok )) goto lexit;
           ak_bckey_context_set_key_random( aKey, &rnd );
         }

 /* сохраняем ключи */
  fp = fopen( "key.txt", "w" );
    eKey->key.unmask( &eKey->key );
    ak_ptr_to_hexstr_static( eKey->key.key.data, 32, str, sizeof( str ), ak_true );
    fprintf(fp, "%s\n", str );
    eKey->key.set_mask( &eKey->key );

    if( !oneKeyFlag ) {
      fprintf(fp, "\n");
      aKey->key.unmask( &aKey->key );
      ak_ptr_to_hexstr_static( aKey->key.key.data, 32, str, sizeof( str ), ak_true );
      fprintf(fp, "%s\n", str );
      aKey->key.set_mask( &aKey->key );
    }
  fclose(fp);
  printf("key(s) stored in key.txt\n");

 /* сохраняем раундовые ключи */
  fp = fopen( "round_key.txt", "w" );
    p = (ak_uint8 *) eKey->key.data;
    for( i = 0; i < 10; i++ ) {
       for( j = 0; j < 16; j++ ) kt[j] = p[j]^p[320+j];
       p += 16;
       ak_ptr_to_hexstr_static( kt, 16, str, sizeof( str ), ak_true );
       fprintf(fp, "%s\n", str );
    }
    if( !oneKeyFlag ) {
      fprintf(fp, "\n");
      p = (ak_uint8 *) aKey->key.data;
      for( i = 0; i < 10; i++ ) {
         for( j = 0; j < 16; j++ ) kt[j] = p[j]^p[320+j];
         p += 16;
         ak_ptr_to_hexstr_static( kt, 16, str, sizeof( str ), ak_true );
         fprintf(fp, "%s\n", str );
      }
    }
  fclose(fp);
  printf("round keys stored in round_key.txt\n");


 /* теперь надо выяснить, что шифруем */
  if( filename == NULL ) {
    /* создаем файл для тестирования */
     ak_uint8 *pv = ivin;
     size_t len = sizeof( ivin );
     memset( ivin, 0, len );
     printf("generated of random data: %u bytes\n", (unsigned int)sizeof( ivin ));
     fp = fopen( "input.txt", "w" );
     ak_random_context_random( &rnd, ivin, (ssize_t)len ); /* синхропосылка, она же ae + шифруемые данные */
     while( len > 0 ) {
       size_t blen = ak_min( len, 16 );
       ak_ptr_to_hexstr_static( pv, blen, str, sizeof( str ), ak_true );
       pv += blen; len -= blen;
       fprintf( fp, "%s\n", str );
     }
     fclose(fp);
     filename = "input.txt";
     testFlag = ak_true;
  }
  printf("using iv and plain data stored in %s\n", filename );

 /* теперь приступаем к шифрованию данных */
  fp = fopen( filename, "r" );
  fs = fopen( "output.txt", "w" );
  if( fgets( str, sizeof( str ), fp ) == NULL ) {
    printf("incorrect reading of iv\n");
    goto lexit;
  }
  str[32] = 0;
  if(strlen( str ) != 32 ) {
    printf("unexpected length of iv (%s, %u bytes)\n", str, (unsigned int)strlen(str));
    goto lexit;
  } else {
            printf( "\n%s (iv)\n", str );
            fprintf( fs, "%s\n", str );
         }

  ak_hexstr_to_ptr( str, iv, 16, ak_true );
  ak_mgm_context_authentication_clean( &mgm, aKey, iv, 16 );
  ak_mgm_context_authentication_update( &mgm, aKey, iv, 16 );
  ak_mgm_context_encryption_clean( &mgm, eKey, iv, 16 );

  while( !feof( fp )) {
   if( fgets( str, sizeof(str), fp ) == NULL ) break;
     blen = strlen( str ) >> 1;
     str[blen << 1] = 0;
     printf( "%s (%02u)\n", str, (unsigned int)++bcount );
     ak_hexstr_to_ptr( str, iv, 16, ak_true );
     ak_mgm_context_encryption_update( &mgm, eKey, aKey, iv, out, blen );

     ak_ptr_to_hexstr_static( out, blen, str, sizeof( str ), ak_true );
     fprintf( fs, "%s\n", str );
   }
  memset( im, 0, sizeof( im ));
  ak_mgm_context_authentication_finalize( &mgm, aKey,  im, 16 );
  ak_ptr_to_hexstr_static( im, 16, str, sizeof( str ), ak_true );
  printf("im: %s\n", str );
  fprintf( fs, "%s (im)\n", str );
  fclose(fp);
  fclose(fs);

 /* выполняем проверку шифрования для случайно выработанных данных */
  if( testFlag ) {
    ak_uint8 im2[16];
    ak_bckey_context_encrypt_mgm(
      eKey, aKey, /* ключи шифрования и имитозащиты */
      ivin, 16, /* открытые данные, подлежащие имитозащите */
      ivin+16,  /* открытый текст */
      ivin+16,  /* шифртекст */
      sizeof( ivin ) - 16,  /* длина обрабатываемых данных */
      ivin, 16, /* синхропосылка */
      im2, sizeof( im2 ));
      ak_ptr_to_hexstr_static( im2, 16, str, sizeof( str ), ak_true );
      printf("im: %s (test)\n", str );
  }

  lexit:
    ak_random_context_destroy( &rnd );
    if( aKey != eKey ) ak_bckey_context_destroy( aKey );
    ak_bckey_context_destroy( eKey );

 return ak_libakrypt_destroy();
}

