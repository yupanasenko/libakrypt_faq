 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <akrypt.h>

 #include <ak_bckey.h>

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_mgm( int argc, TCHAR *argv[] )
{
  bool_t oneKeyFlag = ak_true;
  size_t idx, minDataLen = 32, maxDataLen = 512, aeSize = 16;

  char str[4096];
  struct random rnd;
  struct bckey encryptionKey;
  struct bckey authenticationKey;
  ak_bckey eKey = &encryptionKey, aKey = &authenticationKey; /* указатели на ключи */
  ak_uint8 iv[16], ae[128], in[2048], out[2048], im[16];

  FILE *fp = NULL;
  char *key = "key.txt";
//  char *expanded_keys = "expanded_keys.txt";
  char *inf = "input_data.txt";
  char *outf = "output_data.txt";


  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* создаем случайные параметры: синхропосылку и данные */
  ak_random_context_create_lcg( &rnd );
  ak_random_context_random( &rnd, iv, sizeof( iv )); /* синхропосылка */
  ak_random_context_random( &rnd, in, sizeof( in )); /* шифруемые данные */
  ak_random_context_random( &rnd, ae, sizeof( ae )); /* открытые */

 /* создаем ключи */
  if(( ak_bckey_context_create_kuznechik( eKey ) != ak_error_ok )) goto lexit;
  ak_bckey_context_set_key_random( eKey, &rnd );

  if( oneKeyFlag ) aKey = eKey;
    else {
           if(( ak_bckey_context_create_kuznechik( aKey ) != ak_error_ok )) goto lexit;
           ak_bckey_context_set_key_random( aKey, &rnd );
         }

 /* записываем ключ */
  fp = fopen( key, "w" );

  /* чистый ключ */
   eKey->key.unmask( &eKey->key );
   ak_ptr_to_hexstr_static( eKey->key.key.data, 32, str, sizeof( str ), ak_false );
   fprintf(fp, "%s\n", str );
   eKey->key.set_mask( &eKey->key );
   aKey->key.unmask( &aKey->key );
   ak_ptr_to_hexstr_static( aKey->key.key.data, 32, str, sizeof( str ), ak_false );
   fprintf(fp, "%s\n", str );
   aKey->key.set_mask( &aKey->key );
  fclose(fp);

 /* записываем данные */
  fp = fopen( inf, "w" );
   ak_ptr_to_hexstr_static( iv, sizeof(iv), str, sizeof( str ), ak_false );
   fprintf(fp, "iv: %s\n", str );
   ak_ptr_to_hexstr_static( ae, aeSize, str, sizeof( str ), ak_false );
   fprintf(fp, "ae: %s\n", str );
   ak_ptr_to_hexstr_static( in, maxDataLen, str, sizeof( str ), ak_false );
   fprintf(fp, "in: %s\n", str );
  fclose(fp);

 /* начинаем шифрование */
  fp = fopen( outf, "w" );
  for( idx = minDataLen-1; idx < maxDataLen; idx++ ) {
    ak_bckey_context_encrypt_mgm( eKey, aKey, ae, aeSize,
                                  in, out, idx, iv, sizeof( iv ), im, sizeof(im));
    ak_ptr_to_hexstr_static( out, idx, str, sizeof( str ), ak_false );
    fprintf( fp, "%s\n", str );
    ak_ptr_to_hexstr_static( im, sizeof(im), str, sizeof( str ), ak_false );
    fprintf( fp, "%s\n", str );
  }
  fclose(fp);

  lexit:
    ak_random_context_destroy( &rnd );
    if( aKey != eKey ) ak_bckey_context_destroy( aKey );
    ak_bckey_context_destroy( eKey );

 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
