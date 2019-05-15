/* Пример, иллюстрирующий очень маленькую скорость
   совместного шифрования и выработки имитовставки с помощью режима MGM
   Используются неэкспортируемые функции библиотеки.

   test-internal-mgm04.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <sys/types.h>
 #include <ak_bckey.h>
 #include <ak_tools.h>
 #include <ak_mgm.h>

/* предварительные описания */
 void print_file_icode( const char * );
 void test_block_cipher( ak_oid );
 void test_encrypt_file( ak_bckey, const char *, const char *, ak_uint8 * );
 void test_decrypt_file( ak_bckey, const char *, const char *, ak_uint8 * );

 /* константы */
 static ak_uint32 mbsize = 128;
 static ak_uint8 constkey[32] = {
    0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0xa1, 0xa1, 0xa2, 0xa2, 0xa3, 0xa3, 0xa4, 0xa4 };
 static ak_uint8 constiv[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

 int main( void )
{
  struct file fp;
  ak_oid oid = NULL;
  ak_uint8 memory[1024];
  ak_uint32 idx = 0;

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* в принудительном порядке создаем файл для экспериментов */
  printf(" generation a %dMB file, wait a few seconds ... \n", (int) mbsize ); fflush(stdout);
  ak_file_create_to_write( &fp, "data.dat" );
  for( idx = 0; idx < mbsize*1024; idx++ ) { // mbsize MB
     memset( memory, (ak_uint8)idx, 1024 );
     ak_file_write( &fp, memory, 1024 );
  }
  ak_file_close( &fp );

 /* контрольная сумма файла для проверки */
  print_file_icode( "data.dat" );

 /* цикл поиска алгоритмов блочного шифрования */
  oid = ak_oid_context_find_by_engine( block_cipher );
  while( oid != NULL ) {
   if( oid->mode == algorithm ) {
     printf(" %s test\n", oid->name );
     test_block_cipher( oid );
   }
   oid = ak_oid_context_findnext_by_engine( oid, block_cipher );
  }

 /* завершаем вычисления */
 return ak_libakrypt_destroy();
}

/* тестирование алгоритмов шифрования */
 void test_block_cipher( ak_oid oid )
{
  struct bckey ekey;
  ak_uint8 out1[64];
  char filename[128];

 /* используем внешний oid для создания объекта */
  if(((ak_function_bckey_create *)oid->func.create)( &ekey ) == ak_error_ok )
   printf(" Ok (create encryption key)\n" ); else return;
 /* присваиваем ключу константное значение */
  if( ak_bckey_context_set_key( &ekey, constkey, sizeof( constkey ), ak_true ) ==  ak_error_ok )
   printf(" Ok (set encryption key)\n" ); else goto exlab;

 /* зашифровываем файл */
  ak_snprintf( filename, 128, "data.dat.%s.encrypt", oid->name );
  test_encrypt_file( &ekey, "data.dat", filename, out1 );

 /* расшифровываем файл */
  test_decrypt_file( &ekey, filename, "data.dat", out1 );

  exlab:
  if( ak_error_ok == ((ak_function_destroy_object *)(ekey.key.oid)->func.destroy)( &ekey ))
   printf(" Ok (destroy key)\n\n" );
}

 void test_encrypt_file( ak_bckey key, const char *from, const char *to, ak_uint8 *out1 )
{
  clock_t time = 0;
  struct file in, out;
  ak_uint8 *buffer = NULL;
  size_t len = 0, bsize = 0;
  struct mgm_ctx mctx;

 /* принудительно изменяем ресурс ключа */
  key->key.resource.counter = ( 2*mbsize*1024*1024 )/key->bsize;
  printf(" key resource changed to %lu blocks\n", (unsigned long int)key->key.resource.counter );

 /* открываем файлы */
  if( ak_file_open_to_read( &in, from ) == ak_error_ok )
    printf(" file %s is open (size: %lu bytes)\n", from, (unsigned long int)in.size ); else return;
  if( ak_file_create_to_write( &out, to ) == ak_error_ok ) printf(" file %s is created\n", to ); else return;

  bsize = ( size_t )in.blksize;
  printf(" one block size: %lu\n", (unsigned long int)(bsize));
  buffer = malloc( bsize );

 /* теперь собственно зашифрование */
  time = clock();

   /* обрабатываем ассоциированные данные */
    ak_mgm_context_authentication_clean( &mctx, key, constiv, key->bsize );
    len = ( size_t ) ak_file_read( &in, buffer, bsize );
    if( len > 0 ) {
      ak_mgm_context_authentication_update( &mctx, key, buffer, len );
      ak_file_write( &out, buffer, len );
    }

   /* зашифровываем данные */
    ak_mgm_context_encryption_clean( &mctx, key, constiv, key->bsize );
    do{
       if(( len = ( size_t ) ak_file_read( &in, buffer, bsize )) > 0 ) {
         ak_mgm_context_encryption_update( &mctx, key, key, buffer, buffer, len );
         ak_file_write( &out, buffer, len );
       }
    } while( len );
   /* вычисляем имитовставку */
    ak_mgm_context_authentication_finalize( &mctx, key, out1, key->bsize );

  time = clock() - time;
  ak_ptr_to_hexstr_static( out1, key->bsize, buffer, 1024, ak_false );
  printf(" mac: %s\n", buffer );
  printf(" encrypt time: %fs, per 1MB = %fs, speed = %f MBs\n",
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ), (double) CLOCKS_PER_SEC *mbsize / (double) time );
  free( buffer );
  ak_file_close( &in );
  ak_file_close( &out );

 /* выводим контрольную сумму от зашифрованного файла */
  print_file_icode( to );
}


 void test_decrypt_file( ak_bckey key, const char *from, const char *to, ak_uint8 *out1 )
{
  clock_t time = 0;
  struct file in, out;
  ak_uint8 *buffer = NULL, out2[64];
  size_t len = 0, bsize = 0;
  struct mgm_ctx mctx;

 /* принудительно изменяем ресурс ключа */
  key->key.resource.counter = ( 2*mbsize*1024*1024 )/key->bsize;
  printf(" key resource changed to %lu blocks\n", (unsigned long int)key->key.resource.counter );

 /* открываем файлы */
  if( ak_file_open_to_read( &in, from ) == ak_error_ok )
    printf(" file %s is open (size: %lu bytes)\n", from, (unsigned long int)in.size ); else return;
  if( ak_file_create_to_write( &out, to ) == ak_error_ok ) printf(" file %s is created\n", to ); else return;

  bsize = ( size_t )in.blksize;
  printf(" one block size: %lu\n", (unsigned long int)(bsize));
  buffer = malloc( bsize );

 /* теперь собственно зашифрование */
  time = clock();

   /* обрабатываем ассоциированные данные */
    ak_mgm_context_authentication_clean( &mctx, key, constiv, key->bsize );
    len = ( size_t ) ak_file_read( &in, buffer, bsize );
    if( len > 0 ) {
      ak_mgm_context_authentication_update( &mctx, key, buffer, len );
      ak_file_write( &out, buffer, len );
    }

   /* зашифровываем данные */
    ak_mgm_context_encryption_clean( &mctx, key, constiv, key->bsize );
    do{
       if(( len = ( size_t ) ak_file_read( &in, buffer, bsize )) > 0 ) {
         ak_mgm_context_decryption_update( &mctx, key, key, buffer, buffer, len );
         ak_file_write( &out, buffer, len );
       }
    } while( len );
   /* вычисляем имитовставку */
    ak_mgm_context_authentication_finalize( &mctx, key, out2, key->bsize );

  time = clock() - time;
  ak_ptr_to_hexstr_static( out1, key->bsize, buffer, 1024, ak_false );
  printf(" mac: %s ", buffer );
  if( memcmp( out2, out1, key->bsize ) == 0 ) printf(" Ok\n"); else printf(" Wrong\n" );

  printf(" decrypt time: %fs, per 1MB = %fs, speed = %f MBs\n",
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ), (double) CLOCKS_PER_SEC *mbsize / (double) time );
  free( buffer );
  ak_file_close( &in );
  ak_file_close( &out );

 /* выводим контрольную сумму от зашифрованного файла */
  print_file_icode( to );
}

/* вывод хэш-кода для заданного файла */
 void print_file_icode( const char *file )
{
  clock_t time;
  struct hash ctx;
  ak_uint8 out[32], memory[96];

  time = clock();
   ak_hash_context_create_streebog256( &ctx );
   ak_hash_context_file( &ctx, file, out );
  time = clock() - time;

  ak_ptr_to_hexstr_static( out, 32, memory, sizeof( memory ), ak_false );
  printf(" icode: %s (%fs, %s)\n\n",
    memory, (double) time / (double) CLOCKS_PER_SEC, file );
  ak_hash_context_destroy( &ctx );
}
