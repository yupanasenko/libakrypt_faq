/* Пример, иллюстрирующий скорость алгоритмов блочного шифрования.
   Используются неэкспортируемые функции библиотеки.

   test-internal-bckey03.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <sys/types.h>
 #include <ak_bckey.h>
 #include <ak_tools.h>

/* тестовая функция */
 void test_block_cipher( ak_oid oid );
/* зашифрование одного файла */
 void test_encrypt_file( ak_bckey key, const char *from, const char *to );
/* вывод хэш-кода от заданного файла */
 void print_file_icode( const char * );

 /* константы */
 ak_uint32 mbsize = 128;
 ak_uint32 constkey[8] = {
    0x12345678, 0xabcdef0, 0x11223344, 0x55667788,
    0xaabbccdd, 0xeeff0011, 0xa1a1a2a2, 0xa3a3a4a4
 };
 ak_uint8 constiv[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };

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
     fwrite( memory, 1024, 1, fp.fp );
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

/* тестирование механизмов создания ключей */
 void test_block_cipher( ak_oid oid )
{
  struct bckey key;
  char filename[128];

 /* используем внешний oid для создания объекта */
  if(((ak_function_bckey_create *)oid->func.create)( &key ) == ak_error_ok )
   printf(" Ok (create key)\n" ); else return;
 /* присваиваем ключу константное значение */
  if( ak_bckey_context_set_key( &key, constkey, sizeof( constkey ), ak_true ) ==  ak_error_ok )
   printf(" Ok (set key)\n" ); else goto exlab;

 /* зашифровываем файл */
  ak_snprintf( filename, 128, "data.dat.%s.encrypt", oid->name );
  test_encrypt_file( &key, "data.dat", filename );

 /* расшифровываем файл */
  test_encrypt_file( &key, filename, "data.dat" );

 /* используем oid, содержащийся внутри объекта, для удаления (объект удаляет сам себя) */
  exlab:
  if( ak_error_ok == ((ak_function_destroy_object *)(key.key.oid)->func.destroy)( &key ))
   printf(" Ok (destroy key)\n\n" );
}

/* шифрование заданного файла */
 void test_encrypt_file( ak_bckey key, const char *from, const char *to )
{
  clock_t time = 0;
  struct file in, out;
  ak_uint8 *buffer = NULL;
  size_t len = 0, bsize = 0;

 /* принудительно изменяем ресурс ключа */
  key->key.resource.counter = ( mbsize*1024*1024 )/key->bsize;
  printf(" key resource changed to %lu blocks\n", (unsigned long int)key->key.resource.counter );

 /* открываем файлы */
  if( ak_file_open_to_read( &in, from ) == ak_error_ok )
    printf(" file %s is open (size: %lu bytes)\n", from, (unsigned long int)in.size ); else return;
  if( ak_file_create_to_write( &out, to ) == ak_error_ok ) printf(" file %s is created\n", to ); else return;

  bsize = in.blksize;
  printf(" one block size: %lu\n", (unsigned long int)(bsize));
  buffer = malloc( bsize );

 /* теперь собственно зашифрование */
  time = clock();
  len = fread( buffer, 1, bsize, in.fp );
  if( len > 0 ) {
    ak_bckey_context_xcrypt( key, buffer, buffer, len, constiv, key->bsize/2 );
    fwrite( buffer, len, 1, out.fp );
  }
  do{
     if(( len = fread( buffer, 1, bsize, in.fp )) > 0 ) {
       ak_bckey_context_xcrypt( key, buffer, buffer, len, NULL, 0 );
       fwrite( buffer, len, 1, out.fp );
     }
  } while( len );
  time = clock() - time;
  printf(" encrypt time: %fs, per 1MB = %fs, speed = %f MBs\n",
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
  struct hash ctx;
  ak_uint8 out[32], memory[96];

  ak_hash_context_create_streebog256( &ctx );
  ak_hash_context_file( &ctx, file, out );
  ak_ptr_to_hexstr_static( out, 32, memory, sizeof( memory ), ak_false );
  printf(" icode: %s (%s)\n\n", memory, file );
  ak_hash_context_destroy( &ctx );
}
