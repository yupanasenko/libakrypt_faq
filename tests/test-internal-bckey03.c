/* Пример, иллюстрирующий скорость алгоритмов блочного шифрования.
   Используются неэкспортируемые функции библиотеки.

   test-internal-bckey03.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <sys/types.h>
 #include <ak_bckey.h>

 int main( void )
{
 size_t idx = 0, mbsize = 4;
 FILE *fp = NULL, *fq = NULL;
 clock_t time = 0;
 struct bckey key;
 int len = 0;
 ak_uint8 buffer[1024];
 ak_uint32 constkey[8] = {
  0x12345678, 0xabcdef0, 0x11223344, 0x55667788,
  0xaabbccdd, 0xeeff0011, 0xa1a1a2a2, 0xa3a3a4a4
 };

 /* 1. Инициализируем библиотеку */
 if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* 2. Создаем файл для тестирования */
 fp = fopen( "data.dat", "rb" );
 if( fp == NULL ) {
   ak_uint8 memory[1024];
   printf(" generation a %dMB file, wait a few seconds ... ", (int) mbsize ); fflush(stdout);
   fp = fopen("data.dat", "wb");
   for( idx = 0; idx < mbsize*1024; idx++ ) { // mbsize MB
      memset( memory, (ak_uint8)idx, 1024 );
      fwrite( memory, 1, 1024, fp );
   }
   fflush(fp);
 } else printf(" found file for testing with %dMB size\n", (int) mbsize );
 fclose(fp);
 printf("\n");

 /* ключ */
 ak_bckey_context_create_magma( &key );
 ak_bckey_context_set_key( &key, constkey, 32, ak_true );

 fp = fopen( "data.dat", "rb" );
 fq = fopen( "data.dat.enc.magma", "wb" );

 time = clock();
 len = fread( buffer, 1, 1024, fp );
 if( len > 0 ) {
   ak_bckey_context_xcrypt( &key, buffer, buffer, len, "12345678", 8 );
   fwrite( buffer, 1, len, fq );
 }
 do{
    if(( len = fread( buffer, 1, 1024, fp )) > 0 ) {
      ak_bckey_context_xcrypt( &key, buffer, buffer, len, NULL, 0 );
      fwrite( buffer, 1, len, fq );
    }
 } while( len );
 time = clock() - time;
 printf(" magma time: %fs, per 1MB = %fs, %f MBs\n\n",
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ), (double) CLOCKS_PER_SEC *mbsize / (double) time );

 fclose( fp );
 fclose( fq );
 ak_bckey_context_destroy( &key );

 return ak_libakrypt_destroy();
}

