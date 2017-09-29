 #include <time.h>
 #include <libakrypt.h>

 int main( void )
{
 size_t idx = 0, mbsize = 200;
 char *str= NULL;
 FILE *fp = NULL;
 clock_t time = 0;
 ak_handle handle = ak_error_wrong_handle;

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

 /* 3. Прямой поиск: от OID к дескриптору функции хеширования */
  handle = ak_oid_find_by_engine( hmac_function );
  while( handle != ak_error_wrong_handle ) {
    if( ak_oid_get_mode( handle ) == algorithm ) {
      ak_buffer buff = NULL;
      ak_handle ctx_handle = ak_hmac_new_oid( handle );
      printf(" name: %s (%s)\n", ak_oid_get_name( handle ), ak_oid_get_id( handle ));

        /* устанавливаем фиксированный ключ */
         ak_hmac_set_password( ctx_handle, "password", 8, "initial vector", 14 );

        /* вычисляем имитовставку */
         time = clock();
         if(( buff = ak_hmac_file( ctx_handle, "data.dat", NULL )) == NULL ) goto while_exit;
         time = clock() - time;
             /* мы не знаем длину хешкода, */
             /* поэтому помещаем результат в динамический буффер */
         printf(" hmac: %s\n time: %fs, per 1MB = %fs\n\n", str = ak_buffer_to_hexstr( buff ),
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ));

         if( buff != NULL ) { free( str ); str = NULL; }
         buff = ak_buffer_delete( buff );

      while_exit: ak_handle_delete( ctx_handle );
    }
   /* ищем следующий OID с тем же типом криптографического механизма */
    handle = ak_oid_findnext_by_engine( handle, hmac_function );
  }

 return ak_libakrypt_destroy();
}
