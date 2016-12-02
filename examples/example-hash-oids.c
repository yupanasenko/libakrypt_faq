 #include <time.h>
 #include <libakrypt.h>

 int main( void )
{
 size_t idx = 0, mbsize = 200;
 char *str= NULL;
 FILE *fp = NULL;
 ak_uint8 memory[1024];
 clock_t time = 0;

 /* 1. Инициализируем библиотеку */
 if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* 2. Создаем файл для тестирования */
 fp = fopen( "file2", "rb" );
 if( fp == NULL ) {
   printf(" generation a %ldMB file, wait a few seconds ... ", mbsize ); fflush(stdout);
   fp = fopen("file2", "wb");
   for( idx = 0; idx < mbsize*1024; idx++ ) { // mbsize MB
      memset( memory, (ak_uint8)idx, 1024 );
      fwrite( memory, 1, 1024, fp );
   }
   fflush(fp);
 } else printf(" found file for testing with %ldMB size\n", mbsize );
 fclose(fp);
 printf("\n");

 /* 3. Прямой поиск: от OID к контексту функции хеширования */
 for( idx = 0; idx < ak_oids_get_count(); idx++ ) {
   ak_oid oid = ak_oids_get_oid( idx );

   /* далее мы используем только engine = hash_functions && mode == algorithm */
   if(( ak_oid_get_engine( oid ) == hash_function) && (ak_oid_get_mode( oid ) == algorithm )) {
         ak_buffer buff = NULL;
         ak_hash ctx = ak_hash_new_oid( oid );
         printf(" name = %s [id = %s]\n", ak_oid_get_name( oid ), ak_oid_get_id( oid )); fflush( stdout );

         time = clock();
         if(( buff = ak_hash_file( ctx, "file2", NULL )) == NULL ) continue;
         time = clock() - time;
             /* мы не знаем длину хешкода, */
             /* поэтому помещаем результат в динамический буффер */
         str = ak_buffer_to_hexstr( buff );
         printf(" %s\n total time: %fs, per 1MB = %fs\n\n", str,
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ));

         /* чистим память */
         ctx = ak_hash_delete( ctx );
         buff = ak_buffer_delete( buff );
         if( str != NULL ) free( str );
   }
 }
 return ak_libakrypt_destroy();
}
