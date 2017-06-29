 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
  ak_key key;
  FILE *fp = NULL, *fw = NULL;
  char keystr[32];
  clock_t time = 0;
  ak_uint8 memory[1024],
           iv[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                      0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
  size_t idx = 0, mbsize = 200, blocks = 128;

 /* 1. Инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* 2. Создаем файл для тестирования */
  if(( fp = fopen( "file2", "rb" ) ) == NULL ) {
    printf("generation a %dMB file, wait a few seconds ... ", (int) mbsize ); fflush(stdout);
    fp = fopen("file2", "wb");
    for( idx = 0; idx < mbsize*1024; idx++ ) { // mbsize MB
       memset( memory, (ak_uint8)idx, 1024 );
       fwrite( memory, 1, 1024, fp );
    }
    fflush(fp);
    printf("Ok\n");
  } else printf("found \"file2\" for testing with %dMB size\n", (int) mbsize );
  fclose(fp);
  printf("\n");

 /* 3. Прямой поиск алгоритма блочного шифрования по его OID */
 for( idx = 0; idx < ak_oids_get_count(); idx++ ) {
   ak_oid oid = ak_oids_get_oid( idx );

   /* далее мы используем только engine = block_cipher && mode == algorithm */
   if(( ak_oid_get_engine( oid ) == block_cipher ) && (ak_oid_get_mode( oid ) == algorithm )) {
     printf("found algorithm: %s [OID: %s]\n", ak_oid_get_name( oid ), ak_oid_get_id( oid ));
     ak_snprintf( keystr, 32, "my random %s key", ak_oid_get_name( oid ));

     printf("creating a key ... "); fflush( stdout );
     if(( key = ak_key_new_oid_random( oid,
                                 ak_buffer_new_str( keystr ))) == ak_error_wrong_key ) continue;
     else printf("Ok\n");
     printf("\tnumber: %s\n", ak_buffer_get_str( ak_key_get_number( key )));
     if(( oid = ak_key_get_oid( key )) != NULL )
       printf("\tengine: %s (%s)\n", ak_oid_get_engine_str( oid ), ak_oid_get_name( oid ));
     printf("\tdescription: %s\n", ak_buffer_get_str(ak_key_get_description( key )));

    /* только сейчас начинается процесс зашифрования файла */
    /* fp = fopen("file2", "rb");
     fw = fopen("file2.dat.enc", "wb" );

     fread( memory, 1, 1024, fp );
     ak_key_xcrypt( key, memory, memory, 1024, iv );
     fwrite( memory, 1, 1024, fw );
     blocks = 64;
     while( !feof(fp) )
    {
      fread( memory, 1, 1024, fp );
      if( ak_key_xcrypt_update( key, memory, memory, 1024 ) != ak_error_ok ) break;
      fwrite( memory, 1, 1024, fw );
      blocks += 64;
    }
     fclose( fp );
     fclose( fw );
     */
     printf("\n");
   }
 }

 return ak_libakrypt_destroy();
}
