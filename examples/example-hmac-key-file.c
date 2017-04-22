 #include <stdio.h>
 #include <libakrypt.h>
 #include <ak_skey.h>

#ifndef _WIN32
  #include <errno.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <sys/stat.h>
  #include <sys/mman.h>
#endif

 ak_uint8 key[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
 };

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  size_t idx = 0, mbsize = 200;
  char *str= NULL;
  FILE *fp = NULL;
  ak_uint8 memory[1024];
  clock_t time = 0;

  ak_hmac_key hkey = NULL;
  ak_buffer result = NULL;

  ak_libakrypt_create( ak_function_log_stderr );

 /* Создаем файл для тестирования */
  fp = fopen( "file2", "rb" );
  if( fp == NULL ) {
    printf(" generation a %dMB file, wait a few seconds ... ", (int) mbsize ); fflush(stdout);
    fp = fopen("file2", "wb");
    for( idx = 0; idx < mbsize*1024; idx++ ) { // mbsize MB
       memset( memory, (ak_uint8)idx, 1024 );
       fwrite( memory, 1, 1024, fp );
    }
    fflush(fp);
  } else printf(" found file for testing with %dMB size\n", (int) mbsize );
  fclose(fp);
  printf("\n");

 /* Создаем ключ для вычислений */
  hkey = ak_hmac_key_new_ptr( ak_hash_new_streebog256(), key, 32 );

  time = clock();
  result = ak_hmac_key_file( hkey, "file2", NULL );
  time = clock() - time;

  printf("result:  %s\n", str = ak_buffer_to_hexstr( result )); free( str );
  printf("total time: %fs, per 1MB = %fs\n\n",
        (double) time / (double) CLOCKS_PER_SEC,
        (double) time / ( (double) CLOCKS_PER_SEC * mbsize ));
  result = ak_buffer_delete( result );

#ifndef _WIN32
  {
   int fd;
   struct stat st;
   ak_pointer addr = NULL;

     fd = open("file2", O_RDONLY | O_BINARY );
     fstat( fd, &st );
     addr = mmap( NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0 );

     time = clock();
     result = ak_hmac_key_data( hkey, addr, st.st_size, NULL );
     time = clock() - time;
     printf("result:  %s\n", str = ak_buffer_to_hexstr( result )); free( str );
     printf("total time: %fs, per 1MB = %fs\n\n",
           (double) time / (double) CLOCKS_PER_SEC,
           (double) time / ( (double) CLOCKS_PER_SEC * mbsize ));
     result = ak_buffer_delete( result );
     close(fd);
  }
#endif

  hkey = ak_hmac_key_delete( hkey );
 return ak_libakrypt_destroy();
}
