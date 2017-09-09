/* ----------------------------------------------------------------------------------------------- *
   Пример, иллюстрирующий разные методы вычисления хешкода от заданного файла.
   Внимание: используются неэкспортируемые функции библиотеки

 * ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_SYSMMAN_H
 #include <sys/mman.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSTAT_H
 #include <sys/stat.h>
#endif
#ifdef LIBAKRYPT_HAVE_FCNTL_H
 #include <fcntl.h>
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <libakrypt.h>
 #include <ak_compress.h>

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  int fd = 0;
  size_t i = 0;
  FILE *fp = NULL;
  ak_uint8 buffer[1024];
  struct hash ctx;
  struct compress comp;
  ak_uint8 out[32];
  char *str = NULL;

#ifndef LIBAKRYPT_HAVE_FCNTL_H
  printf("this test runs only in POSIX system\n"); return 0;
#endif
#ifndef LIBAKRYPT_HAVE_UNISTD_H
  printf("this test runs only in POSIX system\n"); return 0;
#endif
#ifndef LIBAKRYPT_HAVE_SYSMMAN_H
  printf("this test runs only in POSIX system\n"); return 0;
#endif
#ifndef LIBAKRYPT_HAVE_SYSSTAT_H
  printf("this test runs only in POSIX system\n"); return 0;
#endif

 /* 1. создаем файл, который в последствии будем хешировать */
  memset( buffer, 1, 1024 ); /* инициализируем буффер и многократно сохраняем его */
  buffer[0] = 'k'; buffer[1023] = 'a';
  if(( fp = fopen("data64.dat", "wb" )) == NULL ) return EXIT_FAILURE;
  for( i = 0; i < 64*1024; i++ ) fwrite( buffer, 1024, 1, fp );
  fclose(fp);
  printf("data64.dat file created\n");

 /* 2. инициализируем библиотеку */
  if( ak_libakrypt_create( NULL ) != ak_true ) return ak_libakrypt_destroy();

 /* 3. хешируем файл как единый массив данных */
#ifdef LIBAKRYPT_HAVE_SYSMMAN_H
   if(( fd = open( "data64.dat", O_RDONLY | O_BINARY )) < 0 ) return ak_libakrypt_destroy();

   if( ak_hash_create_streebog256( &ctx ) == ak_error_ok ) {
     struct stat st;
     fstat( fd, &st );
     ak_uint8 *data = mmap( NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0 );
     ak_hash_dataptr( &ctx, data, st.st_size, out );
     munmap( data, st.st_size );
   }
   ak_hash_destroy( &ctx ); /* уничтожаем контекст функции хеширования */
   close(fd);
   printf("hash: %s (using mmap)\n", str = ak_ptr_to_hexstr( out, 32, ak_false ));
   free( str );
#endif

 /* 4. хешируем, используя функцию класса compress */
   ak_hash_create_streebog256( &ctx );
   ak_compress_create_hash( &comp, &ctx );
   ak_compress_file( &comp, "data64.dat", out );
   ak_compress_destroy( &comp );
   ak_hash_destroy( &ctx );
   printf("hash: %s (using ak_compress_file)\n", str = ak_ptr_to_hexstr( out, 32, ak_false ));
   free( str );

 /* 5. хешируем, используя функцию класса hash */
   ak_hash_create_streebog256( &ctx );
   ak_hash_datafile( &ctx, "data64.dat", out );
   ak_hash_destroy( &ctx );
   printf("hash: %s (using ak_hash_file)\n", str = ak_ptr_to_hexstr( out, 32, ak_false ));
   free( str );

 return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}
