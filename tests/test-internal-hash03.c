/*
   Пример, иллюстрирующий различные методы вычисления хэш-кода для заданного файла.
   В примере используются неэкспортируемые функции библиотеки

   test-internal-hash03.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_tools.h>
 #include <ak_random.h>
 #include <ak_mac.h>

#ifdef LIBAKRYPT_HAVE_SYSMMAN_H
 #include <sys/stat.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <sys/mman.h>
#endif

 int main( int argc, char *argv[] )
{
  size_t tail;
  struct hash ctx;
  struct mac ictx;
  struct file file;
  ak_uint8 out[128];
  ak_uint8 buffer[1024];
  struct random generator;
  int exitcode = EXIT_SUCCESS;

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( NULL ) != ak_true ) return ak_libakrypt_destroy();
  memset( out, 0, sizeof( out ));

  printf("we working with %s file\n", argv[0] );

 /* 1. хешируем файл как единый фрагмент данных (используя mmap) */
#ifdef LIBAKRYPT_HAVE_SYSMMAN_H
 {
   ak_uint8 *data = NULL;

   struct stat st;
   int fd = open( argv[0], O_RDONLY );

   fstat( fd, &st );
   data = mmap( NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0 );

  /* создаем контекст и, в случае успеха, сразу вычисляем значение кода целостности */
   if( ak_hash_context_create_streebog256( &ctx ) == ak_error_ok ) {
     ak_hash_context_ptr( &ctx, data, st.st_size, out );

    /* уничтожаем контекст функции хеширования */
     ak_hash_context_destroy( &ctx );
    /* выводим полученное значение */
     ak_ptr_to_hexstr_static( out, 32, buffer, 1024, ak_false );
     printf("mmap() + ak_hash_context_ptr()\nhash: %s\n\n", buffer );
   }

  /* создаем контекст функции итерационного сжатия */
   if( ak_mac_context_create_oid( &ictx, ak_oid_context_find_by_name("streebog256")) == ak_error_ok ) {
     ak_mac_context_ptr( &ictx, data, st.st_size, out );

    /* уничтожаем контекст функции итерационного сжатия */
     ak_mac_context_destroy( &ictx );
    /* выводим полученное значение */
     ak_ptr_to_hexstr_static( out, 32, buffer, 1024, ak_false );
     printf("mmap() + ak_mac_context_ptr()\nhash: %s\n\n", buffer );
   }

   munmap( data, st.st_size );
 }
#endif

 /* 2. хешируем файл, используя функции класса hash */
   ak_hash_context_create_streebog256( &ctx );
  /* хешируем вызовом всего одной функции */
   ak_hash_context_file( &ctx, argv[0], out+32 );
   ak_hash_context_destroy( &ctx );
  /* выводим полученное значение */
   ak_ptr_to_hexstr_static( out+32, 32, buffer, 1024, ak_false );
   printf("ak_hash_context_file()\nhash: %s\n\n", buffer );
  /* сравниваем полученные результаты */
#ifdef LIBAKRYPT_HAVE_SYSMMAN_H
   if( ak_ptr_is_equal( out, out+32, 32 ) != ak_true ) {
     ak_ptr_to_hexstr_static( out, 128, buffer, 1024, ak_false );
     printf("out:  %s\n", buffer );
     exitcode = EXIT_FAILURE;
   }
#endif

 /* 3. хешируем файл, используя функции класса mac */
   ak_mac_context_create_oid( &ictx, ak_oid_context_find_by_name("streebog256"));
  /* хешируем вызовом всего одной функции */
   ak_mac_context_file( &ictx, argv[0], out+64 );
   ak_mac_context_destroy( &ictx );
  /* выводим полученное значение */
   ak_ptr_to_hexstr_static( out+64, 32, buffer, 1024, ak_false );
   printf("ak_mac_context_file()\nhash: %s\n\n", buffer );
  /* сравниваем полученные результаты */
  /* сравниваем полученные результаты */
   if( ak_ptr_is_equal( out+32, out+64, 32 ) != ak_true ) {
     ak_ptr_to_hexstr_static( out, 128, buffer, 1024, ak_false );
     printf("out:  %s\n", buffer );
     exitcode = EXIT_FAILURE;
   }

 /* 4. хешируем файл, используя фрагменты случайной длины,
       меньшей чем длина обрабатываемого блока */
   ak_random_context_create_lcg( &generator );     /* создаем генератор псевдослучайных чисел */
   ak_mac_context_create_oid( &ictx, ak_oid_context_find_by_name( "streebog256" ));
   ak_mac_context_clean( &ictx );
   if( ak_file_open_to_read( &file, argv[0] ) == ak_error_ok ) {
     tail = file.size; /* текущее значение остатка длины файла */
     while( tail > ctx.bsize ) {
        size_t len, value = 0;
        generator.random( &generator, &value, sizeof( size_t ));
        value = ak_min( tail, value%256 );
        if(( len = fread( buffer, 1, value, file.fp )) != value ) printf("read error\n");
        ak_mac_context_update( &ictx, buffer, value );
      tail -= value;
     }
     ak_mac_context_finalize( &ictx, NULL, 0, out+96 );
     ak_file_close( &file );
   }
   ak_mac_context_destroy( &ictx );
   ak_random_context_destroy( &generator );
  /* выводим полученное значение */
   ak_ptr_to_hexstr_static( out+96, 32, buffer, 1024, ak_false );
   printf("fragments of small random length + ak_mac_context_update()\nhash: %s\n\n", buffer );
  /* сравниваем полученные результаты */
   if( ak_ptr_is_equal( out+64, out+96, 32 ) != ak_true ) {
     ak_ptr_to_hexstr_static( out, 128, buffer, 1024, ak_false );
     printf("out:  %s\n", buffer );
     exitcode = EXIT_FAILURE;
   }

   printf("all results was calculated for %s file (%lu bytes)\n",
                                             argv[0], (unsigned long int) file.size );
 /* останавливаем библиотеку и выходим */
   ak_libakrypt_destroy();
 return exitcode;
}
