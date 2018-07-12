/*
   Пример, иллюстрирующий различные методы вычисления кода цеклостности (хэш-кода)
   для заданного файла.
   В примере используются неэкспортируемые функции библиотеки

   test-internal-hash03.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_tools.h>
 #include <ak_random.h>
 #include <ak_compress.h>

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
  struct file file;
  ak_uint8 out[128];
  struct compress comp;
  ak_uint8 buffer[1024];
  struct random generator;
  int exitcode = EXIT_SUCCESS;

 /* 2. инициализируем библиотеку */
  if( ak_libakrypt_create( NULL ) != ak_true ) return ak_libakrypt_destroy();
  memset( out, 0, sizeof( out ));

 /* 3. хешируем файл как единый фрагмент данных (используя mmap) */
#ifdef LIBAKRYPT_HAVE_SYSMMAN_H
 {
   ak_uint8 *data = NULL;

   ak_file_is_exist( &file, argv[0], ak_false );
   data = mmap( NULL, file.st.st_size, PROT_READ, MAP_SHARED, file.fd, 0 );

  /* создаем контекст и, в случае успеха, сразу вычисляем значение кода целостности */
   if( ak_hash_context_create_streebog256( &ctx ) == ak_error_ok ) {
     ak_hash_context_ptr( &ctx, data, file.st.st_size, out );

    /* уничтожаем контекст функции хеширования */
     ak_hash_context_destroy( &ctx );
    /* выводим полученное значение */
     ak_ptr_to_hexstr_static( out, 32, buffer, 1024, ak_false );
     printf("mmap() + ak_hash_context_ptr()\nhash: %s\n\n", buffer );
   }

   munmap( data, file.st.st_size );
   ak_file_close( &file );
 }
#endif

 /* 4. хешируем файл, используя функции класса hash */
   ak_hash_context_create_streebog256( &ctx );
  /* хешируем вызовом всего одной функции */
   ak_hash_context_file( &ctx, argv[0], out+32 );
   ak_hash_context_destroy( &ctx );
  /* выводим полученное значение */
   ak_ptr_to_hexstr_static( out+32, 32, buffer, 1024, ak_false );
   printf("ak_hash_context_file()\nhash: %s\n\n", buffer );
  /* сравниваем полученные результаты */
   if( ak_ptr_is_equal( out, out+32, 32 ) != ak_true ) {
     ak_ptr_to_hexstr_static( out, 128, buffer, 1024, ak_false );
     printf("out:  %s\n", buffer );
     exitcode = EXIT_FAILURE;
   }

 /* 5. хешируем файл, используя функцию класса compress (итеративного сжимающего отображения) */
   ak_hash_context_create_streebog256( &ctx );
   ak_compress_context_create_hash( &comp, &ctx ); /* создаем объект, связанный с функцией хеширования */
  /* хешируем данные */
   ak_compress_context_file( &comp, argv[0], out+64 );
   ak_compress_context_destroy( &comp );
   ak_hash_context_destroy( &ctx );
  /* выводим полученное значение */
   ak_ptr_to_hexstr_static( out+64, 32, buffer, 1024, ak_false );
   printf("ak_compress_file()\nhash: %s\n\n", buffer );
  /* сравниваем полученные результаты */
   if( ak_ptr_is_equal( out, out+64, 32 ) != ak_true ) {
     ak_ptr_to_hexstr_static( out, 128, buffer, 1024, ak_false );
     printf("out:  %s\n", buffer );
     exitcode = EXIT_FAILURE;
   }

 /* 6. хешируем, используя фрагменты случайной длины, меньшей чем длина обрабатываемого блока */
   ak_random_context_create_lcg( &generator );     /* создаем генератор псевдослучайных чисел */
   ak_hash_context_create_streebog256( &ctx );     /* создаем контекст функции хеширования */
   ak_compress_context_create_hash( &comp, &ctx ); /* создаем контекст сжимающего отображения */

   ak_file_is_exist( &file, argv[0], ak_false );
   ak_compress_context_clean( &comp ); /* очищаем контекст структуры сжатия данных */

   tail = file.st.st_size;
   while( tail > ctx.bsize ) {
     size_t value; /* случайное смещение по файлу */
     generator.random( &generator, &value, sizeof( size_t ));
     value %= ctx.bsize;

     read( file.fd, buffer, value );
     ak_compress_context_update( &comp, buffer, value );
     tail -= value;
   }
   read( file.fd, buffer, tail );
   ak_compress_context_finalize( &comp, buffer, tail, out+96 );
   ak_random_context_destroy( &generator );
   ak_compress_context_destroy( &comp );
   ak_hash_context_destroy( &ctx );
  /* выводим полученное значение */
   ak_ptr_to_hexstr_static( out+96, 32, buffer, 1024, ak_false );
   printf("fragments of small random length + ak_compress_update()\nhash: %s\n\n", buffer );
  /* сравниваем полученные результаты */
   if( ak_ptr_is_equal( out, out+96, 32 ) != ak_true ) {
     ak_ptr_to_hexstr_static( out, 128, buffer, 1024, ak_false );
     printf("out:  %s\n", buffer );
     exitcode = EXIT_FAILURE;
   }

   printf("all results was taken for %s file (%lu bytes)\n",
                                             argv[0], (unsigned long int) file.st.st_size );
   ak_file_close( &file );

 /* останавливаем библиотеку и выходим */
   ak_libakrypt_destroy();
 return exitcode;
}
