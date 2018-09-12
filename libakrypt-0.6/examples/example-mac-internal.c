/* ----------------------------------------------------------------------------------------------- *
   Пример иллюстрирует создание ключей нескольких различных алгоритмов выработки имитовставки
   и их применение для вычисления кода аутентичности произвольной последовательности.
   Внимание: используются неэкспортируемые функции.                                                */
/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <ak_mac.h>
 #include <ak_compress.h>

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  int i = 0;
  unsigned int len = 0;
  ak_uint8 memory[256], hexstr[512]; /* массив для хранения временных значений */
  struct compress comp; /* структура для итерактивного вычисления имитовставки */
  struct random generator; /* генератор псевдослучайного шума */
  struct mac mac;

 /* 1. инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* 2. инициализируем генератор и выводим последовательность */
  ak_random_create_lcg( &generator );
  generator.randomize_ptr( &generator, "hello max", 9 );
  for( i = 0; i < 10; i++ ) {
     generator.random( &generator, &len, 1 ); len >>= 1;
     generator.random( &generator, memory, len );
    /* выводим награбленное */
     ak_ptr_to_hexstr_static( memory, len, hexstr, 512, ak_false );
     printf( "%02d: %s (%u)\n", i, hexstr, len );
  }
  printf("\n");

  /* 3. теперь вычисляем имитовставку
     - создаем контекст ключа и присваиваем ему значение */
   ak_mac_create_hmac_streebog256( &mac );
   ak_mac_context_set_password( &mac, "pass", 4, "salt", 4 );
  /* - инициализируем структуру итеративного сжатия */
/*ak_mac_init(ctx,type,pass,passlen,salt,saltlen(=)*/
   ak_compress_create_mac( &comp, &mac );
   ak_compress_clean( &comp );
  /* - повторяем генерацию последовательности и вычисляем имитовставку */
   generator.randomize_ptr( &generator, "hello max", 9 );
   for( i = 0; i < 10; i++ ) {
      generator.random( &generator, &len, 1 ); len >>= 1;
      generator.random( &generator, memory, len );
      ak_compress_update( &comp, memory, len );
   }
   /* - завершаем обработку входных данных */
   ak_compress_finalize( &comp, NULL, 0, memory );
   ak_ptr_to_hexstr_static( memory, comp.hsize, hexstr, 512, ak_false );
   printf( "%s: %s (%lu)\n", ak_mac_context_get_oid( &mac )->name, hexstr, comp.hsize );

   ak_compress_destroy( &comp );
   ak_mac_destroy( &mac );
   ak_random_destroy( &generator );

 return ak_libakrypt_destroy();
}
