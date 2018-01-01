/* ----------------------------------------------------------------------------------------------- *
   Пример, иллюстрирующий различные походы к гаммированию данных при помощи
   функций ak_bckey_context_xcrypt() и ak_bckey_context_xcrypt_update()
   Внимание: используются неэкспортируемые функции библиотеки

 * ----------------------------------------------------------------------------------------------- */
#include <stdio.h>
#include <ak_bckey.h>

#define len (131)

/* ----------------------------------------------------------------------------------------------- */
 void print_array( unsigned char *a, size_t size );

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
 int i = 0;
 struct bckey xkey;
 unsigned char array[len], iv[4] = { 0, 1, 2, 3 };

 /* инициализируем библиотеку и устанавливаем какое-то значение ключа */
  ak_libakrypt_create( ak_function_log_stderr );
  ak_bckey_create_magma( &xkey );
  ak_bckey_context_set_ptr( &xkey, "12345678901234567890123456789012", 32, ak_true );

 /* инициализируем массивы какими-то данными */
  for( i = 0; i < len; i++ ) array[i] = (char)(i);

 /* 1. Вначале, зашифровываем и расшифровываем данные произвольной длины */
  printf("The first method for whole text\n");
  printf("array xcrypt() encrypt: %d\n",
    ak_bckey_context_xcrypt( &xkey, array, array, len, iv, sizeof(iv)));
  print_array( array, len );

  printf("array xcrypt() decrypt: %d\n",
    ak_bckey_context_xcrypt( &xkey, array, array, len, iv, sizeof(iv)));
  print_array( array, len );

 /* 2. Теперь с xcrypt_update() зашифровываем и расшифровываем */
  printf("The second method for small parts\n");
  printf("array xcrypt_update() encrypt: %d ",
    ak_bckey_context_xcrypt( &xkey, array, array, 32, iv, sizeof(iv))); /* первый фрагмент */
  for( i = 0; i < 3; i++ ) printf("%d ", /* второй - четвертый фрагменты */
    ak_bckey_context_xcrypt_update( &xkey, array+32*(i+1), array+32*(i+1), 32 ));
  /* оставшиеся три байта */
  printf("%d\n", ak_bckey_context_xcrypt_update( &xkey, array+128, array+128, 3 ));
  print_array( array, len );

  /* используем другой размер разбиения, но главное, чтобы кратный длине блока (для Магмы 8 байт) */
  printf("array xcrypt_update() decrypt: %d ",
    ak_bckey_context_xcrypt( &xkey, array, array, 16, iv, sizeof(iv))); /* первый фрагмент */
  for( i = 0; i < 7; i++ ) printf("%d ", /* еще семь фрагментов */
    ak_bckey_context_xcrypt_update( &xkey, array+16*(i+1), array+16*(i+1), 16 ));
  printf("%d\n", ak_bckey_context_xcrypt_update( &xkey, array+128, array+128, 11 ));
  print_array( array, len );

 /* осовобождаем ключ и останавливаем библиотеку */
  ak_bckey_destroy( &xkey );
 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
 void print_array( unsigned char *a, size_t size )
{
 int i = 0;
 for( i = 0; i < size; i++ ) {
     if( i ) { if(i%32 == 0 ) printf("\n"); }
     printf("%02x", a[i]);
 } printf("\n\n");
}
