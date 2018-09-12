 #include <libakrypt.h>

 int main( void )
{
 char *str = NULL;
 ak_handle handle_one; /* дескриптор первого генератора */
 ak_handle handle_two; /* дескриптор второго генератора */
 ak_uint8 data_one[256], data_two[256], iv[4] = { 0x11, 0xa2, 0x1f, 0x14 };

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* создаем первый генератор, инициализируем его и вырабатываем случайные значения */
  if(( handle_one = ak_random_new_lcg()) == ak_error_wrong_handle )
    return ak_libakrypt_destroy();

  ak_random_randomize( handle_one, iv, sizeof( iv ));
  ak_random_ptr( handle_one, data_one, 256 );
  printf("first (256 bytes):\n%s\n",
     str = ak_ptr_to_hexstr( data_one, 256, ak_false )); free( str ) ;

 /* создаем второй генератор, инициализируем его и вырабатываем случайные значения */
  if(( handle_two = ak_random_new_lcg()) == ak_error_wrong_handle )
    return ak_libakrypt_destroy();

  ak_random_randomize( handle_two, iv, sizeof( iv ));
  ak_random_ptr( handle_two, data_two, 256 );
  printf("second (256 bytes):\n%s\n",
     str = ak_ptr_to_hexstr( data_two, 256, ak_false )); free( str ) ;

 /* сравниваем данные */
  if( ak_ptr_is_equal( data_one, data_two, 256 ) ) printf("Ok\n");
    else printf("data is not equal\n");

 return ak_libakrypt_destroy();
}
