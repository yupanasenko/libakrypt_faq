/* Пример, иллюстрирующий функции преобразования вычетов к разлисным форматам данных.

   Внимание! Используются не экспортируемые функции.

   test-internal-mpzn01.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>

 #include <ak_mpzn.h>

 int main( void )
{
  int i = 0;
  char s[1024];
  ak_uint8 buffer[64];
  ak_mpzn256 x = { 0xaLL, 0xbLL, 0xcLL, 0xdLL };
  ak_mpzn256 y = { 0x10000000000aLL, 0x10000000000bLL, 0x10000000000cLL, 0x10000000000dLL };
  ak_mpzn512 z = ak_mpzn512_zero;

  printf("x as uint64: ");
  for( i = 0; i < ak_mpzn256_size; i++ ) printf(" %llu", x[i] );
  printf("\n");

  ak_ptr_to_hexstr_static( x, 32, s, sizeof( s ), ak_false );
  printf("x as str: %s (using ak_ptr_to_hexstr_static)\n", s );
  ak_mpzn_to_hexstr_static( x, ak_mpzn256_size, s, sizeof( s ));
  printf("x as str: %s (using ak_mpzn_to_hexstr_static)\n", s );

 /* преобразуем в little endian последовательность октетов и обратно */
  printf("  octets: " );
  ak_mpzn_to_little_endian( x, ak_mpzn256_size, buffer, sizeof( buffer ), ak_false );
  for( int i = 0; i < 32; i++ ) printf("%02X ", buffer[i] );
  printf("(little endian): ");
  ak_mpzn_set_little_endian( x, ak_mpzn256_size, buffer, 32, ak_false );
  for( i = 0; i < ak_mpzn256_size; i++ ) printf(" %llu", x[i] );
  printf("\n");

  printf("  octets: " );
  ak_mpzn_to_little_endian( x, ak_mpzn256_size, buffer, sizeof( buffer ), ak_true );
  for( int i = 0; i < 32; i++ ) printf("%02X ", buffer[i] );
  printf("(big endian): ");
  ak_mpzn_set_little_endian( x, ak_mpzn256_size, buffer, 32, ak_true );
  for( i = 0; i < ak_mpzn256_size; i++ ) printf(" %llu", x[i] );
  printf("\n\n");



  printf("y as uint64: ");
  for( i = 0; i < ak_mpzn256_size; i++ ) printf(" %llu", y[i] );
  printf("\n");

  ak_ptr_to_hexstr_static( y, 32, s, sizeof( s ), ak_false );
  printf("y as str: %s (using ak_ptr_to_hexstr_static)\n", s );
  ak_mpzn_to_hexstr_static( y, ak_mpzn256_size, s, sizeof( s ));
  printf("y as str: %s (using ak_mpzn_to_hexstr_static)\n", s );

  printf("  octets: " );
  ak_mpzn_to_little_endian( y, ak_mpzn256_size, buffer, sizeof( buffer ), ak_false );
  for( int i = 0; i < 32; i++ ) printf("%02X ", buffer[i] );
  printf("(little endian)\n");
  ak_mpzn_set_little_endian( y, ak_mpzn256_size, buffer, 32, ak_false ); /* преобразуем обратно */

  printf("  octets: " );
  ak_mpzn_to_little_endian( y, ak_mpzn256_size, buffer, sizeof( buffer ), ak_true );
  for( int i = 0; i < 32; i++ ) printf("%02X ", buffer[i] );
  printf("(big endian)\n\n");
  ak_mpzn_set_little_endian( y, ak_mpzn256_size, buffer, 32, ak_true ); /* преобразуем обратно */


  ak_mpzn_mul( z, x, y, ak_mpzn256_size );
  printf("z as uint64: ");
  for( i = 0; i < ak_mpzn512_size; i++ ) printf(" %llu", z[i] );
  printf("\n");

  ak_ptr_to_hexstr_static( z, 64, s, sizeof( s ), ak_false );
  printf("z as str: %s (using ak_ptr_to_hexstr_static)\n", s );
  ak_mpzn_to_hexstr_static( z, ak_mpzn512_size, s, sizeof( s ));
  printf("z as str: %s (using ak_mpzn_to_hexstr_static)\n", s );

  printf("  octets: " );
  ak_mpzn_to_little_endian( z, ak_mpzn512_size, buffer, sizeof( buffer ), ak_false );
  for( int i = 0; i < 64; i++ ) printf("%02X ", buffer[i] );
  printf("(little endian)\n");
  ak_mpzn_set_little_endian( z, ak_mpzn512_size, buffer, 64, ak_false ); /* преобразуем обратно */

  printf("  octets: " );
  ak_mpzn_to_little_endian( z, ak_mpzn512_size, buffer, sizeof( buffer ), ak_true );
  for( int i = 0; i < 64; i++ ) printf("%02X ", buffer[i] );
  printf("(big endian)\n\n");

  if( strncmp( s, "00000000000000000000D000000000A9000190000000013800024000000001AE0002E0000000020C000210000000016900015000000000DC0000A00000000064", 128 ) == 0 )
    printf("Ok\n");
   else { printf("Wrong\n"); return EXIT_FAILURE; }

 return EXIT_SUCCESS;
}
