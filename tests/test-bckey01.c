 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_bckey.h>



 int main( void )
{
 size_t i, j;
 linear_matrix D;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

  ak_bckey_test_kuznechik();

  ak_bckey_context_kuznechik_generate_matrix( gost_lvec, D );
  if( ak_ptr_is_equal( gost_L, D, sizeof( linear_matrix ))) printf("matrix Ok");
    else printf("matrix Wrong\n");

 printf("D:\n");
 for(i = 0; i < 16; i++ ) {
   for( j = 0; j < 16; j++ ) {
     printf("%02x ", D[i][j] );
   }
   printf("\n");
 }

 return ak_libakrypt_destroy();
}
