 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>


 int main( void )
{
  ak_uint32 i, j;
  struct random generator;
  struct hmac oneKey, twoKey;
  int exitcode = EXIT_FAILURE;
  struct blomkey master, abonent_one, abonent_two;
  char *oneID = "very long identifier of abonent N1";
  char *twoID = "N2";
  ak_uint8 onehmac[64], twohmac[64];

  ak_libakrypt_create( ak_function_log_stderr );
  ak_random_create_lcg( &generator );
  ak_blomkey_create_matrix( &master, 5, ak_galois512_size, &generator );

 /* вывод ключевой информации */
  printf("matrix (%u bytes):\n", master.size*master.size*master.count );
  for( i = 0; i < master.size; i++ ) {
    for( j = 0; j < master.size; j++ ) {
       printf("a[%u,%u]: %s\n", i, j, ak_ptr_to_hexstr(
                       ak_blomkey_get_element_by_index( &master, i, j ), master.count, ak_false ));
    }
    printf("\n");
  }
  printf("\n");

 /* вычисляем ключи абонентов */
  ak_blomkey_create_abonent_key( &abonent_one, &master, oneID, strlen( oneID ));
  printf("abonent one:\n");
  for( i = 0, j = 0; i < master.size; i++ ) {
     printf("a[%u,%u]: %s\n", i, j, ak_ptr_to_hexstr(
                  ak_blomkey_get_element_by_index( &abonent_one, i, j ), master.count, ak_false ));
  }
  printf("\n");

  ak_blomkey_create_abonent_key( &abonent_two, &master, twoID, strlen( twoID ));
  printf("abonent two:\n");
  for( i = 0, j = 0; i < master.size; i++ ) {
     printf("a[%u,%u]: %s\n", i, j, ak_ptr_to_hexstr(
                  ak_blomkey_get_element_by_index( &abonent_two, i, j ), master.count, ak_false ));
  }
  printf("\n");

 /* вычисляем ключи парной связи и проверяем, что они совпадают */
  ak_blomkey_create_pairwise_key( &abonent_one, twoID, strlen( twoID ),
                                               &oneKey, ak_oid_find_by_name( "hmac-streebog512" ));
  ak_hmac_ptr( &oneKey, "make love not war", 16, onehmac, sizeof( onehmac ));

  ak_blomkey_create_pairwise_key( &abonent_two, oneID, strlen( oneID ),
                                               &twoKey, ak_oid_find_by_name( "hmac-streebog512" ));
  ak_hmac_ptr( &twoKey, "make love not war", 16, twohmac, sizeof( twohmac ));
  if( ak_ptr_is_equal( onehmac, twohmac, sizeof( onehmac ))) {
    printf("All keys Ok\n");
    exitcode = EXIT_SUCCESS;
  } else printf("Something wrong with generated keys.... \n");

  ak_hmac_destroy( &oneKey );
  ak_hmac_destroy( &twoKey );
  ak_blomkey_destroy( &abonent_one );
  ak_blomkey_destroy( &abonent_two );
  ak_blomkey_destroy( &master );
  ak_random_destroy( &generator );
  ak_libakrypt_destroy();

 return exitcode;
}
