 #include <stdlib.h>
 #include <time.h>
 #include <string.h>
 #include <libakrypt.h>


 int main( int argc, char *argv[] )
{
  struct random generator;
  struct blomkey master;

  int i, j, k, error = ak_libakrypt_create( ak_function_log_stderr );

  ak_random_create_lcg( &generator );
  ak_blomkey_create_matrix( &master, 5, ak_galois256_size, &generator );

/* i - номера столбцов (второй индекс), j - номера строк  (первый индекс) */

  for( i = 0; i < master.size; i++ ) {
    for( j = 0; j < master.size; j++ ) {
       ak_uint64 *key = ak_blomkey_get_element_by_index( &master, i, j );
       printf("{a[%u,%u]: %016llx:%016llx:%016llx:%016llx}", i, j, key[0], key[1], key[2], key[3] );
    }
    printf("\n");
  }
  printf("\n");


  for( i = 0; i < master.size*master.size*master.qword_count; i++ ) {
     printf("%016llx ", master.data[i] );
     if(( i > 0 ) && ((i+1)%master.qword_count == 0 )) printf("\n");
  }
  printf("\n");

  printf("hash: %s\n", ak_ptr_to_hexstr( master.control, 32, ak_false ));

  ak_blomkey_destroy( &master );


  lab1:
    ak_random_destroy( &generator );
  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
