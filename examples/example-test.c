 #include <stdio.h>
 #include <libakrypt.h>


/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
 #include <time.h>



 int main( void )
{
 ak_libakrypt_create( ak_function_log_stderr );


// ak_uint64 y = 0xF000000000000011LL, x = 0x1aaabcda1115LL, z = 0, z1 = 0;

// do{
//    ak_gf64_mul_uint64( &z, &x, &y );
//    ak_gf64_mul_pcmulqdq( &z1, &x, &y );
//    //printf("x = %llx, y = %llx, z = %llx, z1 = %llx\n", x, y, z, z1 );
//    printf("%llx ~ %llx\n", z, z1 );

//    x = y; y = z; i--;
//  } while(( i > 0 ) && ( z == z1 ));
//  printf("end value of i: %d\n", i );


 return ak_libakrypt_destroy();
}
