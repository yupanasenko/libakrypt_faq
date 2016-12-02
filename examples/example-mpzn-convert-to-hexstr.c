 #include <libakrypt.h>
 #include <ak_mpzn.h>

 int main( void )
{
  int i = 0;
  ak_mpzn256 x;// = ak_mpzn256_zero;
  const char *s[4] = { "111",
                       "a7632457236452734aaed121",
                       "8009F186DB88559655ED5580333E4E36887A2BB76B1462F43B2B6DD1626C321",
                       "80009F186DB88559655ED5580333E4E36887A2BB76B1462F43B2B6DD1626C321"
                     };
 for( i = 0; i < 4; i++ ) {
    int res = ak_mpzn_set_hexstr( x, ak_mpzn256_size, s[i] );
    char *str = ak_mpzn_to_hexstr( x, ak_mpzn256_size );
    printf(" %s from %s (code: %d)\n", str, s[i], res );
    free( str );
 }

 return 0;
}
