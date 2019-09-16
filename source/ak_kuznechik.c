/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_kuznechik.h                                                                            */
/*  - содержит реализацию алгоритма блочного шифрования Кузнечик,                                  */
/*    регламентированного ГОСТ Р 34.12-2015                                                        */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ---------------------------------------------------------------------------------------------- */
 #include <ak_hash.h>
 #include <ak_bckey.h>

/* ---------------------------------------------------------------------------------------------- */
 static struct kuznechik_params kuznechik_parameters;

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает два элемента конечного поля \f$\mathbb F_{2^8}\f$, определенного
     согласно ГОСТ Р 34.12-2015.                                                                  */
/* ---------------------------------------------------------------------------------------------- */
 static ak_uint8 ak_bckey_context_kuznechik_mul_gf256( ak_uint8 x, ak_uint8 y )
{
  ak_uint8 z = 0;
  while( y ) {
    if( y&0x1 ) z ^= x;
    x = ((ak_uint8)(x << 1)) ^ ( x & 0x80 ? 0xC3 : 0x00 );
    y >>= 1;
  }
 return z;
}

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция возводит квадратную матрицу в квадрат. */
/* ---------------------------------------------------------------------------------------------- */
 static void ak_bckey_context_kuznechik_square_matrix( linear_matrix a )
{
  linear_matrix c;

 /* умножаем */
  for( int i = 0; i < 16; i++ )
   for( int j = 0; j < 16; j++ ) {
      c[i][j] = 0;
      for( int k = 0; k < 16; k++ )
         c[i][j] ^= ak_bckey_context_kuznechik_mul_gf256( a[i][k], a[k][j] );
   }
 /* копируем */
  for( int i = 0; i < 16; i++ )
   for( int j = 0; j < 16; j++ ) a[i][j] = c[i][j];
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для заданного линейного регистра сдвига, задаваемого набором коэффициентов `reg`,
    функция вычисляет 16-ю степень сопровождающей матрицы.

    \param reg Набор коэффициентов, определябщих линейный регистр сдвига
    \param matrix Сопровождающая матрица
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_context_kuznechik_generate_matrix( const linear_register reg, linear_matrix matrix )
{
  size_t i = 0;

 /* создаем сопровождающую матрицу */
  memset( matrix, 0, sizeof( linear_matrix ));
  for( i = 1; i < 16; i++ ) matrix[i-1][i] = 0x1;
  for( i = 0; i < 16; i++ ) matrix[15][i] = reg[i];

 /* возводим сопровождающую матрицу в 16-ю степень */
  ak_bckey_context_kuznechik_square_matrix( matrix );
  ak_bckey_context_kuznechik_square_matrix( matrix );
  ak_bckey_context_kuznechik_square_matrix( matrix );
  ak_bckey_context_kuznechik_square_matrix( matrix );
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_context_kuznechik_invert_matrix( linear_matrix matrix, linear_matrix matrixinv )
{
  ak_uint8 i, j;
 /* некоторый фокус */
  for( i = 0; i < 16; i++ ) {
     for( j = 0; j < 16; j++ ) matrixinv[15-i][15-j] = matrix[i][j];
  }
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_context_kuznechik_invert_permutation( const sbox pi, sbox pinv )
{
  ak_uint32 idx = 0;
  for( idx = 0; idx < sizeof( sbox ); idx++ ) pinv[pi[idx]] = ( ak_uint8 )idx;
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_context_kuznechik_init_tables( const linear_register reg,
                                                           const sbox pi, ak_kuznechik_params par )
{
  int i, j, l;

 /* сохраняем необходимое */
  memcpy( par->reg, reg, sizeof( linear_register ));
  memcpy( par->pi, pi, sizeof( sbox ));

 /* вырабатываем матрицы */
  ak_bckey_context_kuznechik_generate_matrix( reg, par->L );
  ak_bckey_context_kuznechik_invert_matrix( par->L, par->Linv );

 /* обращаем таблицы замен */
  ak_bckey_context_kuznechik_invert_permutation( pi, par->pinv );

 /* теперь вырабатываем развернутые таблицы */
  for( i = 0; i < 16; i++ ) {
      for( j = 0; j < 256; j++ ) {
         ak_uint8 b[16], ib[16];
         for( l = 0; l < 16; l++ ) {
             b[l] = ak_bckey_context_kuznechik_mul_gf256( par->L[l][i], par->pi[j] );
            ib[l] = ak_bckey_context_kuznechik_mul_gf256( par->Linv[l][i], par->pinv[j] );
         }
         memcpy( par->enc[i][j], b, 16 );
         memcpy( par->dec[i][j], ib, 16 );
      }
  }
}

/* ----------------------------------------------------------------------------------------------- */
 void ak_bckey_context_kuznechik_init_gost_tables( void )
{
  int audit = ak_log_get_level();
  ak_bckey_context_kuznechik_init_tables( gost_lvec, gost_pi, &kuznechik_parameters );

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                              "generation of GOST R 34.12-2015 parameters is Ok" );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                      функции тестирования                                       */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_bckey_test_kuznechik_parameters( void )
{
  struct hash ctx;
  ak_uint8 out[16];
  char *str = NULL;
  struct kuznechik_params parameters;
  int error = ak_error_ok, audit = ak_log_get_level();

  ak_uint8 esum[16] = { 0x5B, 0x80, 0x54, 0xB3, 0x4E, 0x81, 0x09, 0x94,
                        0xCC, 0x83, 0x8B, 0x8E, 0x53, 0xBA, 0x9D, 0x18 };
  ak_uint8 dsum[16] = { 0xBF, 0x07, 0xDF, 0x13, 0x1E, 0x30, 0xCD, 0xA1,
                        0x26, 0x14, 0xBA, 0x2C, 0xFB, 0x28, 0xEC, 0xA3 };

 /* вырабатываем значения параметров */
  ak_bckey_context_kuznechik_init_tables( gost_lvec, gost_pi, &parameters );

 /* проверяем генерацию обратной перестановки */
  if( !ak_ptr_is_equal( gost_pinv, parameters.pinv, sizeof( sbox ))) {
    ak_error_message( ak_error_not_equal_data, __func__,
                                         "incorrect generation of nonlinear inverse permutation" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                                     "inverse permutation is Ok" );

 /* проверяем генерацию сопровождающей матрицы линейного регистра сдвига и обратной к ней */
  if( !ak_ptr_is_equal( gost_L, parameters.L, sizeof( linear_matrix ))) {
    size_t i = 0;
    ak_error_message( ak_error_not_equal_data, __func__,
                                              "incorrect generation of linear reccurence matrix" );
    ak_error_message( 0, __func__, "matrix:" );
    for( i = 0; i < 16; i++ ) {
      ak_error_message_fmt( 0, __func__,
        "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        parameters.L[i][0],  parameters.L[i][1],  parameters.L[i][2],  parameters.L[i][3],
        parameters.L[i][4],  parameters.L[i][5],  parameters.L[i][6],  parameters.L[i][7],
        parameters.L[i][8],  parameters.L[i][9],  parameters.L[i][10], parameters.L[i][11],
              parameters.L[i][12], parameters.L[i][13], parameters.L[i][14], parameters.L[i][15] );
    }
    return ak_false;
  }

  if( !ak_ptr_is_equal( gost_Linv, parameters.Linv, sizeof( linear_matrix ))) {
    size_t i = 0;
    ak_error_message( ak_error_not_equal_data, __func__,
                                              "incorrect generation inverse of companion matrix" );
    ak_error_message( 0, __func__, "inverse matrix:" );
    for( i = 0; i < 16; i++ ) {
      ak_error_message_fmt( 0, __func__,
        "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        parameters.Linv[i][0],  parameters.Linv[i][1],  parameters.Linv[i][2],
        parameters.Linv[i][3],  parameters.Linv[i][4],  parameters.Linv[i][5],
        parameters.Linv[i][6],  parameters.Linv[i][7],  parameters.Linv[i][8],
        parameters.Linv[i][9],  parameters.Linv[i][10], parameters.Linv[i][11],
        parameters.Linv[i][12], parameters.Linv[i][13], parameters.Linv[i][14],
                                                                          parameters.Linv[i][15] );
    }
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                       "companion matrix and it's inverse is Ok" );
 /* проверяем выработанные таблицы */
  if(( error = ak_hash_context_create_streebog256( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of hash function context" );
    return ak_false;
  }
  ak_hash_context_ptr( &ctx, parameters.enc, sizeof( expanded_table ), out, sizeof( out ));
  if( !ak_ptr_is_equal( out, esum, sizeof( out ))) {
    ak_hash_context_destroy( &ctx );
    ak_error_message( ak_error_not_equal_data, __func__,
                                                      "incorrect hash value of encryption table" );
    ak_error_message_fmt( 0, "", "%s (calculated value)",
                              str = ak_ptr_to_hexstr( out, sizeof( out ), ak_false )); free( str );
    ak_error_message_fmt( 0, "", "%s (predefined const)",
                            str = ak_ptr_to_hexstr( esum, sizeof( esum ), ak_false )); free( str );
    return ak_false;
  }

  ak_hash_context_ptr( &ctx, parameters.dec, sizeof( expanded_table ), out, sizeof( out ));
  if( !ak_ptr_is_equal( out, dsum, sizeof( out ))) {
    ak_hash_context_destroy( &ctx );
    ak_error_message( ak_error_not_equal_data, __func__,
                                                      "incorrect hash value of encryption table" );
    ak_error_message_fmt( 0, "", "%s (calculated value)",
                              str = ak_ptr_to_hexstr( out, sizeof( out ), ak_false )); free( str );
    ak_error_message_fmt( 0, "", "%s (predefined const)",
                            str = ak_ptr_to_hexstr( dsum, sizeof( dsum ), ak_false )); free( str );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                                   "expanded encryption/decryption tables is Ok" );
  ak_hash_context_destroy( &ctx );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_bckey_test_kuznechik( void )
{
  int audit = audit = ak_log_get_level();

 /* тестируем стандартные параметры алгоритма */
  if( !ak_bckey_test_kuznechik_parameters( )) {
    ak_error_message( ak_error_get_value(), __func__,
                             "incorrect testing of predefined parameters from GOST R 34.12-2015" );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                 "testing of predefined parameters from GOST R 34.12-2015 is Ok" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_kuznechik.c  */
/* ----------------------------------------------------------------------------------------------- */
