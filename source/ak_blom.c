/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_blom.с                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/*! Схема Блома представляет собой механизм выработки секретных симметричных ключей,
    предоставляющий действенную альтернативу инфрастуктуре открытых ключей.

    Мастер ключ в схеме Блома это симметричная матрица
           row
         ------->
         |
  column |   a_{i,j} = a_{j,i}
         v

   ключ клиента (столбец, каждая коордиата которого сумма по строке)
   ключ сервера (строка, каждая координата сумма по столбцам)


    Ключ клиентаи ключ сервера
    Общий ключ парной связи

    */

/* ----------------------------------------------------------------------------------------------- */
/*! В ходе своего выполнения функция вырабатывает симметричную матрицу,
    состоящую из (`size`)x(`size`) элементов конечного поля \f$ GF(2^n)\f$, где `n` это количество
    бит в `count` 64-х битных словах. Например, для поля \f$ GF(2^{256})\f$ величина `count` должна
    принимать значение 4.

    \param bkey указатель на контекст мастер-ключа
    \param size размер матрицы
    \param count размер, в 64-х битных словах, одного элемента конечного поля.
    \param generator указатель на контекст генератора случайных значений.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_create_matrix( ak_blomkey bkey, const ak_uint32 size,
                                                      const ak_uint32 count, ak_random generator )
{
  struct hash ctx;
  int error = ak_error_ok;
  ak_uint32 column = 0, row = 0;
  size_t memsize = size*size*count*sizeof( ak_uint64 );

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to blom matrix" );
  if( size > 4096 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                          "using very huge size for blom matrix" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__, "using zero field size" );

  bkey->type = blom_matrix_key;
  bkey->qword_count = count;
  bkey->size = size;
  bkey->data = malloc( size*size*count*sizeof( ak_uint64 ));
  if( bkey->data == NULL ) return ak_error_message( ak_error_out_of_memory, __func__,
                                                                   "incorrect memory allocation" );
 /* Мастер ключ в схеме Блома это симметричная матрица

           row
         ------->
         |
  column |   a_{i,j} = a_{j,i}, где a_{i,j} элемент поля GF(2^256)
         v                                                          */

  memset( bkey->data, 0, memsize );
  for( column = 0; column < size; column++ ) {
    /* копируем созданное ранее */
     for( row = 0; row < column; row++ ) memcpy( bkey->data + column*count*size+row*count,
                  ak_blomkey_get_element_by_index( bkey, row, column ), count*sizeof( ak_uint64 ));
    /* создаем новое */
     ak_random_ptr( generator, bkey->data+column*count*(size+1),
                                                      ( size - column )*count*sizeof( ak_uint64 ));
  }
  if(( error = ak_hash_create_streebog256( &ctx )) != ak_error_ok ) {
    ak_blomkey_destroy( bkey );
    return ak_error_message( error, __func__, "incorrect creation of hash function context" );
  }
  if(( error = ak_hash_ptr( &ctx, bkey->data, memsize,
                                  bkey->control, 32 )) != ak_error_ok ) ak_blomkey_destroy( bkey );
  ak_hash_destroy( &ctx );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param bkey указатель на контекст мастер-ключа или ключа-строки (ключа-столбца)
    \param row номер строки
    \param column номер столбца
    \return В случае успеха, функция возвращает указатель на область памяти,
    первые `bkey.qword_count` 64-х битных слов дают искомый элемент. В случае возникновения
    ошибки возвращается `NULL`.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint64 *ak_blomkey_get_element_by_index( ak_blomkey bkey, const ak_uint32 row,
                                                                          const ak_uint32 column )
{
  if( bkey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to blom matrix " );
    return NULL;
  }
  if(( row >= bkey->size ) || ( column >= bkey->size )) {
    ak_error_message( ak_error_wrong_index, __func__, "parameter is very large" );
    return NULL;
  }
  switch( bkey->type ) {
   case blom_matrix_key: return bkey->data + (bkey->size*row + column)*bkey->qword_count;
   case blom_client_column_key:
   case blom_server_row_key:
   default:
     ak_error_message_fmt( ak_error_undefined_value, __func__ ,
                                                "incorrect type of blom matrix (%u)", bkey->type );
  }
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param bkey указатель на контекст мастер-ключа или ключа-строки (ключа-столбца)
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_destroy( ak_blomkey bkey )
{
  struct random generator;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "destroying null pointer to blom context" );
  if( bkey->data != NULL ) {
    ak_random_create_lcg( &generator );
    ak_ptr_wipe( bkey->data,
                   (bkey->size)*(bkey->size)*(bkey->qword_count)*sizeof( ak_uint64 ), &generator );
    ak_random_destroy( &generator );
  }
  memset( bkey, 0, sizeof( struct blomkey ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_blom.c  */
/* ----------------------------------------------------------------------------------------------- */
