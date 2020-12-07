/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_blom.с                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup skey-blom-doc Реализация схемы Блома распределения ключевой информации @{
   Схема Блома представляет собой механизм выработки секретных симметричных ключей парной связи,
   предоставляющий действенную альтернативу инфрастуктуре открытых ключей.
   Ключевая система, построенная на схеме Блома, рекомендована к использованию
   в рекомендациях по стандартизации Р 1323565.1.018-2018, Р 1323565.1.019-2018 и Р 1323565.1.028–2019.

   Пусть заданы конечное поле \f$ GF(2^n)\f$, где \f$ n \in \{ 256, 512 \} \f$
   и параметр безопасности \f$ m \f$.
   Основным ключевым элементом схемы Блома является мастер-ключ, представленный в виде
   секретной симметричной матрицы

   \f\[ A = (a_{i,j})_{i,j = 0}^{m-1} =
           \left( \begin{array}{c}
           a_{0,0\ }a_{0,1}\dots \ a_{0,m-1} \\
           a_{1,0}\ a_{1,1}\dots \ a_{1,m-1} \\
           \dots \  \\
           a_{m,0\ }a_{m,1}\dots \ a_{m-1,m-1} \end{array}
           \right),
   \f\]
  где \f$ a_{i,j} = a_{j,i},\: 0 \le i < m,\: 0 \le j < m \f$ и \f$ a_{i,j} \in GF(2^n)\f$.
  Указаная матрица может быть создана с помощью функции ak_blomkey_create_matrix().

  С матрицей может быть связан многочлен
  \f\[ f(x,y)= \sum_{i=0}^{m-1} \sum_{j=0}^{m-1} a_{i,j}x^i y^j,\quad f(x,y) \in GF(2^{n})[x,y], \f\]
  удволетворяющий равенству \f$ f(x,y) = f(y,x) \f$.

  Пусть абоненты a и b имеют идентификаторы IDa и IDb, тогда ключ парной связи между
  указанными абонентами определяется равенством

  \f\[ Kab = f( \texttt{Streebog}_n(IDa), \texttt{Streebog}_nh(IDb) ). \f\]

  Для возможности вступать в связь с несколькими абонентами,
  каждый абонент `a` может выработать из мастер-ключа свой уникальный ключ, представляющий собой
  вектор

  \f\[ Ka = (b_0, b_1, \ldots, b_{m-1}),  \f\]

  в котором координаты \f$ b_i \in GF(2^n), \: 0 \le i < m \f$, определены равенствами

  \f[ b_i = \sum_{j=0}^{m-1} a_{i,j} \big( \texttt{Streebog}_n(IDa) \big)^j \f]

  и могут быть связаны с многочленом

  \f\[ f_a(x) = f\left(x, \texttt{Streebog}_n(IDa)\right) = \sum_{i=0}^{m-1} b_ix^i,
   \quad f_a(x) \in GF(2^{n})[x]. \f\]

  Тогда для связи с любым абонентом, имеющим идентификатор IDb,
  абоненту `a` достаточно вычислить ключ парной связи, определяемый равенством
  \f\[ Kab = f_a\left( \texttt{Streebog}_n(IDb) \right). \f\]

  Создание ключа абонента может быть выполнено с помощью функции ak_blomkey_create_abonent_key().
  Создание ключа парной связи - с помощью функции ak_blomkey_create_pairwise_key().
  Удаление созданных ключей выполняется с помощью функции ak_blomkey_destroy().
  Экспорт и импорт абонентских ключей и мастер-ключа из файлов осуществляется с помощью функций
  ak_blomkey_export_to_file() и ak_blomkey_import_from_file().

  Отметим, что неприводимые многочлены, используемые для реализации элементарных операций
  в конечном поле \f$ GF(2^n)\f$, определены в файле ak_gf2n.c                                  @} */
/* ----------------------------------------------------------------------------------------------- */
 static bool_t ak_blomkey_check_icode( ak_blomkey bkey )
{
  ak_uint8 value[32];

  if( bkey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to blom key context" );
    return ak_false;
  }
  if( bkey->data == NULL ) {
    ak_error_message( ak_error_undefined_value, __func__, "checking the null pointer memory" );
    return ak_false;
  }

 /* вычисляем контрольную сумму и сравниваем */
  memset( value, 0, sizeof( value ));
  ak_hash_ptr( &bkey->ctx, bkey->data,
                    bkey->type == blom_matrix_key ? (bkey->size)*(bkey->size)*bkey->count :
                                                             (bkey->size)*bkey->count, value, 32 );
  if( ak_ptr_is_equal( value, bkey->icode, 32 ) == ak_false ) {
    ak_error_message( ak_error_not_equal_data, __func__, "integrity code is wrong" );
    return ak_false;
  }
 return ak_true;
}



/* ----------------------------------------------------------------------------------------------- */
/*! В ходе своего выполнения функция вырабатывает симметричную матрицу,
    состоящую из (`size`)x(`size`) элементов конечного поля \f$ GF(2^n)\f$, где `n` это количество
    бит (задается параметром `count`). Например, для поля \f$ GF(2^{256})\f$ величина `count` должна
    принимать значение 32.

    \param bkey указатель на контекст мастер-ключа
    \param size размер матрицы
    \param count количество октетов, определяющих размер конечного поля;
    допустимыми значениями являются \ref ak_galois256_size и \ref ak_galois512_size.
    \param generator указатель на контекст генератора случайных значений.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_create_matrix( ak_blomkey bkey, const ak_uint32 size,
                                                      const ak_uint32 count, ak_random generator )
{
  int error = ak_error_ok;
  ak_uint32 column = 0, row = 0;
  size_t memsize = size*size*count;

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to blom matrix" );
  if( size > 4096 ) return ak_error_message( ak_error_wrong_length, __func__,
                                                          "using very huge size for blom matrix" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__, "using zero field size" );
  if(( count != ak_galois256_size ) && ( count != ak_galois512_size ))
   return ak_error_message( ak_error_undefined_value, __func__,
                                       "this function accepts only 256 or 512 bit galois fields" );
  bkey->type = blom_matrix_key;
  bkey->count = count;
  bkey->size = size;
  if(( bkey->data = malloc( memsize )) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );

  memset( bkey->data, 0, memsize );
  for( column = 0; column < size; column++ ) {
    /* копируем созданное ранее */
     for( row = 0; row < column; row++ ) memcpy( bkey->data + column*count*size+row*count,
                                     ak_blomkey_get_element_by_index( bkey, row, column ), count );
    /* создаем новое */
     ak_random_ptr( generator, bkey->data+column*count*(size+1),( size - column )*count );
  }
  switch( bkey->count ) {
    case ak_galois256_size: error = ak_hash_create_streebog256( &bkey->ctx );
                            break;
    case ak_galois512_size: error = ak_hash_create_streebog512( &bkey->ctx );
                            break;
    default: ak_error_message( error = ak_error_undefined_value, __func__,
                                       "this function accepts only 256 or 512 bit galois fields" );
  }
  if( error != ak_error_ok ) {
    ak_blomkey_destroy( bkey );
    return ak_error_message( error, __func__, "incorrect creation of hash function context" );
  }
  if(( error = ak_hash_ptr( &bkey->ctx, bkey->data, memsize,
                                    bkey->icode, 32 )) != ak_error_ok ) ak_blomkey_destroy( bkey );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Вырабатываемый ключ предназначается для конкретного абонента и
    однозначно зависит от его идентификатора и мастер-ключа.
    \param bkey указатель на контекст создаваемого ключа абонента
    \param matrix указатель на контекст мастер-ключа
    \param id указатель на идентификатор абонента
    \param size длина идентификатора (в октетах)
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_create_abonent_key( ak_blomkey bkey, ak_blomkey matrix,
                                                               ak_pointer id, const size_t idsize )
{
  ak_uint8 value[64];
  size_t memsize = 0;
  ak_int32 column = 0;
  ak_uint32 i, row = 0;
  int error = ak_error_ok;

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to abonent's key" );
  if( matrix == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to blom master key" );
  if( matrix->type != blom_matrix_key ) return ak_error_message( ak_error_wrong_key_type,
                                                   __func__, "incorrect type of blom secret key" );
  if(( id == NULL ) || ( !idsize )) return ak_error_message( ak_error_undefined_value, __func__,
                                                          "using undefined abonent's identifier" );
  if( !ak_blomkey_check_icode( matrix ))
    return ak_error_message( ak_error_get_value(), __func__, "using wrong blom master key" );

  memset( bkey, 0, sizeof( struct blomkey ));
  bkey->count = matrix->count;
  bkey->size = matrix->size;
  bkey->type = blom_abonent_key;

 /* создаем контекст хеш-функции */
  if(( error = ak_hash_create_oid( &bkey->ctx, matrix->ctx.oid )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of hash function context" );
 /* формируем хэш от идентификатора */
  if(( error = ak_hash_ptr( &bkey->ctx, id, idsize, value, bkey->count )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect evauation of initial hash value" );

 /* формируем ключевые данные */
  if(( bkey->data = malloc(( memsize = bkey->size*matrix->count ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );

  memset( bkey->data, 0, memsize );
  for( row = 0; row < bkey->size; row++ ) { /* схема Горнера для вычисления значений многочлена */
     ak_uint8 *sum = bkey->data + row*bkey->count;
     memset( sum, 0, bkey->count );
     for( column = bkey->size - 1; column >= 0; column-- ) {
        ak_uint8 *key = ak_blomkey_get_element_by_index( matrix, row, column );
        if( bkey->count == ak_galois256_size ) ak_gf256_mul( sum, sum, value );
         else ak_gf512_mul( sum, sum, value );
        for( i = 0; i < ( bkey->count >> 3 ); i++ ) ((ak_uint64 *)sum)[i] ^= ((ak_uint64 *)key)[i];
     }
  }

  if(( error = ak_hash_ptr( &bkey->ctx, bkey->data, memsize,
                                    bkey->icode, 32 )) != ak_error_ok ) ak_blomkey_destroy( bkey );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает общий для двух абонентов секретный вектор и
    помещает его в контекст секретного ключа парной связи с заданным oid
    (функция релизует действие `import = create + set_key`.

    \param bkey указатель на контекст ключа абонента
    \param id указатель на идентификатор абонента, с которым вырабатывается ключ парной связи
    \param size длина идентификатора (в октетах)
    \param skey указатель на контекст вырабатываемого секретного ключа парной связи
    \param oid идентификатор алгоритма, для которого предназначен ключ парной связи
    (в настоящее время  поддерживаются только секретные ключи блочных алгоритмов шифрования
     и ключи алгоритмов HMAC).
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_create_pairwise_key( ak_blomkey bkey, ak_pointer id, const size_t idsize,
                                                                      ak_pointer skey, ak_oid oid )
{
  ak_uint32 i = 0;
  ak_int32 row = 0;
  struct random generator;
  int error = ak_error_ok;
  ak_uint8 sum[64], value[64];

  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to abonent's key" );
  if(( id == NULL ) || ( !idsize )) return ak_error_message( ak_error_undefined_value, __func__,
                                                          "using undefined abonent's identifier" );
  if( bkey->type != blom_abonent_key ) return ak_error_message( ak_error_wrong_key_type,
                                                   __func__, "incorrect type of blom secret key" );
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to pairwise key" );
  if( !ak_blomkey_check_icode( bkey))
    return ak_error_message( ak_error_get_value(), __func__, "using wrong blom master key" );

 /* проверяем, что заданый oid корректно определяет секретный ключ */
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to pairwise key identifier" );
  if( oid->mode != algorithm ) return ak_error_message( ak_error_oid_mode, __func__,
                                                   "using wrong mode to pairwise key identifier" );
  if(( oid->engine != block_cipher ) && ( oid->engine != hmac_function ))
    return ak_error_message( ak_error_oid_engine, __func__,
                                                 "using wrong engine to pairwise key identifier" );
 /* формируем хэш от идентификатора */
  if(( error = ak_hash_ptr( &bkey->ctx, id, idsize, value, bkey->count )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect evauation of initial hash value" );

  memset( sum, 0, bkey->count );
  for( row = bkey->size - 1; row >= 0; row-- ) {
        ak_uint8 *key = ak_blomkey_get_element_by_index( bkey, row, 0 );
        if( bkey->count == ak_galois256_size ) ak_gf256_mul( sum, sum, value );
         else ak_gf512_mul( sum, sum, value );
        for( i = 0; i < ( bkey->count >> 3 ); i++ ) ((ak_uint64 *)sum)[i] ^= ((ak_uint64 *)key)[i];
     }

 /* формируем ключ парной связи для заданного пользователем алгоритма */
  if(( error = oid->func.first.create( skey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation of pairwise key" );
    goto lab1;
  }
  if(( error = oid->func.first.set_key( skey, sum, bkey->count )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning of pairwise key value" );
    goto lab1;
  }

  lab1:
    if( ak_random_create_lcg( &generator ) == ak_error_ok ) {
      ak_ptr_wipe( sum, 64, &generator );
      ak_random_destroy( &generator );
    }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param bkey указатель на контекст мастер-ключа или ключа-строки (ключа-столбца)
    \param row номер строки
    \param column номер столбца; для ключей абонентов данное значение не учитывается.
    \return В случае успеха, функция возвращает указатель на область памяти, содержащей
    зазанный элемент. В случае возникновения ошибки возвращается `NULL`.                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 *ak_blomkey_get_element_by_index( ak_blomkey bkey, const ak_uint32 row,
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
   case blom_matrix_key: return bkey->data + (bkey->size*row + column)*bkey->count;
   case blom_abonent_key: return bkey->data + row*bkey->count;
   default:
     ak_error_message_fmt( ak_error_undefined_value, __func__ ,
                                                "incorrect type of blom matrix (%u)", bkey->type );
  }
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param bkey указатель на контекст мастер-ключа или ключа абонента
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха,
    в противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_blomkey_destroy( ak_blomkey bkey )
{
  struct random generator;
  if( bkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "destroying null pointer to blom context" );
  ak_hash_destroy( &bkey->ctx );
  if( bkey->data != NULL ) {
    ak_random_create_lcg( &generator );
    ak_ptr_wipe( bkey->data, /* очищаем либо матрицу, либо строку */
       bkey->type == blom_matrix_key ?
                (bkey->size)*(bkey->size)*(bkey->count) : (bkey->size)*(bkey->count), &generator );
    ak_random_destroy( &generator );
    free( bkey->data );
  }
  memset( bkey, 0, sizeof( struct blomkey ));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example test-blom-keys.c                                                                      */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_blom.c  */
/* ----------------------------------------------------------------------------------------------- */
