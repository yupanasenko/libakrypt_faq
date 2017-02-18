/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*  ak_update.c                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_update.h>

/* ----------------------------------------------------------------------------------------------- */
 ak_update ak_update_new( size_t size )
{
  ak_update upd = NULL;

  if( size == 0 ) {
    ak_error_message( ak_error_zero_length, __func__ ,
                                                   "using zero length of temporary data buffer" );
    return NULL;
  }
  if(( upd = ( ak_update ) malloc( sizeof( struct update ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                                   "wrong memroy alllocation for a new context" );
    return NULL;
  }

 /* выделем память и присваиваем значения */
  if(( upd->data = malloc( upd->bsize = size )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                    "wrong memroy alllocation for a new temporary data buffer" );
    return ( upd = ak_update_delete( upd ));
  } else memset( upd->data, 0, size );

  upd->length =   0;
  upd->hsize =    0;
  upd->ctx =      NULL;
  upd->update =   NULL;
  upd->finalize = NULL;
  upd->clean =    NULL;
  upd->free =     NULL;
 return upd;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_update ak_update_new_hash( ak_hash ctx )
{
  ak_update upd = NULL;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to hash context" );
    return NULL;
  }
  if(( upd = ak_update_new( ak_hash_get_block_size( ctx ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                                  "wrong memory alllocation for a new context" );
    return NULL;
  }

  upd->hsize =    ctx->hsize;
  upd->ctx =      ctx;
  upd->update =   ctx->update;
  upd->finalize = ctx->finalize;
  upd->clean =    ctx->clean;
  upd->free =     ak_hash_delete;
 return upd;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_update_delete( ak_pointer ptr )
{
  ak_update upd = ( ak_update ) ptr;
  if( upd == NULL )
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to update context" );
  else {
         if( upd->data != NULL ) {
           free( upd->data );
           upd->data = NULL;
         }
         if( upd->free != NULL ) {
           if( upd->ctx == NULL )
             ak_error_message( ak_error_null_pointer, __func__,
                                              "freeing a null pointer to internal context" );
             else upd->ctx = upd->free( upd->ctx );
         }
         upd->bsize =       0;
         upd->hsize =       0;
         upd->length =      0;
         upd->update =   NULL;
         upd->finalize = NULL;
         upd->clean =    NULL;
         upd->free =     NULL;
         free( upd );
       }
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 size_t ak_update_get_code_size( ak_update upd )
{
  if( upd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to update context" );
    return 0;
  }
 return upd->hsize;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_update_clean( ak_update upd )
{
  if( upd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to update context" );
    return ak_error_null_pointer;
  }
  if( upd->clean == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ ,
                                                         "using an undefined internal function" );
    return ak_error_undefined_function;
  }

  if( upd->data != NULL ) memset( upd->data, 0, upd->bsize );
  upd->length = 0;
  upd->clean( upd->ctx );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ctx Контекст структуры итеративного вычисления значений сжимающих отображений
    @param in Сжимаемые данные
    @param size Размер сжимаемых данных в байтах. Данное значение может
    быть произвольным, в том числе равным нулю и/или не кратным длине блока обрабатываемых данных
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_update_update( ak_update upd, const ak_pointer in, const size_t size )
{
  ak_uint8 *ptrin = (ak_uint8 *) in;
  size_t quot = 0, offset = 0, newsize = size;

  if( upd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to update context" );
    return ak_error_null_pointer;
  }
  if( upd->update == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ ,
                                                          "using an undefined internal function" );
    return ak_error_undefined_function;
  }

 /* в начале проверяем, есть ли данные во временном буфере */
  if( upd->length != 0 ) {
   /* если новых данных мало, то добавляем во временный буффер и выходим */
    if(( upd->length + newsize ) < upd->bsize ) {
       memcpy( upd->data + upd->length, ptrin, newsize );
       upd->length += newsize;
       return ak_error_ok;
    }
   /* дополняем буффер до длины, кратной bsize */
    offset = upd->bsize - upd->length;
    memcpy( upd->data + upd->length, ptrin, offset );

   /* обновляем значение контекста функции и очищаем временный буффер */
    upd->update( upd->ctx, upd->data, upd->bsize );
    memset( upd->data, 0, upd->bsize );
    upd->length = 0;
    ptrin += offset;
    newsize -= offset;
  }

 /* теперь обрабатываем входные данные с пустым временным буффером */
  if( newsize != 0 ) {
    quot = newsize/upd->bsize;
    offset = quot*upd->bsize;
   /* обрабатываем часть, кратную величине bsize */
    if( quot > 0 ) upd->update( upd->ctx, ptrin, offset );
   /* хвост оставляем на следующий раз */
    if( offset < newsize ) {
      upd->length = newsize - offset;
      memcpy( upd->data, ptrin + offset, upd->length );
    }
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Результат вычислений помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param ctx Контекст структуры итеративного вычисления значений сжимающих отображений
    @param in Сжимаемые данные
    @param size Размер сжимаемых данных в байтах. Данное значение может
    быть произвольным, в том числе превышающем величину блока обрабатываемых данных.
    @param out Область памяти, куда будет помещен рещультат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_update_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений.                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_update_finalize( ak_update upd, const ak_pointer in, const size_t size, ak_pointer out )
{
  ak_buffer result = NULL;
  if( upd == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to update context" );
    return NULL;
  }
  if( upd->finalize == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ ,
                                                 "using an undefined internal finalize function" );
    return NULL;
  }
  if( upd->clean == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ ,
                                                    "using an undefined internal clean function" );
    return NULL;
  }

  /* начинаем с того, что обрабатываем все переданные данные */
   ak_update_update( upd, in, size );
  /* потом обрабатываем хвост, оставшийся во временном буффере */
  result = upd->finalize( upd->ctx, upd->data, upd->length, out );
  upd->clean( upd->ctx );

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-hash-update.c                                                                 */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_update.c */
/* ----------------------------------------------------------------------------------------------- */
