/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_fiot_tlp.с                                                                             */
/*  - содержит функции, реализующие транспортный протокол (Transport Layer Protocol)               */
/*     защищенного криптографического взаимодействия.                                              */
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

#include <stdio.h>

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_fiot.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Изменение текущего значения счетчиков.
    \details Функция увеличивает значения счетчиков и проверяет их значения на соответствие
    текущим ограничениям. Если значения счетчиков выходят за допустимые значения -
    вырабатываются новые ключевые значения.

    \param fctx Контекст защищенного соединения протокола sp fiot.                                 */
/* ----------------------------------------------------------------------------------------------- */
 static inline void ak_fiot_context_increment_counters( ak_fiot fctx )
{
  if(( ++fctx->lcounter ) == fctx->restriction.maxFrameCount ) {
    fctx->lcounter = 0;
    if(( ++fctx->mcounter ) > fctx->restriction.maxFrameKeysCount ) {

      fctx->mcounter = 0;
      if( ++fctx->ncounter > fctx->restriction.maxApplicationSecretCount ) {
        /* здесь мы должны заблокировать фрейм и перейти к процедуре выработки нового
           сеанса криптографического взаимодействия */

      } else {
               /* здесь мы должны выработать новое значение ключевой информации SATS и CAST,
                  а также инициализировать зависящие от них ключи eC(S)FK и iC(S)FK */

             }
    } else {
             /* здесь мы должны выработать новую пару ключей eC(S)FK и iC(S)FK */

           }
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \details Эта функция самого нижнего уровня - она в явном виде получает отправляемые в канал
    данные, формирует сообщение, если необходимо - дополнение, вычисляет имитовставку и
    зашифровывает сообщение.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    Контекст должен быть предварительно создан, а ключевые значения инициализированы.
    \param header Дополнительные данные, помещаемые в заголовок фрейма. Длина дополнительных данных
    определяется величиной `fctx->header_offset - 8`, где 8 это длина стандартного заголовка,
    а величина `fctx->header_offset` определяется на все время выполнения протокола.

    В случае использования значения `NULL` дополнительные данные в заголовок не помещаются,
    а длина заголовка полагается равной 8.

    \param data Данные, которые помещаются во фрейм и отправляются в канал.
    \param datalen Размер отправляемых данных в байтах.
    \param ftype Тип формируемого фрейма данных
    (данные передаются в зашифрованном или открытом виде)
    \param mtype Тип передаваемых данных

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_send_frame( ak_fiot fctx, ak_pointer header,
                             ak_pointer data, size_t datalen, frame_type_t ftype, message_t mtype )
{
   ak_mac ikey = NULL;
   ak_bckey ekey = NULL;
   size_t ilen = 0, olen = 0, framelen = 0, offset = 0;

  /* выполняем минимальные проверки */
   if( fctx->enc_gate == undefined_gate ) return fiot_error_wrong_gate;
   if( datalen < 1 ) return ak_error_zero_length; /* мы отправляем хотя бы один байт информации */

  /* определяем размер имитовставки */
   if( ftype == plain_frame ) ikey = fctx->epsk;
    else {
          switch( fctx->role ) {
            case client_role: ikey = fctx->icfk; ekey = fctx->ecfk; break;
            case server_role: ikey = fctx->isfk; ekey = fctx->esfk; break;
            default: return fiot_error_wrong_role;
          }
         }
   ilen = ikey->hsize;
  /* определяем минимальный размер сообщения
      framelen - полная длина фрейма,
      olen - длина фрейма без дополнения */
   olen = framelen = fctx->header_offset /* заголовок */
                   + 3 /* истинная длина сообщения + его тип */
                   + datalen /* собственно данные */
                   + 2 /* признак наличия имитовставки + ее длина */
                   + ilen; /* имитовставка */

   if( framelen > fctx->oframe_size ) return fiot_error_wrong_send_length;

  /* увеличиваем длину фрейма за счет паддинга

     внимание! Сейчас используется политика по-умолчанию, при которой общая длина фрейма
     должна быть кратной 16 байтам, если этого сделать нельзя, то откатываемся назад.
     необходимо реализовать все возможные политики в соответствии с методическими рекомендациями. */
   if( framelen%16 != 0 ) {
     framelen = ( 1+ (framelen>>4) )<<4;
     if( framelen > fctx->oframe_size ) framelen = olen;
   }
  /* теперь собираем фрейм по кусочкам */
   memset( fctx->oframe, 0, fctx->oframe_size );

  /* тип фрейма и размер заголовка */
   fctx->oframe[0] = ( char )(( fctx->header_offset << 2 ) + ftype );

  /* размер фрейма */
   fctx->oframe[1] = ( char )(( framelen >> 8 )%256 );
   fctx->oframe[2] = ( char )( framelen%256 );

  /* номер фрейма */
   fctx->oframe[3] = ( char )(( fctx->ncounter )%256 );
   fctx->oframe[4] = ( char )((( fctx->mcounter ) >> 8)%256 );
   fctx->oframe[5] = ( char )(( fctx->mcounter )%256 );
   fctx->oframe[6] = ( char )((( fctx->lcounter ) >> 8)%256 );
   fctx->oframe[7] = ( char )(( fctx->lcounter )%256 );

  /* добавляем данные в заголовок пакета
     если fctx->header_offset > 8, то эти данные занимают область
     с fctx->oframe[8] ... по fctx->ofram[ fctx->header_offset - 1 ] */
   if( fctx->header_offset > 8 ) {
     if( header == NULL ) memset( fctx->oframe+8, 0, fctx->header_offset - 8 );
      else memcpy( fctx->oframe+8, header, fctx->header_offset - 8 );
   }

  /* тип и размер сообщения */
   offset = fctx->header_offset;
   fctx->oframe[ offset++ ] = ( char ) mtype;
   fctx->oframe[ offset++ ] = ( char )(( datalen >> 8 )%256 );
   fctx->oframe[ offset++ ] = ( char )( datalen%256 );

  /* данные */
   memcpy( fctx->oframe + offset, data, datalen );

  /* паддинг и контрольная сумма */
   if(( olen = framelen - olen ) > 0 ) fctx->plain_rnd.random( &fctx->plain_rnd,
                                  fctx->oframe + offset + datalen, (ssize_t) olen );
   fctx->oframe[ framelen - 2 - ilen ] = ( char ) is_present;
   fctx->oframe[ framelen - 1 - ilen ] = ( char ) ilen;

   olen = framelen - ilen - 2;
   if( ftype == plain_frame )
     ak_mac_context_ptr( ikey, fctx->oframe, olen, fctx->oframe + framelen - ilen );
   else { /* это все только для ctr+omac, mgm впереди ))) */
     ak_mac_context_ptr( ikey, fctx->oframe, olen, fctx->oframe + framelen - ilen );
     olen -= fctx->header_offset;

    /* здесь надо аккуратно определить iv */
     ak_bckey_context_xcrypt( ekey,
       fctx->oframe + fctx->header_offset,
       fctx->oframe + fctx->header_offset, olen, fctx->oframe, 8 );
     }

  /* контрольный вывод */
   if( ak_log_get_level() >= fiot_log_maximum )
     ak_fiot_context_print_frame( fctx->oframe, ( ssize_t )framelen );

//   if( fctx->send( fctx->sendDescriptor, frame, framelen ) != framelen ) {
//     return fiot_error_wrong_send;
//   }

  /* изменяем значения счетчиков и ключей после отправки фрейма в канал связи */
   ak_fiot_context_increment_counters( fctx );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                             ak_fiot_protocol.c  */
/* ----------------------------------------------------------------------------------------------- */

