/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_fiot.с                                                                                 */
/*  - содержит функции, реализующие транспортный протокол и протокол выработки общих ключей         */
/*    защищенного криптографического взаимодействия.                                               */
/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */
 #include <ak_fiot.h>

/* для формирования фрейма нам нужен заголовок


 * (fctx->heade ) */

  fctx->header_offset (заголовок)
  data
  ( imitosize + 2 )

/* ----------------------------------------------------------------------------------------------- */
/*! \details Эта функция самого нижнего уровня - она в явном виде получает отправляемые в канал
    данные, формирует сообщение, если необходимо - дополнение, вычисляет имитовтсавку и
    зашифровывает сооббщение.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    Контекст должен быть предварительно создан и инициализирован.
    \param data Данные, которые помещаются во фрейм и отправляются в канал в зашифрованном виде
    \param datalen Размер отправляемых данных в байтах
    \param ftype Тип формируемого фрейма данных (зашифрованные или открытые)
    \param mtype Тип передаваемых данных

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_send_frame( ak_fiot fctx, ak_pointer data, ssize_t datalen,
                                                               frame_type_t ftype, message_t mtype )
{
  /* проверки */
   if( datalen < 1 ) return ak_error_zero_length; /* мы отправляем хотя бы один байт информации */
   if( fctx->role == undefined_role ) return fiot_error_wrong_role;
   if( fctx->enc_gate == undefined_gate ) return fiot_error_wrong_gate;

  /* определяем размеры передаваемого фрейма */
   if( ftype == plain_frame ) ilen = fctx->epsk
   fiot_context_get_mac_size( fctx, psk );
//    else {
//           switch( fctx->role ) {
//             case client_role: ikey = icfk; ekey = ecfk; break;
//             case server_role: ikey = isfk; ekey = esfk; break;
//           }
//           ilen = fiot_context_get_mac_size( fctx, ikey );
//         }

//   olen = framelen = FIOT_FRAME_MESSAGE_OFFSET + meslen + 2 + ilen;
//   if( framelen > FIOT_TCP_FRAME_SIZE ) return fiot_error_wrong_send_length;

//  /* пытаемся увеличить длину и сделать ее кратной 16 октетам; если нельзя, то откатываемся назад */
//   if( framelen%16 != 0 ) {
//     framelen = ( 1+ (framelen>>4) )<<4;
//     if( framelen > FIOT_TCP_FRAME_SIZE ) framelen = olen;
//   }



//  ssize_t framelen = fctx->header_offset /* заголовок */
//                   + 3 /* истинная длина сообщения + его тип */
//                   + datalen /* собственно данные */
//                   + 2 /* признак наличия имитовставки */
//                   + ilen; /* имитовставка */

//  if( framelen > fctx-oframe_size ) return fiot_error_wrong_send_length;

//  FIOT_FRAME_MESSAGE_OFFSET + meslen + 2 + ilen;
//   if( framelen > FIOT_TCP_FRAME_SIZE ) return fiot_error_wrong_send_length;



//  memset( fctx->oframe, 0, fctx-> );
//  memcpy( frame + FIOT_FRAME_MESSAGE_OFFSET, data, meslen );
//  if( fiot_frame_send( fctx, frame, encryptedFrame, applicationData, meslen ) != fiot_error_ok )
    return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                             ak_fiot_protocol.c  */
/* ----------------------------------------------------------------------------------------------- */

