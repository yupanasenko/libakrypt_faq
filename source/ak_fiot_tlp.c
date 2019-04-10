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
#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
 /* заголовок нужен длял реализации функции send */
 #include <sys/socket.h>
#endif

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
 int ak_fiot_context_write_frame( ak_fiot fctx, ak_pointer header,
                             ak_pointer data, size_t datalen, frame_type_t ftype, message_t mtype )
{
   ak_mac ikey = NULL;
   ak_bckey ekey = NULL;
   int error = ak_error_ok;
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
     framelen = ( 1+ ( framelen>>4 )) <<4;
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

          /*! \todo здесь надо аккуратно определить iv */
           ak_bckey_context_xcrypt( ekey, fctx->oframe + fctx->header_offset,
                              fctx->oframe + fctx->header_offset, olen, fctx->oframe, 8 );
        }

  /* контрольный вывод */
   if( ak_log_get_level() >= fiot_log_maximum )
     ak_fiot_context_print_frame( fctx->oframe, ( ssize_t )framelen );

   if( fctx->write( fctx->enc_gate, fctx->oframe, ( ssize_t )framelen ) != ( ssize_t )framelen )
    ak_error_set_value( error = ak_error_write_data );

  /* изменяем значения счетчиков и ключей после отправки фрейма в канал связи */
   ak_fiot_context_increment_counters( fctx );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция получает данные из канала связи, рашифровывает их, проверяет целостность
    помещает полученные данные во временный буффер.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    Контекст должен быть предварительно создан, а ключевые значения инициализированы.
    \param length Переменная, в которую помещается длина полученного сообщения.
    \param mtype Переменная, в которую помещается тип полученного сообщения

    \return В случае успешного приема функция возвращает указатель на область памяти,
    в которой находятся полученные данные. В случае неудачи, возвращается `NULL`,
    а также устанавливается код ошибки, который может быть определен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 char *ak_fiot_context_read_frame( ak_fiot fctx, size_t *length, message_t *mtype )
{
   ak_uint8 out[64]; /* максимальная длина имитовставки - длина хэшкода для Стрибога 512 */
   ak_mac ikey = NULL;
   ak_bckey ekey = NULL;
   int i, error = ak_error_ok;
   ssize_t ilen = 4, ftype = 0, offset = 0, framelen = 0;

  /* необходимые проверки */
   if( fctx->enc_gate == undefined_gate ) {
     ak_error_set_value( fiot_error_wrong_gate );
     return NULL;
   }

  /* в начале пытаемся получить из канала связи три байта, содержащие тип фрейма и его длину */
   if( ak_fiot_context_read_ptr_timeout( fctx,
                                       encryption_gate, fctx->inframe, 3 ) != 3 ) return NULL;
  /* проверяем, что тип полученного фрейма корректен */
   ftype = fctx->inframe[0]&0x3;
   if(( ftype != plain_frame ) && ( ftype != encrypted_frame )) {
     ak_error_set_value( fiot_error_frame_type );
     return NULL;
   }

  /* определяем длину заголовка */
   offset = fctx->inframe[0]>>2;

  /* проверяем, что длина полученного фрейма корректна */
   if(( framelen = fctx->inframe[2] + fctx->inframe[1]*256 ) > fiot_max_frame_size ) {
     ak_error_set_value( fiot_error_frame_size );
     return NULL;
   }
  /* при необходимости, увеличиваем объем внутреннего буффера */
   if(( size_t )framelen > fctx->inframe_size )
     if(( error = ak_fiot_context_set_frame_size( fctx, inframe,
                                                       ( size_t )framelen )) != ak_error_ok )
       return NULL;

  /* теперь получаем из канала основное тело пакета */
   if( ak_fiot_context_read_ptr_timeout( fctx, encryption_gate,
                                    fctx->inframe+3, framelen-3 ) != framelen-3 ) return NULL;
   if( ak_log_get_level() >= fiot_log_maximum )
     ak_fiot_context_print_frame( fctx->inframe, framelen );

  /* теперь процесс проверки данных
     начинаем с уcтановки ключей и проверки длины имитовставки */
   if( ftype == plain_frame ) ikey = fctx->epsk;
    else {
          switch( fctx->role ) {
            case client_role: ikey = fctx->icfk; ekey = fctx->ecfk; break;
            case server_role: ikey = fctx->isfk; ekey = fctx->esfk; break;
            default:
                 ak_error_set_value( fiot_error_wrong_role );
                 return NULL;
          }
         }

  /* в начале, пытаемся определить размер имитовставки (без использования контекста протокола ) */
   for( i = 0; i < 6; i++ ) {
      ssize_t idx = framelen-1-ilen;
      if( idx < 1 ) { ilen = 256; break; }
      if(( size_t )idx > ( size_t )( framelen-1 )) { ilen = 256; break; }
      if(( fctx->inframe[idx] == ilen ) && ( fctx->inframe[idx-1] == ( char )is_present )) break;
      ilen <<= 1;
   }
   if( ilen > 128 ) { /* значение имитовставки слишком большое */
     ak_error_set_value( fiot_error_frame_format );
     return NULL;
   }
   if(( size_t )ilen != ikey->hsize ) { /* длина имитовставки полученного фрейма не совпадает
                                           с длиной имитовставки для установленного ключа */
     ak_error_set_value( fiot_error_wrong_mechanism );
     return NULL;
   }

 /* расшифровываем и проверяем контрольную сумму */
   if( ftype == encrypted_frame ) {
    /*! \todo здесь надо аккуратно определить iv */
     ak_bckey_context_xcrypt( ekey, fctx->inframe + offset,
          fctx->inframe + offset, ( size_t )( framelen - offset - ilen - 2 ), fctx->inframe, 8 );
   }
   ak_mac_context_ptr( ikey, fctx->inframe, ( size_t )(framelen - ilen - 2 ), out );
   if( memcmp( fctx->inframe + framelen - ilen, out, ( size_t )ilen ) != 0 ) {
     ak_error_set_value( ak_error_not_equal_data );
     return NULL;
   }

 /* теперь помещаем значения полей */
   *mtype = ( message_t ) fctx->inframe[ offset++ ];
   *length = ( size_t )( fctx->inframe[ offset++ ]*256 );
   *length += ( size_t )( fctx->inframe[ offset++ ] );

 return fctx->inframe + offset;
}

/* ----------------------------------------------------------------------------------------------- */
/*         далее идет большая группа функций, реализующих аудит передаваемых фреймов               */
/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует вывод произвольного буффера с данными.
    \param data Указатель на данные
    \param length Длина данных в байтах
    \param level Уровень сдвига (количество табуляций, предваряющих выводимые данные).

    \return Функия возвращает количество выведенных данных.                                        */
/* ----------------------------------------------------------------------------------------------- */
 static ssize_t ak_fiot_context_print_ptr( char *data, ssize_t length, const unsigned int level )
{
  char buffer[1024];
  ssize_t i, j, blocks = length >> 4;
  ssize_t tail = length - (blocks << 4), offset = 0;

  for( i = 0; i < blocks; i++ ) {
     memset( buffer, 0, sizeof( buffer ));
     memset( buffer, ' ', ( size_t )( offset = 8*level ));
     for( j = 0; j < 16; j++ ) {
        ak_snprintf( buffer+offset, 8, "%02X ", (unsigned char)data[16*i+j] );
        offset += 3;
     }
     ak_error_message( ak_error_ok, "", buffer );
  }
  if( tail ) {
    memset( buffer, 0, sizeof( buffer ));
    memset( buffer, ' ', ( size_t )( offset = 8*level ));
    for( j = 0; j < tail; j++ ) {
       ak_snprintf( buffer+offset, 8, "%02X ", (unsigned char)data[16*i+j] );
       offset += 3;
    }
    ak_error_message( ak_error_ok, "", buffer );
 }
 return length;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param frame Указатель на последовательность октетов, содержащую сериализованное
           представление фрейма.
    @param framelen Длина последовательности октетов.                                              */
/* ----------------------------------------------------------------------------------------------- */
 void ak_fiot_context_print_frame( char *frame, ssize_t framelen )
{
   char buffer[1024];
   ssize_t offset = 0;
   char *message = NULL;
   int error = ak_error_ok;
   unsigned int i, ilen = 4;

  /* выводим общую информацию */
   if( frame == NULL ) return;
   ak_error_message( ak_error_ok, __func__, "" );
   ak_error_message_fmt( ak_error_ok, "",  "%ld octets", framelen );
   ak_fiot_context_print_ptr( frame, framelen, 1 );

   ak_error_message_fmt( ak_error_ok, "",  "header [%u octets]", ( offset = frame[0]>>2 ));
   switch( frame[0]&0x3 ) {
    case plain_frame:
      ak_snprintf( buffer, 1024, "        %02X [tag: %s]", frame[0], "plain frame" );
      break;
    case encrypted_frame:
      ak_snprintf( buffer, 1024, "        %02X [tag: %s]", frame[0], "encrypted frame" );
      break;
    default:
      error = fiot_error_frame_type;
      ak_snprintf( buffer, 1024, "        %02X [tag: %s]", frame[0], "unexpected frame type" );
      break;
   }
   ak_error_message( error, "",  buffer );
   ak_error_message_fmt( error, "",
                             "        %02X %02X [length: %u octets]", frame[1], frame[2], framelen );
   ak_error_message_fmt( error, "",
     "        %02X %02X %02X %02X %02X [number]", frame[3], frame[4], frame[5], frame[6], frame[7] );
   if( offset > 8 ) ak_fiot_context_print_ptr( frame+8, offset-8, 1 );
   if( error != ak_error_ok ) return;

  /* пытаемся определить имитовставку (без использования контекста протокола ) */
   for( i = 0; i < 6; i++ ) {
      ssize_t idx = framelen-1-ilen;
      if( idx < 1 ) { ilen = 256; break; }
      if( idx > framelen-1 ) { ilen = 256; break; }
      if((( unsigned int )frame[idx] == ilen ) && ( frame[idx-1] == ( char )is_present )) break;
      ilen <<= 1;
   }
   if( ilen > 128 ) { ak_error_message_fmt( fiot_error_frame_format, "",
                                            "frame is broken (wrong integrity tag size: %u)", ilen );
     return;
   }

  /* выводим зашифрованную часть */
   if(( frame[0]&0x3 ) == encrypted_frame ) {
     ak_error_message_fmt( ak_error_ok, "", "body [%lu octets, encrypted]", framelen-ilen-2-offset );
     ak_fiot_context_print_ptr( frame+offset, framelen-ilen-2-offset, 1 );
   } else {
//      switch( frame[8] ) {
//        case clientHello: fiot_error( fiot_error_ok, __func__,
//                                                  "type:\t  %02X [clientHello message]", frame[8] );
//                          break;
//        case serverHello: fiot_error( fiot_error_ok, __func__,
//                                                  "type:\t  %02X [serverHello message]", frame[8] );
//                          break;
//        case verifyMessage: fiot_error( fiot_error_ok, __func__,
//                                                       "type:\t  %02X [verify message]", frame[8] );
//                          break;
//        case applicationData: fiot_error( fiot_error_ok, __func__,
//                                              "type:\t  %02X [applicationData message]", frame[8] );
//                          break;
//        case alert: fiot_error( fiot_error_ok, __func__,
//                                                        "type:\t  %02X [alert message]", frame[8] );
//                          break;
//        case generatePSK: fiot_error( fiot_error_ok, __func__,
//                                                  "type:\t  %02X [generatePSK message]", frame[8] );
//                          break;
//        default: fiot_error( fiot_error_frame_format, __func__,
//                                                    "type:\t  %02X [undefined message]", frame[8] );
//                 return;
//      }

//      meslen = frame[9]*256 + frame[10];
//      fiot_error( fiot_error_ok, __func__, "meslen:\t  %02X %02X [%ld octets]",
//                                                                     frame[9], frame[10], meslen );
//      switch( frame[8] ) {
//        case clientHello: // fiot_frame_printf_clientHello(( unsigned char * )( frame+11 )); break;
//        case serverHello: // fiot_frame_printf_serverHello(( unsigned char * )( frame+11 )); break;
//        case verifyMessage: // fiot_frame_printf_verify(( unsigned char * )( frame+11 )); break;
//        default: fiot_error(fiot_error_ok, __func__, "message: [%lu octets]", meslen );
//                 fiot_frame_printf_data( frame+11, meslen, 1 );
//      }
//      fiot_error( fiot_error_ok, __func__, "padding: (%lu octets)", framelen-11-meslen-(ilen+2));
//      fiot_frame_printf_data( frame+11+meslen, framelen-11-meslen-(ilen+2), 1 );
   }

  /* теперь выводим значение имитовставки */
   if( !ilen ) { ak_error_message( fiot_error_frame_format, "",
                                           "frame is broken (undefined length of integrity tag)" );
     return;
   }
   ak_error_message_fmt( ak_error_ok, "", "icode [%lu octets]", ilen+2 );
   if( frame[framelen-1] == ( char ) not_present ) {
     ak_error_message( ak_error_ok, "", "\tintegrity tag is'nt present" );
     return;
   }

   message = frame + framelen -2 -ilen;
    switch( ( unsigned char ) message[0] )
   {
     case is_present:
        ak_error_message_fmt( ak_error_ok, "", "        %02X [tag: present]",
                                                                      (unsigned char) message[0] );
        ak_error_message_fmt( ak_error_ok, "", "        %02X [length: %lu octets]",
                                        (unsigned char) message[1], ( unsigned char ) message[1] );
        ak_fiot_context_print_ptr( message+2, message[1], 1 );
        break;
     case not_present:
        ak_error_message_fmt( ak_error_ok, "", "        %02X [tag: not present]",
                                                                    ( unsigned char ) message[0] );
        break;
   }
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                             ak_fiot_protocol.c  */
/* ----------------------------------------------------------------------------------------------- */

