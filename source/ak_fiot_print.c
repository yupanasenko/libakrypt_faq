/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_fiot_print.с                                                                           */
/*  - содержит функции, реализующие вывод передаваемых фреймов.                                    */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_fiot.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует вывод произвольного буффера с данными.
    \param data Указатель на данные
    \param length Длина данных в байтах
    \param level Уровень сдвига (количество табуляций, первряющих выводимые данные).

    \return Функия возвращает количество выведенных данных.                                        */
/* ----------------------------------------------------------------------------------------------- */
 static ssize_t ak_fiot_context_print_ptr( char *data, ssize_t length, const unsigned int level )
{
  char buffer[1024];
  ssize_t i, j, blocks = length >> 4;
  ssize_t tail = length - (blocks << 4), offset = 0;

  for( i = 0; i < blocks; i++ ) {
     memset( buffer, 0, sizeof( buffer ));
     memset( buffer, ' ', offset = 8*level );
     for( j = 0; j < 16; j++ ) {
        ak_snprintf( buffer+offset, 8, "%02X ", (unsigned char)data[16*i+j] );
        offset += 3;
     }
     ak_error_message( ak_error_ok, "", buffer );
  }
  if( tail ) {
    memset( buffer, 0, sizeof( buffer ));
    memset( buffer, ' ', offset = 8*level );
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
   unsigned int i, ilen = 4, meslen;


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
   if( offset > 8 ) {
     if( offset > 56 ) ak_error_message( error = ak_error_wrong_length, __func__,
                                                               "frame has incorrect offset length" );
      else ak_fiot_context_print_ptr( frame+8, offset-8, 1 );
   }
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
