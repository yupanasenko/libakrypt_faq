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
#ifdef LIBAKRYPT_HAVE_SYSSELECT_H
 #include <sys/select.h>
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

    В заголовок сообщения могут быть помещены дополнительные данные.
    Размер таких данных
    определяется величиной `fctx->header_offset - 8`, где 8 это длина стандартного заголовка.
    Сами данные должны располагаться в `fctx->header_data` и устанавливаться до вызова
    настоящей функции. В случае, если данные в `fctx->header_data` не определены, то
    длина заголовка полагается равной 8.

    \param data Данные, которые помещаются во фрейм и отправляются в канал связи через интрефейс,
    обеспечивающий шифрование информации.
    \param datalen Размер отправляемых данных в байтах.
    \param ftype Тип формируемого фрейма данных
    (данные передаются в зашифрованном или открытом виде)
    \param mtype Тип передаваемых данных

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_write_frame( ak_fiot fctx,
                             ak_pointer data, size_t datalen, frame_type_t ftype, message_t mtype )
{
   ak_mac ikey = NULL;
   ak_bckey ekey = NULL;
   int error = ak_error_ok;
   ak_uint8 *oframe = NULL;
   size_t ilen = 0, olen = 0, framelen = 0, offset = 0;

  /* выполняем минимальные проверки */
   if( fctx->iface_enc == undefined_interface ) return fiot_error_wrong_interface;
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
  /* проверяем, что минимальный разме фрейма удовлетворяет допустимым ограничениям на размер */
   if( framelen > fctx->oframe.size ) return fiot_error_wrong_send_length;

  /* увеличиваем длину фрейма за счет паддинга */
  /*! \note Сейчас при реализации дополнения фрейма используется политика по-умолчанию,
     при которой общая длина фрейма должна быть кратной 16 байтам, если этого сделать
     нельзя, то мы откатываемся назад. Необходимо реализовать все возможные политики в
     соответствии с методическими рекомендациями. */
   if( framelen%16 != 0 ) {
     framelen = ( 1+ ( framelen>>4 )) <<4;
     if( framelen > fctx->oframe.size ) framelen = olen;
   }
  /* теперь собираем фрейм по кусочкам */
   memset( oframe = fctx->oframe.data, 0, fctx->oframe.size );

  /* тип фрейма и размер заголовка */
   oframe[0] = ( ak_uint8 )(( fctx->header_offset << 2 ) + ftype );

  /* размер фрейма */
   oframe[1] = ( ak_uint8 )(( framelen >> 8 )%256 );
   oframe[2] = ( ak_uint8 )( framelen%256 );

  /* номер фрейма */
   oframe[3] = ( ak_uint8 )(( fctx->ncounter )%256 );
   oframe[4] = ( ak_uint8 )((( fctx->mcounter ) >> 8)%256 );
   oframe[5] = ( ak_uint8 )(( fctx->mcounter )%256 );
   oframe[6] = ( ak_uint8 )((( fctx->lcounter ) >> 8)%256 );
   oframe[7] = ( ak_uint8 )(( fctx->lcounter )%256 );

  /* если fctx->header_offset > 8, то добавляем данные в заголовок пакета
     дополнительные данные передаются в открытом виде и занимают область
     с fctx->oframe[8] ... по fctx->ofram[ fctx->header_offset - 1 ] */
   if( fctx->header_offset > 8 ) {
     if( ak_buffer_is_assigned( &fctx->header_data ))
       memcpy( oframe+8, fctx->header_data.data, fctx->header_offset - 8 );
      else memset( oframe+8, 0, fctx->header_offset - 8 );
   }

  /* тип и размер сообщения */
   offset = fctx->header_offset;
   oframe[ offset++ ] = ( ak_uint8 ) mtype;
   oframe[ offset++ ] = ( ak_uint8 )(( datalen >> 8 )%256 );
   oframe[ offset++ ] = ( ak_uint8 )( datalen%256 );

  /* данные */
   memcpy( oframe + offset, data, datalen );

  /* паддинг и контрольная сумма */
   if(( olen = framelen - olen ) > 0 ) fctx->plain_rnd.random( &fctx->plain_rnd,
                                             oframe + offset + datalen, (ssize_t) olen );
  /* по-умолчанию, мы всегда добавляем во фрейм контрольную сумму */
   oframe[ framelen - 2 - ilen ] = ( ak_uint8 ) is_present;
   oframe[ framelen - 1 - ilen ] = ( ak_uint8 ) ilen;

   olen = framelen - ilen - 2;
   if( ftype == plain_frame )
     ak_mac_context_ptr( ikey, oframe, olen, oframe + framelen - ilen );
   else { /* это все только для ctr+omac, mgm впереди ))) */
           ak_mac_context_ptr( ikey, oframe, olen, oframe + framelen - ilen );
           olen -= fctx->header_offset;

          /*! \todo здесь надо аккуратно определить iv */
           ak_bckey_context_xcrypt( ekey, oframe + fctx->header_offset,
                                             oframe + fctx->header_offset, olen, oframe, 8 );
        }

  /* контрольный вывод */
   if( ak_log_get_level() >= fiot_log_maximum )
     ak_fiot_context_log_frame( fctx->oframe.data, framelen );

   if( fctx->write( fctx->iface_enc, fctx->oframe.data, framelen ) != ( ssize_t ) framelen )
    ak_error_set_value( error = ak_error_write_data );

  /* изменяем значения счетчиков и ключей после отправки фрейма в канал связи */
   ak_fiot_context_increment_counters( fctx );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция интерпретирует входящие данные, на которые указывает `data`, как единый массив октетов
    с известной длиной. Массив разбивается на фрагменты, длина которых не превосходит максимально
    возможной длины отправляемого фрейма. Максимально возможная длина отправляемого фрейма
    определяется значением `fctx->oframe_size`, которое может изменяться пользователем.

    После разбиения, все фрагменты, последовательно, отправляются в канал связи
    с помощью функции ak_fiot_context_write_frame().
    Все передаваемые данные помещаются во фреймы типа application data и зашифровываются.

    \param fctx Контекст защищенного соединения протокола sp fiot.
    Контекст должен быть предварительно создан, а ключевые значения инициализированы.
    \param data Данные, которые помещаются во фрейм и отправляются в канал.
    \param datalen Размер отправляемых данных в байтах.

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    Иначе, возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_write_application_data( ak_fiot fctx, ak_pointer data, size_t datalen )
{
  int error = ak_error_ok;
  ak_uint8 *dataptr = data;
  size_t meslen = 0, ilen = 0;

  if( fctx == NULL ) ak_error_message( ak_error_null_pointer, __func__,
                                                           "using null pointer to fiot context" );
  ilen = ( fctx->role == client_role ) ? fctx->icfk->hsize : fctx->isfk->hsize;
  meslen = fctx->oframe.size - fctx->header_offset - 3 - 2 - ilen;

  while( datalen > 0 ) {
    ilen = ak_min( meslen, datalen ); /* получаем длину отправляемого фрагмента */
    if(( error = ak_fiot_context_write_frame( fctx,
                             dataptr, ilen, encrypted_frame, application_data )) != ak_error_ok )
      return ak_error_message( error, __func__, "write application data error" );
    dataptr += ilen; datalen -= ilen;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция ожидает данные в течение заданного временного интревала.
    По истечении времени, если данные не получены, возвращается ошибка.

    \param fctx Контекст защищенного соединения.
    \param gate Интерфейс, на котором ожидаются данные.
    \param buffer Указатель на область памяти, в которую помещаются полученные данные
    \param length Размер области памяти в байтах.
    \return Функция возвращает количество полученных данных.                                       */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_fiot_context_read_ptr_timeout( ak_fiot fctx, interface_t gate,
                                                                  ak_pointer buffer, size_t length )
{
    int fd = -1;
#ifdef LIBAKRYPT_HAVE_SYSSELECT_H
    fd_set fdset;
    struct timeval tv;
#endif
    if( gate == encryption_interface ) fd = fctx->iface_enc;
      else fd = fctx->iface_plain;

#ifdef LIBAKRYPT_HAVE_SYSSELECT_H
    tv.tv_usec = 0; tv.tv_sec = fctx->timeout;

    FD_ZERO( &fdset );
    FD_SET( fd, &fdset );
    if( select( fd+1, &fdset, NULL, NULL, &tv ) <= 0 )
      return ak_error_set_value( ak_error_read_data );
#endif

 return fctx->read( fd, buffer, length );
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
 ak_uint8 *ak_fiot_context_read_frame( ak_fiot fctx, size_t *length, message_t *mtype )
{
   ak_uint8 out[64]; /* максимальная длина имитовставки - длина хэшкода для Стрибога 512 */
   ak_mac ikey = NULL;
   ak_bckey ekey = NULL;
   ak_uint8 *frame = NULL;
   int i, error = ak_error_ok;
   size_t ilen = 4, ftype = 0, offset = 0, framelen = 0;

  /* необходимые проверки */
   if( fctx->iface_enc == undefined_interface ) {
     ak_error_set_value( fiot_error_wrong_interface );
     return NULL;
   }
   if(( fctx->inframe.data == NULL ) || ( fctx->inframe.size == 0 )) {
     ak_error_set_value( ak_error_wrong_buffer );
     return NULL;
   }

  /* в начале пытаемся получить из канала связи три байта, содержащие тип фрейма и его длину */
   memset( frame = fctx->inframe.data, 0, fctx->inframe.size );
   if( ak_fiot_context_read_ptr_timeout( fctx,
                            encryption_interface, fctx->inframe.data, 3 ) != 3 ) return NULL;
  /* проверяем, что тип полученного фрейма корректен */
   ftype = frame[0]&0x3;
   if(( ftype != plain_frame ) && ( ftype != encrypted_frame )) {
     ak_error_set_value( fiot_error_frame_type );
     return NULL;
   }

  /* определяем длину заголовка */
   offset = frame[0]>>2;

  /* проверяем, что длина полученного фрейма корректна */
   framelen = frame[2] + frame[1]*256;
   if(( framelen > fiot_max_frame_size ) || ( framelen < offset + 14 )) {
                              /* константа 14 формируется следующим образом:
                                 тип сообщения - 1 октет
                                 истинная длина сообщения - 2 октета
                                 как минимум - 1 октет сообщения (сообщения всегда не пусты)
                                 флаг наличия имитовставки + ее длина - 2 октета
                                 миниумум 8 октетов имитовставки */
     ak_error_set_value( fiot_error_frame_size );
     return NULL;
   }
  /* при необходимости, увеличиваем объем внутреннего буффера */
   if( framelen > fctx->inframe.size )
     if(( error = ak_fiot_context_set_frame_size( fctx, inframe, framelen )) != ak_error_ok )
       return NULL;

  /* теперь получаем из канала основное тело пакета */
   if( ak_fiot_context_read_ptr_timeout( fctx, encryption_interface,
                               frame+3, framelen-3 ) != ( ssize_t ) framelen-3 ) return NULL;
   if( ak_log_get_level() >= fiot_log_maximum )
     ak_fiot_context_log_frame( frame, framelen );

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
      size_t idx = framelen-1-ilen;
      if( idx < 1 ) { ilen = 256; break; }
      if( idx > framelen-1 ) { ilen = 256; break; }
      if(( frame[idx] == ilen ) && ( frame[idx-1] == is_present )) break;
      ilen <<= 1;
   }
   if( ilen > 128 ) { /* значение имитовставки слишком большое */
     ak_error_set_value( fiot_error_frame_format );
     return NULL;
   }
   if( ilen != ikey->hsize ) { /* длина имитовставки полученного фрейма не совпадает
                                           с длиной имитовставки для установленного ключа */
     ak_error_set_value( fiot_error_wrong_mechanism );
     return NULL;
   }

 /* расшифровываем и проверяем контрольную сумму */
   if( ftype == encrypted_frame ) {
    /*! \todo здесь надо аккуратно определить iv */
     ak_bckey_context_xcrypt( ekey, frame + offset,
                                  frame + offset, framelen - offset - ilen - 2, frame, 8 );
   }
   ak_mac_context_ptr( ikey, frame, framelen - ilen - 2, out );
   if( memcmp( frame + framelen - ilen, out, ilen ) != 0 ) {
     ak_error_set_value( ak_error_not_equal_data );
     return NULL;
   }

 /* теперь помещаем значения полей */
   *mtype = ( message_t ) frame[ offset++ ];
   *length = frame[ offset++ ]*256;
   *length += frame[ offset++ ];

 return frame + offset;
}

/* ----------------------------------------------------------------------------------------------- */
/*             далее идет группа функций, реализующих аудит передаваемых фреймов                   */
/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует вывод произвольного буффера с данными.
    \param data Указатель на данные
    \param length Длина данных в байтах
    \param level Уровень сдвига (количество табуляций, предваряющих выводимые данные).

    \return Функия возвращает количество выведенных данных.                                        */
/* ----------------------------------------------------------------------------------------------- */
 static size_t ak_fiot_context_log_ptr( ak_uint8 *data, size_t length, const unsigned int level )
{
  char buffer[1024];
  size_t i, j, blocks = length >> 4;
  size_t tail = length - (blocks << 4), offset = 0;

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
/*! \details Функция не только выводит содержимое фрейма с помощью действующего механизма аудита,
    но и выполняет проверку корректности переданного ей фрейма. Функция пытается декомпозировать
    полученную последовательность октетов в качестве правильно сформированного фрейма. При этом
    криптографические проверки не производятся.

    \param frame Указатель на последовательность октетов, содержащую сериализованное
           представление фрейма.
    \param framelen Длина последовательности октетов.
    \return В случае удачной декомпозиции фрейма функция возвращает \ref ak_erro_ok.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_fiot_context_log_frame( ak_uint8 *frame, size_t framelen )
{
   char buffer[1024];
   size_t offset = 0;
   ak_uint8 *message = NULL;
   int error = ak_error_ok;
   unsigned int i, ilen = 4;

  /* необходимые проверки */
   if( frame == NULL )
     return ak_error_message( ak_error_null_pointer, "", "using null pointer to frame" );

  /* выводим общую информацию */
   ak_error_message( ak_error_ok, __func__, "" );
   ak_error_message_fmt( ak_error_ok, "",  "%ld octets", framelen );
   ak_fiot_context_log_ptr( frame, framelen, 1 );
   if( framelen <= 8 ) return ak_error_message_fmt( ak_error_wrong_length, __func__,
                                                  "insufficient length of frame", framelen );

   ak_error_message_fmt( ak_error_ok, "",  "header [%u octets]", ( offset = frame[0]>>2 ));
   if(( offset < 8 ) || ( offset > framelen ))
     return ak_error_message( ak_error_wrong_length, "", "incorrect value of frame offset" );
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
   if( offset > 8 ) ak_fiot_context_log_ptr( frame+8, offset-8, 1 );
   if( error != ak_error_ok ) return ak_error_message( error, __func__,
                                                             "frame is broken (unexpected header)" );

  /* пытаемся определить значение имитовставки без использования контекста протокола
    (реализуется поиск по массиву данных с целью найти маркер наличия имитовставки и ее длину ) */
   for( i = 0; i < 6; i++ ) {
      size_t idx = framelen-1-ilen;
      if( idx < 1 ) { ilen = 256; break; }
      if( idx > framelen-1 ) { ilen = 256; break; }
      if((( unsigned int )frame[idx] == ilen ) && ( frame[idx-1] == is_present )) break;
      ilen <<= 1;
   }
   if( ilen > 128 ) return ak_error_message_fmt( fiot_error_frame_format, __func__,
                                            "frame is broken (wrong integrity tag size: %u)", ilen );

  /* выводим зашифрованную часть */
   if(( frame[0]&0x3 ) == encrypted_frame ) {
     ak_error_message_fmt( ak_error_ok, "", "body [%lu octets, encrypted]", framelen-ilen-2-offset );
     ak_fiot_context_log_ptr( frame+offset, framelen-ilen-2-offset, 1 );
   } else {
            /* здесь должен быть разбор незашифрованных сообщений */
          }

  /* теперь выводим значение имитовставки */
   if( !ilen ) return ak_error_message( fiot_error_frame_format, __func__,
                                           "frame is broken (undefined length of integrity tag)" );
   ak_error_message_fmt( ak_error_ok, "", "icode [%lu octets]", ilen+2 );
   if( frame[framelen-1] == not_present )
     return ak_error_message( ak_error_ok, __func__, "frame is broken (integrity tag is'nt present)" );

   message = frame + framelen - 2 - ilen;
    switch( message[0] )
   {
     case is_present:
        ak_error_message_fmt( ak_error_ok, "", "        %02X [tag: present]", message[0] );
        ak_error_message_fmt( ak_error_ok, "", "        %02X [length: %lu octets]",
                                                                  message[1], message[1] );
        ak_fiot_context_log_ptr( message+2, message[1], 1 );
        break;
     case not_present:
        ak_error_message_fmt( ak_error_ok, "", "        %02X [tag: not present]", message[0] );
        break;
   }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                             ak_fiot_protocol.c  */
/* ----------------------------------------------------------------------------------------------- */

