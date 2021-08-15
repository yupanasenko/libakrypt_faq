/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2021 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_asn1_cert.c                                                                            */
/*  - содержит реализацию функций, предназначенных для экспорта/импорта открытых ключей            */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-internal.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_STRING_H
 #include <string.h>
#endif
#ifdef AK_HAVE_TIME_H
 #include <time.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
                  /* Функции экспорта открытых ключей в запрос на сертификат */
/* ----------------------------------------------------------------------------------------------- */
 int ak_request_destroy( ak_request req )
{
  int error = ak_error_ok;
  if( req == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to request options context" );
  if(( error = ak_verifykey_destroy( &req->vkey )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong destroying of verifykey context" );

  if( req->opts.subject != NULL )
    ak_tlv_delete( req->opts.subject );

  memset( req, 0, sizeof( struct request ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует фрагмент asn1 дерева, содержащий параметры открытого ключа.
    \param vk контекст открытого ключа
    \return Функция возвращает указатель на tlv узел, содержащий сформированную структуру.
    В случае ошибки возвращается `NULL`.                                                           */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_verifykey_export_to_asn1_value( ak_verifykey vk )
{
  ak_oid ec = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_tlv tlv = NULL, os = NULL;
  ak_asn1 asn = NULL, basn = NULL;
  size_t val64 = sizeof( ak_uint64 )*vk->wc->size;          /* количество октетов в одном вычете */
  ak_uint8 data[ 2*sizeof(ak_uint64)*ak_mpznmax_size ];    /* asn1 представление открытого ключа */
  ak_uint8 encode[ 4 + sizeof( data )];                             /* кодированная octet string */
  size_t sz = sizeof( encode );

  if(( error = ak_asn1_add_oid( asn = ak_asn1_new(), vk->oid->id[0] )) != ak_error_ok ) goto labex;
  if(( error = ak_asn1_add_asn1( asn, TSEQUENCE, ak_asn1_new( ))) != ak_error_ok ) goto labex;
  if(( ec = ak_oid_find_by_data( vk->wc )) == NULL ) {
    ak_error_message( ak_error_wrong_oid, __func__,
                                 "public key has incorrect pointer to elliptic curve parameters" );
    goto labex;
  }
  ak_asn1_add_oid( asn->current->data.constructed, ec->id[0] );
  ak_asn1_add_oid( asn->current->data.constructed, vk->ctx.oid->id[0] );

  if(( basn = ak_asn1_new()) == NULL ) goto labex;
  if(( error = ak_asn1_add_asn1( basn, TSEQUENCE, asn )) != ak_error_ok ) {
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }

 /* кодируем открытый ключ => готовим octet string */
  memset( data, 0, sizeof( data ));
  if(( os = ak_tlv_new_primitive( TOCTET_STRING, ( val64<<1 ), data, ak_false )) == NULL ){
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }
 /* помещаем в нее данные */
  ak_wpoint_reduce( &vk->qpoint, vk->wc );
  ak_mpzn_to_little_endian( vk->qpoint.x, vk->wc->size, data, val64, ak_false );
  ak_mpzn_to_little_endian( vk->qpoint.y, vk->wc->size, data+val64, val64, ak_false );
  if(( error = ak_tlv_encode( os, encode, &sz )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encoding of temporary tlv context" );
    if( os != NULL ) ak_tlv_delete( os );
    if( basn != NULL ) ak_asn1_delete( basn );
    goto labex;
  }
  bs.value = encode;
  bs.len = sz;
  bs.unused = 0;
  ak_asn1_add_bit_string( basn, &bs );
  if(( tlv = ak_tlv_new_constructed( TSEQUENCE^CONSTRUCTED, basn )) == NULL ) {
    ak_asn1_delete( basn );
    ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect addition the bit sting with public key value" );
  }

  ak_tlv_delete( os );
 return  tlv;

 labex:
  if( asn != NULL ) ak_asn1_delete( asn );
  ak_error_message( error, __func__, "incorrect export of public key into request asn1 tree" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Выполняются следующие действия:

    - формируется tlv элемент, содержащий имя владельца, параметры алгоритма и значение ключа,
    - tlv элемент кодируется в der-последовательность,
    - вырабатывается подпись под der-последовательностью,
    - идентификатор алгоритма выработки подписи и значение подписи также помещаются в asn1 дерево.

   \param req контекст запроса на сертификат, содержащий в себе
    открытый ключ и ряд параметров экспорта
   \param sk контекст секретного ключа, соответствующего экспортируемому открытому ключу
   \param a уровень asn1 дерева, в который помещается запрос на сертификат.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_request_export_to_asn1( ak_request req, ak_signkey sk, ak_random generator, ak_asn1 a )
{
  ak_asn1 asn = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_uint8 data[4096], s[128];
  size_t size = sizeof( data );
  ak_verifykey vk = &req->vkey;
  ak_tlv tlv = NULL, pkey = NULL;

  if( req == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to request context" );
  if( sk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( a == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to asn1 context" );
  if( !ak_ptr_is_equal( vk->number, sk->verifykey_number, sizeof( vk->number )))
    return ak_error_message( ak_error_not_equal_data, __func__,
                                                     "secret key not correspondig to public key" );
  if( ak_signkey_get_tag_size( sk ) > sizeof( s ))
    ak_error_message( ak_error_wrong_length, __func__,
                                   "using digital signature algorithm with very large signature" );

 /* 1. Создаем последовательность, которая будет содержать данные запроса */
  if(( error = ak_asn1_add_asn1( a, TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new())) != ak_error_ok ) {
    if( asn != NULL ) ak_asn1_delete( asn );
    return ak_error_message( error, __func__, "incorrect creation of first level sequence");
  }

 /* 2. Создаем tlv элемент, для которого, потом, будет вычисляться электронная подпись */
   tlv = ak_tlv_new_constructed( TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new( ));
  /* добавляем ноль */
   ak_asn1_add_uint32( asn, 0 );
  /* копируем asn1 дерево с расширенным именем из структуры открытого ключа
     в asn1 дерево формируемого запроса */
   ak_asn1_add_tlv( asn, ak_tlv_duplicate_global_name( req->opts.subject ));

  /* помещаем информацию об алгоритме и открытом ключе */
   ak_asn1_add_tlv( asn, pkey = ak_verifykey_export_to_asn1_value( vk ));
   if( pkey == NULL ) {
     if( tlv != NULL ) ak_tlv_delete( tlv );
     return ak_error_message( ak_error_get_value(), __func__,
                                               "incorrect export of public key into tlv context" );
   }
  /* 0x00 это помещаемое в CONTEXT_SPECIFIC значение */
   ak_asn1_add_asn1( asn, CONTEXT_SPECIFIC^0x00, ak_asn1_new( ));

  /* 3. Помещаем tlv элемент в основное дерево */
   ak_asn1_add_tlv( a->current->data.constructed, tlv );

  /* 4. Помещаем идентификатор алгоритма выработки подписи */
   ak_asn1_add_asn1( a->current->data.constructed, TSEQUENCE^CONSTRUCTED, asn = ak_asn1_new());
   ak_asn1_add_oid( asn, sk->key.oid->id[0] );

  /* 4. Помещаем bit-string со значением подписи */
   if(( error =  ak_tlv_encode( tlv, data, &size )) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect encoding of asn1 context");

   memset( s, 0, sizeof( s ));
   if(( error = ak_signkey_sign_ptr( sk, generator, data, size, s, sizeof( s ))) != ak_error_ok )
     return ak_error_message( error, __func__, "incorrect signing internal data" );
   bs.value = s;
   bs.len = ak_signkey_get_tag_size( sk );
   bs.unused = 0;
   if(( error = ak_asn1_add_bit_string( a->current->data.constructed, &bs )) != ak_error_ok )
     ak_error_message( error, __func__, "incorrect adding a digital signature value" );

  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию
    и сохраняет созданное дерево в файл, который называется "запросом на сертификат".

   \note Контекст секретного ключа `sk` должен соответствовать контексту открытого ключа `vk`,
   помещеному в конеткст запроса.
   В противном случае нельзя будет проверить электронную подпись под открытым ключом, поскольку
   запрос на сертификат, по сути, является урезанной версией самоподписанного сертификата.
   Отсюда следует, что нельзя создать запрос на сертификат ключа, который не поддерживает
   определенный библиотекой алгоритм подписи (например ключ на кривой в 640 бит).
   Такие ключи должны сразу помещаться в сертификат.

   \param req контекст запроса на сертификат, содержащий в себе
    открытый ключ и ряд параметров экспорта
   \param sk Контекст секретного ключа, соответствующий открытому ключу
   \param generator Генератор псевдослучайных последовательностей, используемый для выработки
    электронной подписи под запросом на сертификат
   \param filename Указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
   \param size  Размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
   \param format Формат, в котором сохраняются данные - der или pem.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_request_export_to_file( ak_request req, ak_signkey sk, ak_random generator,
                                       char *filename, const size_t size, export_format_t format )
{
  ak_asn1 asn = NULL;
  int error = ak_error_ok;

  if( req == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to request context" );
  if( sk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                               "using null pointer to file name" );

 /* 1. При необходимости, формируем имя файла для экспорта открытого ключа
       Формируемое имя совпадает с номером ключа и однозначно зависит от его значения */
  if( size != 0 ) {
    memset( filename, 0, size );
    if( size < 12 ) return ak_error_message( ak_error_wrong_length, __func__,
                                               "using small buffer to storing request file name" );
     else ak_snprintf( filename, size, "%s.csr",
                          ak_ptr_to_hexstr( req->vkey.number, req->vkey.number_length, ak_false ));
  }

 /* 2. Создаем asn1 дерево */
  if(( error = ak_request_export_to_asn1( req, sk, generator,
                                                         asn = ak_asn1_new( ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation af asn1 context" );
    goto labexit;
  }

 /* 3. Сохраняем созданное дерево в файл */
  if(( error = ak_asn1_export_to_file( asn,
                                filename, format, public_key_request_content )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "incorrect export asn1 context to file %s", filename );
    goto labexit;
  }

  labexit:
    if( asn != NULL ) ak_asn1_delete( asn );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                 /* Функции импорта открытых ключей из запроса на сертификат */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_import_from_asn1_value( ak_verifykey vkey, ak_asn1 asnkey )
{
  size_t size = 0;
  ak_oid oid = NULL;
  struct bit_string bs;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;
  ak_asn1 asn = asnkey, asnl1;
  ak_uint32 val = 0, val64 = 0;

 /* проверяем наличие последовательности верхнего уровня */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                               "the first next level element must be a sequence" );
 /* получаем алгоритм электронной подписи */
  ak_asn1_first( asnl1 = asn->current->data.constructed );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOBJECT_IDENTIFIER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                          "the first element of child asn1 context must be an object identifier" );
  if(( error = ak_tlv_get_oid( asnl1->current, &ptr )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect reading an object identifier" );

  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message_fmt( ak_error_oid_id, __func__,
                                                   "using unsupported object identifier %s", ptr );
  if(( oid->engine != verify_function ) || ( oid->mode != algorithm ))
    return ak_error_message( ak_error_oid_engine, __func__, "using wrong object identifier" );

 /* получаем параметры элиптической кривой */
  ak_asn1_next( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
             "the second element of child asn1 context must be a sequence of object identifiers" );
  asnl1 = asnl1->current->data.constructed;

  ak_asn1_first( asnl1 );
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOBJECT_IDENTIFIER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                     "the first element of last child asn1 context must be an object identifier" );
  if(( error = ak_tlv_get_oid( asnl1->current, &ptr )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect reading an object identifier" );

  if(( oid = ak_oid_find_by_id( ptr )) == NULL )
    return ak_error_message_fmt( ak_error_oid_id, __func__,
                            "import an unsupported object identifier %s for elliptic curve", ptr );
  if(( oid->engine != identifier ) || ( oid->mode != wcurve_params ))
    return ak_error_message( ak_error_oid_engine, __func__, "using wrong object identifier" );

 /* создаем контекст */
  asnl1 = NULL;
  if(( error = ak_verifykey_create( vkey, (const ak_wcurve )oid->data )) != ak_error_ok )
   return ak_error_message( error, __func__, "incorrect creation of verify key context" );

 /* получаем значение открытого ключа */
  ak_asn1_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_get_bit_string( asn->current, &bs )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect reading a bit string" );
    goto lab1;
  }

 /* считали битовую строку, проверяем что это der-кодировка некоторого целого числа */
  if(( error = ak_asn1_decode( asnl1 = ak_asn1_new(),
                                                  bs.value, bs.len, ak_false )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect decoding a value of public key" );
    goto lab1;
  }
  if(( DATA_STRUCTURE( asnl1->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asnl1->current->tag ) != TOCTET_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                                        "the public key must be an octet string" );
    goto lab1;
  }

 /* считываем строку и разбиваем ее на две половинки */
  val = ( ak_uint32 )vkey->wc->size;
  val64 = sizeof( ak_uint64 )*val;
  ak_tlv_get_octet_string( asnl1->current, &ptr, &size );
  if( size != 2*val64 ) {
    ak_error_message_fmt( error = ak_error_wrong_length, __func__ ,
        "the size of public key is equal to %u (must be %u octets)", (unsigned int)size, 2*val64 );
    goto lab1;
  }

 /* копируем данные и проверям, что точка действительно принадлежит кривой */
  ak_mpzn_set_little_endian( vkey->qpoint.x, val, ptr, val64, ak_false );
  ak_mpzn_set_little_endian( vkey->qpoint.y, val, ((ak_uint8*)ptr)+val64, val64, ak_false );
  ak_mpzn_set_ui( vkey->qpoint.z, val, 1 );
  if( ak_wpoint_is_ok( &vkey->qpoint, vkey->wc ) != ak_true ) {
    ak_error_message_fmt( error = ak_error_curve_point, __func__ ,
                                                  "the public key isn't on given elliptic curve" );
    goto lab1;
  }

 /* устанавливаем флаг */
  vkey->flags = key_flag_set_key;

 lab1:
  if( asnl1 != NULL ) ak_asn1_delete( asnl1 );
  if( error != ak_error_ok ) ak_verifykey_destroy( vkey );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция получает значение открытого ключа из запроса на сертификат,
    разобранного в ASN.1 дерево, и создает контекст открытого ключа.

    Функция считывает oid алгоритма подписи и проверяет, что он соответствует ГОСТ Р 34.12-2012,
    потом функция считывает параметры эллиптической кривой и проверяет, что библиотека поддерживает
    данные параметры. В заключение функция считывает открытый ключ и проверяет,
    что он принадлежит кривой со считанными ранее параметрами.

    После выполнения всех проверок, функция создает (действие `create`) контекст открытого ключа,
    а также присваивает (действие `set_key`) ему считанное из asn1 дерева значение.

    \param req контекст запроса на сертификат для
    создаваемого открытого ключа асимметричного криптографического алгоритма
    \param asnkey считанное из файла asn1 дерево
    \param reqopt опции запроса на сертификат, считываемые вместе со значением открытого ключа


    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_request_import_from_asn1( ak_request req, ak_asn1 asnkey )
{
  ak_uint32 val = 0;
  ak_asn1 asn = asnkey; /* копируем адрес */

 /* проверяем, что первым элементом содержится ноль */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TINTEGER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                          "the first element of root asn1 context be an integer" );
  ak_tlv_get_uint32( asn->current, &val );
 /* проверяемое нами значение 0 соотвествует единственному
    поддерживаемому формату запроса не сертифкат */
  if( val ) return ak_error_message( ak_error_invalid_asn1_content, __func__ ,
                                              "the first element of asn1 context must be a zero" );
  req->opts.version = val+1;

 /* второй элемент содержит имя владельца ключа,
    этот элемент будет перенесен в контекст опций открытого ключа после проверки подписи */
  ak_asn1_next( asn );

 /* третий элемент должен быть SEQUENCE с набором oid и значением ключа */
  if( ak_asn1_next( asn ) != ak_true )
    return ak_error_message( ak_error_invalid_asn1_count, __func__, "unexpected end of asn1 tree" );

 /* проверяем наличие последовательности верхнего уровня */
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                      "the element of root asn1 tree must be a sequence with object identifiers" );
  asn = asn->current->data.constructed;

 return ak_verifykey_import_from_asn1_value( &req->vkey, asn );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция считывает из заданного файла запрос на получение сертификата. Запрос хранится в виде
    asn1 дерева, определяемого Р 1323565.1.023-2018.
    Собственно asn1 дерево может быть храниться в файле в виде обычной der-последовательности,
    либо в виде der-последовательности, дополнительно закодированной в `base64` (формат `pem`).
    После считывания asn1 дерева  функция проверяет подпись под открытым ключом и,
    в случае успешной проверки, создает контекст и инициирует его необходимыми значениями.

    \note Функция является конструктором контекста ak_request (и ak_verifykey, в частности)

    \param req контекст на сертификат, содержит в себе открытый ключ
     асимметричного криптографического алгоритма, а также параметры ключа
    \param filename имя файла

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_request_import_from_file( ak_request req, const char *filename )
{
  size_t size = 0;
  ak_tlv tlv = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_uint8 buffer[1024], *ptr = NULL;
  ak_asn1 root = NULL, asn = NULL;

 /* стандартные проверки */
  if( req == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to request context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to filename" );
 /* считываем ключ и преобразуем его в ASN.1 дерево */
  if(( error = ak_asn1_import_from_file( root = ak_asn1_new(), filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
    goto lab1;
  }
 /* проверяем, что данные содержат хоть какое-то значение */
  if(( root->count == 0 ) || ( root->current == NULL )) {
    ak_error_message_fmt( error = ak_error_null_pointer, __func__,
                                           "reading a zero ASN.1 context from %s file", filename );
    goto lab1;
  }

 /* здесь мы считали asn1, декодировали и должны убедиться, что это то самое дерево */
  ak_asn1_first( root );
  tlv = root->current;
  if( DATA_STRUCTURE( tlv->tag ) != CONSTRUCTED ) {
    ak_error_message( error = ak_error_invalid_asn1_tag,
                                                 __func__, "incorrect structure of asn1 context" );
    goto lab1;
  }

 /* проверяем количество узлов */
  if(( asn = tlv->data.constructed )->count != 3 ) {
    ak_error_message_fmt( error = ak_error_invalid_asn1_count, __func__,
                                          "root asn1 context contains incorrect count of leaves" );
    goto lab1;
  }

 /* первый узел позволит нам получить значение открытого ключа
    (мы считываем параметры эллиптической кривой, инициализируем контекст значением
    открытого ключа и проверяем, что ключ принадлежит указанной кривой ) */
  ak_asn1_first( asn );
  if( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__,
                                                           "incorrect structure of asn1 context" );
    goto lab1;
  }
  if(( error = ak_request_import_from_asn1( req,
                                               asn->current->data.constructed )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect structure of request" );
    goto lab1;
  }
 /* 4. На основе считанных данных формируем номер ключа */
  if(( error = ak_verifykey_set_number( &req->vkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation on public key number" );
    goto lab1;
  }

 /* второй узел, в нашей терминологии, содержит идентификатор секретного ключа
    и бесполезен, поскольку вся информация об открытом ключе проверки подписи,
    эллиптической кривой и ее параметрах уже считана. */
  ak_asn1_next( asn );


 /* третий узел -> остается только проверить подпись,
    расположенную в последнем, третьем узле запроса. */

 /* 1. Начинаем с того, что готовим данные, под которыми должна быть проверена подпись */
  ak_asn1_first( asn );
  if(( error = ak_tlv_evaluate_length( asn->current, &size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect evaluation of encoded tlv context length");
    goto lab1;
  }
  if( size > sizeof( buffer )) { /* выделяем память, если статической не хватает */
    if(( ptr = malloc( size )) == NULL ) {
      ak_error_message( ak_error_out_of_memory, __func__, "memory allocation error");
      goto lab1;
    }
     else memset( ptr, 0, size );
  }
   else {
     ptr = buffer;
     memset( buffer, 0, size = sizeof( buffer ));
   }

  if(( error = ak_tlv_encode( asn->current, ptr, &size )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                 "incorrect encoding of tlv context contains of %u octets", (unsigned int) size );
    goto lab1;
  }

 /* 2. Теперь получаем значение подписи из asn1 дерева и сравниваем его с вычисленным значением */
  ak_asn1_last( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_get_bit_string( asn->current, &bs )) != ak_error_ok ) {
    ak_error_message( error , __func__ , "incorrect value of bit string in root asn1 context" );
    goto lab1;
  }

 /* 3. Только сейчас проверяем подпись под данными */
  if( ak_verifykey_verify_ptr( &req->vkey, ptr, size, bs.value ) != ak_true ) {
    ak_error_message( error = ak_error_not_equal_data, __func__, "digital signature isn't valid" );
    goto lab1;
  }
   else { /* копируем значение подписи в опции запроса на сертификат */
       memset( req->opts.signature, 0, sizeof( req->opts.signature ));
       memcpy( req->opts.signature, bs.value, ak_min( sizeof( req->opts.signature ),
                                                        2*ak_hash_get_tag_size( &req->vkey.ctx )));
   }

 /* 5. В самом конце, после проверки подписи,
    изымаем узел, содержащий имя владельца открытого ключа -- далее этот узел будет перемещен
    в сертификат открытого ключа.
    Все проверки пройдены ранее и нам точно известна структура asn1 дерева. */
  ak_asn1_first( asn );
  if(( asn = asn->current->data.constructed ) != NULL ) {
   ak_asn1_first( asn );
   ak_asn1_next( asn ); /* нужен второй узел */
   req->opts.subject = ak_asn1_exclude( asn );
  }

 lab1:
  if( root != NULL ) ak_asn1_delete( root );
  if(( ptr != NULL ) && ( ptr != buffer )) free( ptr );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                      /* Служебные функции для работы с сертификатами */
/* ----------------------------------------------------------------------------------------------- */
/*! Данный номер зависит от номера секретного ключа, подписывающего открытый ключ и,
    тем самым, может принимать различные значения для каждого из подписывающих ключей.

    Серийный номер сертификата, по-умолчанию, образуют младшие 32 байта результата хеширования
    последовательной конкатенации номеров открытого и секретного ключей.
    Для хеширования используется функция, определенная в контексте `секретного` ключа,
    т.е. Стрибог512 для длинной подписи и Стрибог256 для короткой.

   \code
    result[0 .. size-1] = LSB( size, Hash( vk->number || sk->number ))
   \endcode

    Вычисленное значение не размещается в контексте открытого ключа, а
    помещается в заданную область памяти. Это позволяет использовать данную функцию как при экспорте,
    так и при импорте сертификатов открытых ключей (в момент разбора цепочек сертификации).

   \param vk контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param sk контекст ключа подписи, содержащий параметры центра сертификации
   \param buf буффер, в котором размещается серийный номер.
   \param size размер буффера (в октетах).
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_generate_serial_number( ak_verifykey vk, ak_signkey sk,
                                                                 ak_uint8 *buf, const size_t size )
{
  if( vk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to verifykey context" );
  if( sk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( size > ak_hash_get_tag_size( &sk->ctx ))
    return ak_error_message( ak_error_wrong_length, __func__,
                                                 "the buffer size exceeds the permissible bound" );
 /* используем для хеширования контекст секретного ключа */
  ak_hash_clean( &sk->ctx );
  ak_hash_update( &sk->ctx, vk->number, sizeof( vk->number ));
  ak_hash_finalize( &sk->ctx, sk->key.number, sizeof( sk->key.number ), buf, size );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param cert контекст сертификата открытого ключа
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль), в противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_opts_create( ak_certificate_opts opts )
{
  if( opts == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "initializing null pointer to certificate options" );
 /* значения по умолчанию */
  memset( opts, 0, sizeof( struct certificate_opts ));
  opts->subject = NULL;
  opts->issuer = NULL;
  opts->ext_ca.is_present = ak_false;
  opts->ext_key_usage.is_present = ak_false;
  opts->ext_subjkey.is_present = ak_false;
  opts->ext_authoritykey.is_present = ak_false;
  opts->created = ak_false;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_destroy( ak_certificate cert )
{
  int error = ak_error_ok;
  if( cert == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to certificate context" );
  if(( error = ak_verifykey_destroy( &cert->vkey )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong destroying of verifykey context" );

  if( cert->opts.subject != NULL ) ak_tlv_delete( cert->opts.subject );
  if( cert->opts.issuer != NULL ) ak_tlv_delete( cert->opts.issuer );

  memset( cert, 0, sizeof( struct certificate ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                   Функции создания расширений x509v3 для сертификатов                           */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает расширение x509v3 следующего вида.

 \code
   ├SEQUENCE┐
            ├OBJECT IDENTIFIER 2.5.29.14 (subject-key-identifier)
            └OCTET STRING
               04 14 9B 85 5E FB 81 DC 4D 59 07 51 63 CF BE DF
               DA 2C 7F C9 44 3C
               ├ ( decoded 22 octets)
               └OCTET STRING
                  9B 85 5E FB 81 DC 4D 59 07 51 63 CF BE DF DA 2C  // данные, на которые
                  7F C9 44 3C                                      // указывает ptr
 \endcode

 \param ptr указатель на область памяти, содержащую идентификатор ключа
 \param size размер области памяти
 \return Функция возвращает указатель на структуру узла. Данная структура должна
  быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
  удаления дерева, в который данный узел будет входить.
  В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
  функции ak_error_get_value().                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_subject_key_identifier( ak_pointer ptr, const size_t size )
{
  ak_uint8 encode[256]; /* очень длинные идентификаторы это плохо */
  ak_tlv tlv = NULL, os = NULL;
  size_t len = sizeof( encode );

  if(( tlv = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
 /* добавляем идентификатор расширения */
  ak_asn1_add_oid( tlv->data.constructed, "2.5.29.14" );
 /* добавляем закодированный идентификатор (номер) ключа */
  memset( encode, 0, sizeof( encode ));
  if(( os = ak_tlv_new_primitive( TOCTET_STRING, size, ptr, ak_false )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  if( ak_tlv_encode( os, encode, &len ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                    "incorrect encoding a temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  ak_tlv_delete( os );
 /* собственно вставка в asn1 дерево */
  ak_asn1_add_octet_string( tlv->data.constructed, encode, len );
 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает расширение x509v3, определяемое следующей структурой

  \code
   id-ce-basicConstraints OBJECT IDENTIFIER ::=  { 2 5 29 19 }

   BasicConstraints ::= SEQUENCE {
        cA                      BOOLEAN DEFAULT FALSE,
        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
  \endcode


  Пример иерархического представления данного расширения выгдядит следующим образом.

 \code
   └SEQUENCE┐
            ├OBJECT IDENTIFIER 2.5.29.19 (basic-constraints)
            ├BOOLEAN TRUE                 // расширение является критичным
            └OCTET STRING
               30 06 01 01 FF 02 01 00
               ├ ( decoded 8 octets)
               └SEQUENCE┐
                        ├BOOLEAN TRUE     //  сертификат может создавать цепочки сертификации (cA)
                        └INTEGER 0x0      //  длина цепочки равна 1
                                          // (количество промежуточных сертификатов равно ноль)
 \endcode

  RFC5280: Расширение для базовых ограничений (basic constraints) указывает, является ли `субъект`
  сертификата центром сертификации (certificate authority), а также максимальную глубину действительных
  сертификационных путей, которые включают данный сертификат. Булевское значение сА указывает,
  принадлежит ли сертифицированный открытый ключ центру сертификации.
  Если булевское значение сА не установлено,
  то бит keyCertSign в расширении использования ключа (keyUsage) не должен быть установлен.
  Поле pathLenConstrant имеет смысл, только если булевское значение сА установлено, и в расширении
  использования ключа установлен бит keyCertSign. В этом случае данное поле определяет максимальное
  число несамовыпущенных промежуточных сертификатов, которые *могут* следовать за данным сертификатом
  в действительном сертификационном пути.
  Сертификат является самовыпущенным (самоподписаным), если номера ключей,
  которые присутствуют в полях субъекта и выпускающего (эмитента), являются одинаковыми и не пустыми.
  Когда pathLenConstraint не присутствует, никаких ограничений не предполагается.

 \note Данное расширение должно присутствовать как критичное во всех сертификатах центра сертификации,
 которые содержат открытые ключи, используемые для проверки цифровых подписей в сертификатах.
 Данное расширение *может* присутствовать как критичное или некритичное расширение в сертификатах
 центра сертификации, которые содержат открытые ключи, используемые для целей, отличных от проверки
 цифровых подписей в сертификатах. Такие сертификаты содержат открытые ключи, используемые
 исключительно для проверки цифровых подписей в CRLs,
 и сертификатами, которые содержат открытые ключи для управления ключом, используемым в протоколах
 регистрации сертификатов.

 \param ca флаг возможности создавать цепочки сертификации
 \param pathLen длина цепочки сертифкации
 \return Функция возвращает указатель на структуру узла. Данная структура должна
  быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
  удаления дерева, в который данный узел будет входить.
  В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
  функции ak_error_get_value().                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_basic_constraints( bool_t ca, const ak_uint32 pathLen )
{
  ak_uint8 encode[256]; /* очень длинные идентификаторы это плохо */
  ak_tlv tlv = NULL, os = NULL;
  size_t len = sizeof( encode );

  if(( tlv = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
 /* добавляем идентификатор расширения */
  ak_asn1_add_oid( tlv->data.constructed, "2.5.29.19" );
  ak_asn1_add_bool( tlv->data.constructed, ak_true ); /* расширение всегда критическое */

 /* добавляем закодированный идентификатор (номер) ключа */
  if(( os = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    return ak_tlv_delete( tlv );
  }

  ak_asn1_add_bool( os->data.constructed, ca );
  if( ca ) ak_asn1_add_uint32( os->data.constructed, pathLen );

  memset( encode, 0, sizeof( encode ));
  if( ak_tlv_encode( os, encode, &len ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                    "incorrect encoding a temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  ak_tlv_delete( os );

 /* собственно вставка в asn1 дерево */
  ak_asn1_add_octet_string( tlv->data.constructed, encode, len );
 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает расширение x509v3 следующего вида.

 \code
    └SEQUENCE┐
             ├OBJECT IDENTIFIER 2.5.29.15 (key-usage)
             └OCTET STRING
                03 02 00 84
                ├ (decoded 4 octets)
                └BIT STRING
                   84
 \endcode

 \param bits набор флагов
 \return Функция возвращает указатель на структуру узла. Данная структура должна
  быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
  удаления дерева, в который данный узел будет входить.
  В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
  функции ak_error_get_value().                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_key_usage( const ak_uint32 bits )
{
  ak_uint8 buffer[2], /* значащими битами являются младшие 9,
            поэтому нам хватит двух байт для хранения флагов */
           encode[16];  /* массив для кодирования битовой строки */
  struct bit_string bs;
  ak_tlv tlv = NULL, os = NULL;
  size_t len = sizeof( encode );

  if( !bits ) {
    ak_error_message( ak_error_zero_length, __func__, "using undefined set of keyUsage flags" );
    return NULL;
  }
  if(( tlv = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
 /* добавляем идентификатор расширения */
  ak_asn1_add_oid( tlv->data.constructed, "2.5.29.15" );

  buffer[0] = ( bits >> 1 )&0xFF;
  if( bits&0x01 ) { /* определен бит decipherOnly */
    buffer[1] = 0x80;
    bs.unused = 7;
    bs.len = 2;
  } else {
      buffer[1] = 0;
      bs.unused = 0;
      bs.len = 1;
   }
  bs.value = buffer;

 /* добавляем закодированную последовательность бит */
  if(( os = ak_tlv_new_primitive( TBIT_STRING, bs.len+1, NULL, ak_true )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  os->data.primitive[0] = bs.unused;
  memcpy( os->data.primitive+1, bs.value, bs.len );

  memset( encode, 0, sizeof( encode ));
  if( ak_tlv_encode( os, encode, &len ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                    "incorrect encoding a temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  ak_tlv_delete( os );

 /* собственно вставка в asn1 дерево */
  ak_asn1_add_octet_string( tlv->data.constructed, encode, len );
 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает расширение x509v3 определяемое следующей структурой

 \code
    KeyIdentifier ::= ОСТЕТ SТRING

    AuthorityKeyIdentifier ::= SEQUENCE {
       keyIdentifier       [О] KeyIdentifier OPTIONAL,
       authorityCertIssuer [1] GeneralNames OPTIONAL,
       authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
    }
 \endcode

   Пример данного расширения выглядит следующим образом (взято из сертификата,
   подписанного корневым сертификатом ГУЦ)

 \code
└SEQUENCE┐
         ├[0] 8b983b891851e8ef9c0278b8eac8d420b255c95d
         ├[1]┐
         │   └[4]┐
         │       └SEQUENCE┐
         │                ├SET┐
         │                │   └SEQUENCE┐
         │                │            ├OBJECT IDENTIFIER 1.2.840.113549.1.9.1 (email-address)
         │                │            └IA5 STRING dit@minsvyaz.ru
         │                ├SET┐
         │                │   └SEQUENCE┐
         │                │            ├OBJECT IDENTIFIER 2.5.4.6 (country-name)
         │                │            └PRINTABLE STRING RU
         │                ├SET┐
         │                │   └SEQUENCE┐
         │                │            ├OBJECT IDENTIFIER 2.5.4.8 (state-or-province-name)
         │                │            └UTF8 STRING 77 г. Москва
         │                └SET┐
         │                    └SEQUENCE┐
         │                             ├OBJECT IDENTIFIER 2.5.4.3 (common-name)
         │                             └UTF8 STRING Головной удостоверяющий центр
         └[2] 34681e40cb41ef33a9a0b7c876929a29
 \endcode

   Метке `[0]` соответствует номер ключа подписи (поле verifykey.number),
   метке `[1]`  - расширенное имя ключа подписи (поле verifykey.name),
   метке `[2]`  - серийный номер выпущенного сертификата открытого ключа (однозначно вычисляется из
   номеров секретного ключа и ключа подписи).

   RFC 5280: Расширение для идентификатора ключа сертификационного центра предоставляет способ
   идентификации открытого ключа, соответствующего закрытому ключу, который использовался для
   подписывания сертификата. Данное расширение используется, когда выпускающий имеет несколько ключей
   для подписывания. Идентификация может быть основана либо на идентификаторе ключа
   (идентификатор ключа субъекта в сертификате выпускающего), либо на имени выпускающего и
   серийном номере сертификата.

   \note Поле `keyIdentifier` расширения authorityKeyIdentifier должно быть включено во все
   сертификаты, выпущенные цетром сертификации для обеспечения возможности создания
   сертификационного пути. Существует одно исключение: когда центр сертификации распространяет свой
   открытый ключ в форме самоподписанного сертификата, идентификатор ключа уполномоченного органа
   может быть опущен. Подпись для самоподписанного сертификата создается закрытым ключом,
   соответствующим открытому ключу субъекта. ЭТО доказывает, что выпускающий обладает как открытым
   ключом, так и закрытым.

   \param issuer_cert сертификат открытого ключа эмитента (лица, подписывающего сертификат)
   \param include_name булево значение; если оно истинно,
   то в расширение помещается глобальное имя владельца указанных ключей
   \return Функция возвращает указатель на структуру узла. Данная структура должна
   быть позднее удалена с помощью явного вызова функции ak_tlv_delete() или путем
   удаления дерева, в который данный узел будет входить.
   В случае ошибки возвращается NULL. Код ошибки может быть получен с помощью вызова
   функции ak_error_get_value().                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_tlv ak_tlv_new_authority_key_identifier( ak_certificate issuer_cert, bool_t include_name )
{
  ak_uint8 encode[512];  /* массив для кодирования */
  size_t len = sizeof( encode );
  ak_tlv tlv = NULL, os = NULL;
  ak_asn1 asn = NULL, asn1 = NULL;

  if(( tlv = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }

 /* добавляем идентификатор расширения */
  ak_asn1_add_oid( tlv->data.constructed, "2.5.29.35" );

 /* добавляем закодированную последовательность, содержащую перечень имен */
  if(( os = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                   "incorrect creation of temporary tlv context" );
    return ak_tlv_delete( tlv );
  }

 /* добавляем [0] */
  ak_asn1_add_tlv( os->data.constructed,
                 ak_tlv_new_primitive( CONTEXT_SPECIFIC^0x00,
                             issuer_cert->vkey.number_length, issuer_cert->vkey.number, ak_true ));
 /* добавляем [1] */
  if( include_name ) {
    ak_asn1_add_tlv( os->data.constructed,
                  ak_tlv_new_constructed( CONSTRUCTED^CONTEXT_SPECIFIC^0x01, asn = ak_asn1_new()));
    ak_asn1_add_tlv( asn,
                 ak_tlv_new_constructed( CONSTRUCTED^CONTEXT_SPECIFIC^0x04, asn1 = ak_asn1_new()));
    ak_asn1_add_tlv( asn1, ak_tlv_duplicate_global_name( issuer_cert->opts.subject ));
  }
 /* добавляем [2] */
  if( issuer_cert->opts.serialnum_length ) {
    ak_asn1_add_tlv( os->data.constructed,
            ak_tlv_new_primitive( CONTEXT_SPECIFIC^0x02,
                       issuer_cert->opts.serialnum_length, issuer_cert->opts.serialnum, ak_true ));
  }

  memset( encode, 0, sizeof( encode ));
  if( ak_tlv_encode( os, encode, &len ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                    "incorrect encoding a temporary tlv context" );
    return ak_tlv_delete( tlv );
  }
  ak_tlv_delete( os );

 /* собственно вставка в asn1 дерево */
  ak_asn1_add_octet_string( tlv->data.constructed, encode, len );
 return tlv;
}

/* ----------------------------------------------------------------------------------------------- */
                     /* Функции экспорта открытых ключей в сертификат */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание tlv узла, содержащего структуру TBSCertificate версии 3
    в соответствии с Р 1323565.1.023-2018.

   Структура `tbsCertificate` определяется следующим образом

   \code
    TBSCertificate  ::=  SEQUENCE  {
        version         [0]  Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  Extensions OPTIONAL
                             -- If present, version MUST be v3 --  }
   \endcode

   Перечень добавляемых расширений определяется значениями аргумента `opts`.

   \param subject_cert контекст сертификата открытого ключа, помещаемого в asn1 дерево сертификата
   \param issuer_skey контекст ключа подписи
   \param issuer_cert контект сертификата ключа проверки подписи
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_certificate_export_to_tbs( ak_certificate subject_cert, ak_signkey issuer_skey,
                                                                       ak_certificate issuer_cert )
{
  ak_mpzn256 serialNumber;
  ak_tlv tbs = NULL, tlv = NULL;
  ak_asn1 asn = NULL, tbasn = NULL;

  if(( tbs = ak_tlv_new_sequence()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect creation of tlv context" );
    return NULL;
  }
   else tbasn = tbs->data.constructed;

 /* теперь создаем дерево сертификата в соответствии с Р 1323565.1.023-2018
    version: начинаем с размещения версии сертификата, т.е. ветки следующего вида
     ┐
     ├[0]┐
     │   └INTEGER 2 (величина 2 является максимально возможным значением ) */

  ak_asn1_add_asn1( tbasn, CONTEXT_SPECIFIC^0x00, asn = ak_asn1_new( ));
  if( asn != NULL ) ak_asn1_add_uint32( asn, 2 );
    else {
      ak_error_message( ak_error_get_value(), __func__,
                                              "incorrect creation of certificate version context");
      goto labex;
    }

 /* serialNumber: вырабатываем и добавляем номер сертификата */
  ak_certificate_generate_serial_number( &subject_cert->vkey, issuer_skey,
                                                                   subject_cert->opts.serialnum,
              subject_cert->opts.serialnum_length = sizeof( subject_cert->opts.issuer_serialnum ));
  ak_mpzn_set_little_endian( serialNumber, ak_mpzn256_size,
                     subject_cert->opts.serialnum, subject_cert->opts.serialnum_length, ak_true );
  ak_asn1_add_mpzn( tbasn, TINTEGER, serialNumber, ak_mpzn256_size );

 /* signature: указываем алгоритм подписи (это будет повторено еще раз при выработке подписи) */
  ak_asn1_add_algorithm_identifier( tbasn, issuer_skey->key.oid, NULL );

 /* issuer: вставляем информацию о расширенном имени лица, подписывающего ключ
    (эмитента, выдающего сертификат) */
  ak_asn1_add_tlv( tbasn, ak_tlv_duplicate_global_name( issuer_cert->opts.subject ));

 /* validity: вставляем информацию в времени действия ключа */
  ak_asn1_add_validity( tbasn, subject_cert->opts.time.not_before,
                                                               subject_cert->opts.time.not_after );
 /* subject: вставляем информацию о расширенном имени владельца ключа  */
  ak_asn1_add_tlv( tbasn, ak_tlv_duplicate_global_name( subject_cert->opts.subject ));

 /* subjectPublicKeyInfo: вставляем информацию об открытом ключе */
  ak_asn1_add_tlv( tbasn, tlv = ak_verifykey_export_to_asn1_value( &subject_cert->vkey ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                               "incorrect generation of subject public key info" );
    goto labex;
  }

 /* далее мы реализуем возможности сертификатов третьей версии, а именно
    вставляем перечень расширений
    0x03 это помещаемое в CONTEXT_SPECIFIC значение */
  ak_asn1_add_asn1( tbasn, CONTEXT_SPECIFIC^0x03, asn = ak_asn1_new( ));
  if( asn == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                      "incorrect creation of certificate extensions asn1 context");
    goto labex;
  }
  ak_asn1_add_tlv( asn, ak_tlv_new_sequence( ));
  asn = asn->current->data.constructed;

 /* 1. В обязательном порядке добавляем номер открытого ключа */
  ak_asn1_add_tlv( asn, tlv = ak_tlv_new_subject_key_identifier( subject_cert->vkey.number,
                                                               subject_cert->vkey.number_length ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
    goto labex;
  }

 /* 2. Если определено расширение BasicConstraints, то добавляем его
      (расширение может добавляться не только в самоподписаные сертификаты) */
  if( subject_cert->opts.ext_ca.is_present ) {
    ak_asn1_add_tlv( asn, tlv = ak_tlv_new_basic_constraints( subject_cert->opts.ext_ca.value,
                                                    subject_cert->opts.ext_ca.pathlenConstraint ));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
      goto labex;
    }
  }

 /* 3. Если определены флаги keyUsage, то мы добавляем соответствующее расширение */
  if( subject_cert->opts.ext_key_usage.is_present ) {
    ak_asn1_add_tlv( asn, tlv = ak_tlv_new_key_usage( subject_cert->opts.ext_key_usage.bits ));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
      goto labex;
    }
  }

 /* 4. Добавляем имена для поиска ключа проверки подписи (Authority Key Identifier)
                                                       данное расширение будет добавляться всегда */
  ak_asn1_add_tlv( asn, tlv = ak_tlv_new_authority_key_identifier( issuer_cert,
                                               subject_cert->opts.ext_authoritykey.include_name ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                    "incorrect generation of Authority Key Identifier extension" );
    goto labex;
  }

 return tbs;

  labex: if( tbs != NULL ) ak_tlv_delete( tbs );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param subject_cert контекст сертификата, помещаемого в asn1 дерево
    \param issuer_skey контекст ключа подписи
    \param issuer_cert контект сертификата ключа проверки подписи,
     содержащий параметры центра сертификации
    \param generator геератор случайных последовательностей, используемый для подписи сертификата
    \return Функция возвращает указатель на созданный объект.
    В случае ошибки возвращается NULL.                                                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_asn1 ak_certificate_export_to_asn1( ak_certificate subject_cert,
                          ak_signkey issuer_skey, ak_certificate issuer_cert, ak_random generator )
{
  size_t len = 0;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_asn1 certificate = NULL;
  time_t current = time( NULL );
  ak_uint8 encode[4096], out[128];
  ak_tlv tlv = NULL, ta = NULL, tbs = NULL;

 /* 1. Необходимые проверки */
  if( subject_cert == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                           "using null pointer to subject's certificate context" );
    return NULL;
  }
  if( issuer_skey == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                             "using null pointer to issuer's secret key context" );
    return NULL;
  }
  if( issuer_cert == NULL ) { ak_error_message( ak_error_null_pointer, __func__,
                                            "using null pointer to issuer's certificate context" );
    return NULL;
  }

 /* 2. Проверяем, разрешено ли issuer_cert подписывать сертификаты.
       Для создания подписи расширение BasicConstraints должно быть определено,
                                             а поле value установлено в "true".
       Создание самоподписаных сертификатов разрешено в любом случае.            */
  if( subject_cert != issuer_cert ) {
    if( !issuer_cert->opts.ext_ca.is_present || !issuer_cert->opts.ext_ca.value ) {
      ak_error_message( ak_error_certificate_ca, __func__, "issuer is not certificate's authority" );
      return NULL;
    }
  }

 /* 3. Проверяем, что текущее время попадает во время действия сертификата подписи. */
  if( current < issuer_cert->opts.time.not_before ||
      current > issuer_cert->opts.time.not_after ) {
    ak_error_message( ak_error_certificate_validity, __func__,
                                                             "issuer's certificate time expired" );
    return NULL;
  }

 /* 4. Проверям, что секретный ключ соответствует сертификату ключа подписи */
  if( issuer_cert->vkey.number_length != 32 ) {
   /* мы работаем только со своими секретными ключами,
      а у них длина номера - фиксирована и равна 32 октетам */
    ak_error_message( ak_error_wrong_length, __func__,
                                               "the issuer public key's number has wrong length" );
    return NULL;
  }
  if( memcmp( issuer_skey->verifykey_number, issuer_cert->vkey.number, 32 ) != 0 ) {
    ak_error_message( ak_error_not_equal_data, __func__,
                           "the issuer's secret key does not correspond to the given public key" );
    return NULL;
  }

 /* 5. Создаем контейнер для сертификата */
  if(( error = ak_asn1_add_tlv( certificate = ak_asn1_new(),
                                         tlv = ak_tlv_new_sequence( ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect addition of tlv context" );
    goto labex;
  }
  if( tlv == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "incorrect creation of tlv context" );
    goto labex;
  }

 /* 6. Создаем поле tbsCertificate */
  if(( tbs = ak_certificate_export_to_tbs( subject_cert, issuer_skey, issuer_cert )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                                  "incorrect creation of tbsCertificate element" );
    goto labex;
  }

 /* вставляем в основное дерево созданный элемент */
  ak_asn1_add_tlv( tlv->data.constructed, tbs );
 /* добавляем информацию о алгоритме подписи */
  ak_asn1_add_tlv( tlv->data.constructed, ta = ak_tlv_new_sequence( ));
  if( ta == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                          "incorrect generation of digital signature identifier" );
    goto labex;
  }
  ak_asn1_add_oid( ta->data.constructed, issuer_skey->key.oid->id[0] );

 /* 7. Вырабатываем подпись */
  len = sizeof( encode );
  if(( error = ak_tlv_encode( tbs, encode, &len )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encoding of tbsCertificate element" );
    goto labex;
  }
  if(( error = ak_signkey_sign_ptr( issuer_skey, generator, encode,
                                                      len, out, sizeof( out ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect generation of digital signature" );
    goto labex;
  }

 /* добавляем подпись в основное дерево */
  bs.value = out;
  bs.len = ak_signkey_get_tag_size( issuer_skey );
  bs.unused = 0;
  if(( error = ak_asn1_add_bit_string( tlv->data.constructed, &bs )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect adding a digital signature value" );
    goto labex;
  }
 return certificate;

  labex: if( certificate != NULL ) ak_asn1_delete( certificate );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию,
    помещает в это же asn1 дерево информацию о подписывающем лице и правилах применения ключа.
    После этого сформированное дерево сохраняется в файл (сертификат открытого ключа)
    в заданном пользователем формате.

   \param subject_cert контекст сертификата, содержащий как открытый ключ, также опции и расширения
   создаваемого сертификата;
   \param issuer_skey контекст секретного ключа, с помощью которого подписывается создаваемый сертификат;
   \param issuer_cert контекст сертификата открытого ключа, соответствующий секретному ключу подписи;
   данный контекст используется для получения расширенного имени лица,
   подписывающего сертификат (issuer), а также для проверки разрешений на использование сертификата;
   для самоподписанных сертификатов должен принимать значение, совпадающее с subject_cert;
   \param generator генератор случайных чисел, используемый для подписи сертификата.
   \param filename указатель на строку, содержащую имя файла, в который будет экспортирован ключ;
    Если параметр `filename_size` отличен от нуля,
    то указатель должен указывать на область памяти, в которую будет помещено сформированное имя файла.
   \param size  размер области памяти, в которую будет помещено имя файла.
    Если размер области недостаточен, то будет возбуждена ошибка.
    Данный параметр должен принимать значение 0 (ноль), если указатель `filename` указывает
    на константную строку.
   \param format формат, в котором сохраняются данные, допутимые значения
   \ref asn1_der_format или \ref asn1_pem_format.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 dll_export int ak_certificate_export_to_file( ak_certificate subject_cert,
                   ak_signkey issuer_skey, ak_certificate issuer_cert, ak_random generator,
                                       char *filename, const size_t size, export_format_t format )
{
  int error = ak_error_ok;
  ak_asn1 certificate = NULL;
  const char *file_extensions[] = { /* имена параметризуются значениями типа export_format_t */
   "cer",
   "crt"
  };

  /* вырабатываем asn1 дерево */
  if(( certificate = ak_certificate_export_to_asn1(
                                    subject_cert, issuer_skey, issuer_cert, generator )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__,
                                            "incorrect creation of asn1 context for certificate" );
 /* формируем имя файла для хранения ключа
    поскольку один и тот же ключ может быть помещен в несколько сертификатов,
    то имя файла в точности совпадает с серийным номером сертификата */
  if( size ) {
    if( size < ( 5 + 2*sizeof( subject_cert->opts.serialnum )) ) {
      ak_error_message( error = ak_error_out_of_memory, __func__,
                                              "insufficent buffer size for certificate filename" );
      goto labex;
    }
    if( subject_cert->opts.serialnum_length == 0 ) {
      ak_certificate_generate_serial_number( &subject_cert->vkey, issuer_skey,
                                                                   subject_cert->opts.serialnum,
              subject_cert->opts.serialnum_length = sizeof( subject_cert->opts.issuer_serialnum ));

    }
    ak_snprintf( filename, size, "%s.%s", ak_ptr_to_hexstr( subject_cert->opts.serialnum,
           subject_cert->opts.serialnum_length, ak_false ), file_extensions[ak_min( 1, format )] );

  } /* конец if(size) */

 /* сохраняем созданное дерево в файл */
  if(( error = ak_asn1_export_to_file( certificate, filename,
                                        format, public_key_certificate_content )) != ak_error_ok )
    ak_error_message_fmt( error, __func__,
                              "incorrect export asn1 context to file %s in pem format", filename );

  labex: if( certificate != NULL ) ak_asn1_delete( certificate );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_cert.c  */
/* ----------------------------------------------------------------------------------------------- */
