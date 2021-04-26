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
  ak_error_message( ak_error_get_value(), __func__,
                                         "incorrect export of public key into request asn1 tree" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция формирует asn1 дерево с запросом на сертификат открытого ключа.

    Выполняются следующие действия:

    - формируется tlv элемент, содержащий имя владельца, параметры алгоритма и значение ключа,
    - tlv элемент кодируется в der-последовательность,
    - вырабатывается подпись под der-последовательностью,
    - идентификатор алгоритма выработки подписи и значение подписи также помещаются в asn1 дерево.

   \param vk контекст открытого ключа
   \param sk контекст секретного ключа
   \param a уровень asn1 дерева, в который помещается запрос на сертификат.

   \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_export_to_asn1_request( ak_verifykey vk, ak_signkey sk,
                                                                   ak_random generator, ak_asn1 a )
{
  ak_asn1 asn = NULL;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_uint8 data[4096], s[128];
  size_t size = sizeof( data );
  ak_tlv tlv = NULL, pkey = NULL;

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
   ak_asn1_add_tlv( asn, ak_tlv_duplicate_global_name( vk->name ));

  /* помещаем информацию об алгоритме и открытом ключе */
   ak_asn1_add_tlv( asn, pkey = ak_verifykey_export_to_asn1_value( vk ));
   if( pkey == NULL ) {
     if( tlv != NULL ) tlv = ak_tlv_delete( tlv );
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

   \note Контекст секретного ключа `sk` должен соответствовать контексту открытого ключа `vk`.
   В противном случае нельзя будет проверить электронную подпись под открытым ключом, поскольку
   запрос на сертификат, по сути, является урезанной версией самоподписанного сертификата.
   Отсюда следует, что нельзя создать запрос на сертификат ключа, который не поддерживает
   определенный библиотекой алгоритм подписи (например ключ на кривой в 640 бит).
   Такие ключи должны сразу помещаться в сертификат.

   \param vk Контекст открытого ключа
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
 int ak_verifykey_export_to_request( ak_verifykey vk, ak_signkey sk, ak_random generator,
                                       char *filename, const size_t size, export_format_t format )
{
  ak_asn1 asn = NULL;
  int error = ak_error_ok;

  if( vk == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to public key context" );
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
                                   ak_ptr_to_hexstr( vk->number, sizeof( vk->number ), ak_false ));
  }

 /* 2. Создаем asn1 дерево */
  if(( error = ak_verifykey_export_to_asn1_request( vk, sk, generator,
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
    if( asn != NULL ) asn = ak_asn1_delete( asn );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                 /* Функции импорта открытых ключей из запроса на сертификат */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_import_from_asn1_value( ak_verifykey vkey, ak_asn1 asnkey,
                                                                  ak_function_file_output verbose )
{
  size_t size = 0;
  char message[256];
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
  vkey->flags = ak_key_flag_set_key;

 /* выводим считанное */
  if( verbose ) {
    verbose(" Public Key:\n");
    ak_snprintf( message, sizeof( message ), "    x: %s\n",
                          ak_mpzn_to_hexstr( vkey->qpoint.x, vkey->wc->size )); verbose( message );
    ak_snprintf( message, sizeof( message ), "    y: %s\n",
                          ak_mpzn_to_hexstr( vkey->qpoint.y, vkey->wc->size )); verbose( message );
    ak_snprintf( message, sizeof( message ), "    curve: %s (%u bits)\n",
                                             oid->name[0], 64*vkey->wc->size ); verbose( message );
  }

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

    \param vkey контекст создаваемого открытого ключа асимметричного криптографического алгоритма
    \param asnkey считанное из файла asn1 дерево
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_import_from_asn1_request( ak_verifykey vkey, ak_asn1 asnkey,
                                                                  ak_function_file_output verbose )
{
  char message[512];
  ak_uint32 val = 0;
  ak_asn1 asn = asnkey; /* копируем адрес */

 /* проверяем, что первым элементом содержится ноль */
  ak_asn1_first( asn );
  if(( DATA_STRUCTURE( asn->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( asn->current->tag ) != TINTEGER ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                          "the first element of root asn1 context be an integer" );
  ak_tlv_get_uint32( asn->current, &val );
  if( val != 0 ) return ak_error_message( ak_error_invalid_asn1_content, __func__ ,
                                              "the first element of asn1 context must be a zero" );
  if( verbose ) {
    verbose(" Type:\n    Public Key Certificate's Request\n");
    ak_snprintf( message, sizeof( message ), " Version: v%d\n", val+1 );
    verbose( message );
  }

 /* второй элемент содержит имя владельца ключа.
    этот элемент должен быть позднее перенесен в контекст открытого ключа */
  ak_asn1_next( asn );
  if( verbose ) {
    verbose(" Subject:\n");
    ak_tlv_snprintf_global_name( asn->current, message, sizeof( message ));
    verbose( message ); verbose( "\n" );
  }

 /* третий элемент должен быть SEQUENCE с набором oid и значением ключа */
  if( ak_asn1_next( asn ) != ak_true )
    return ak_error_message( ak_error_invalid_asn1_count, __func__, "unexpected end of asn1 tree" );

 /* проверяем наличие последовательности верхнего уровня */
  if(( DATA_STRUCTURE( asn->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( asn->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                      "the element of root asn1 tree must be a sequence with object identifiers" );
  asn = asn->current->data.constructed;

 return ak_verifykey_import_from_asn1_value( vkey, asn, verbose );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция считывает из заданного файла запрос на получение сертификата. Запрос хранится в виде
    asn1 дерева, определяемого Р 1323565.1.023-2018.
    Собственно asn1 дерево может быть храниться в файле в виде обычной der-последовательности,
    либо в виде der-последовательности, дополнительно закодированной в `base64` (формат `pem`).

    \note Функция является конструктором контекста ak_verifykey.
    После считывания asn1 дерева  функция проверяет подпись под открытым ключом и,
    в случае успешной проверки, создает контекст `vkey` и инициирует его необходимыми значениями.

    \param vkey контекст создаваемого открытого ключа асимметричного криптографического алгоритма
    \param filename имя файла
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_import_from_request( ak_verifykey vkey, const char *filename,
                                                                  ak_function_file_output verbose )
{
  size_t size = 0;
  ak_tlv tlv = NULL;
  struct bit_string bs;
  ak_uint8 buffer[4096];
  int error = ak_error_ok;
  ak_asn1 root = NULL, asn = NULL, asnkey = NULL;

 /* стандартные проверки */
  if( vkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to filename" );
 /* считываем ключ и преобразуем его в ASN.1 дерево */
  if(( error = ak_asn1_import_from_file( root = ak_asn1_new(), filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
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
  if(( error = ak_verifykey_import_from_asn1_request( vkey,
                             asnkey = asn->current->data.constructed, verbose )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect structure of request" );
    goto lab1;
  }
 /* 4. На основе считанных данных формируем номер ключа */
  if(( error = ak_verifykey_set_number( vkey )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect creation on public key number" );
    goto lab1;
  }


 /* второй узел, в нашей терминологии, содержит идентификатор секретного ключа
    и бесполезен, поскольку вся информация об открытом ключе проверки подписи,
    эллиптической кривой и ее параметрах уже считана. остается только проверить подпись,
    расположенную в последнем, третьем узле запроса. */

 /* 1. Начинаем с того, что готовим данные, под которыми должна быть проверена подпись */
  memset( buffer, 0, size = sizeof( buffer ));
  ak_asn1_first( asn );
  if(( error = ak_tlv_encode( asn->current, buffer, &size )) != ak_error_ok ) {
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
  if( ak_verifykey_verify_ptr( vkey, buffer, size, bs.value ) != ak_true ) {
     ak_error_message( error = ak_error_not_equal_data, __func__, "digital signature isn't valid" );
     goto lab1;
  }

 /* 5. В самом конце, после проверки подписи,
    изымаем узел, содержащий имя владельца открытого ключа -- далее этот узел будет перемещен
    в сертификат открытого ключа.
    Все проверки пройдены ранее и нам точно известна структура asn1 дерева. */
  ak_asn1_first( asn );
  asn = asn->current->data.constructed;
  ak_asn1_first( asn );
  ak_asn1_next( asn ); /* нужен второй узел */
  vkey->name = ak_asn1_exclude( asn );

  lab1: if( root != NULL ) ak_asn1_delete( root );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                      /* Служебные функции для работы с сертификатами */
/* ----------------------------------------------------------------------------------------------- */
/*! Данный номер (serialNumber) зависит от номера секретного ключа, подписывающего открытый ключ и,
    тем самым, может принимать различные значения для каждого из подписывающих ключей.

    Серийный номер сертификата образуют младшие 32 байта результата хеширования
    последовательной конкатенации номеров открытого и секретного ключей.
    Для хеширования используется функция, определенная в контексте `секретного` ключа,
    т.е.  Стрибог512 для длинной подписи и Стрибог256 для короткой.

   \code
    result[0..31] = Hash( vk->number || sk->number )
   \endcode

    Вычисленное значение не помещается в контекст открытого ключа, а возвращается как
    большое целое число. Это позволяет использовать данную функцию как при экспорте,
    так и при импорте сертификатов открытых ключей (в момент разбора цепочек сертификации).

   \param vk контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param sk контекст ключа подписи, содержащий параметры центра сертификации
   \param serialNumber переменная, в которую помещается серийный номер.
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_generate_certificate_serial_number( ak_verifykey vk,
                                                          ak_signkey sk, ak_mpzn256 serialNumber )
{
  ak_uint8 result[64];

 /* используем для хеширования контекст секретного ключа */
  if( ak_hash_get_tag_size( &sk->ctx ) > sizeof( result ))
    return ak_error_message( ak_error_wrong_length, __func__,
                                                      "using secret key with huge signature tag" );
  memset( result, 0, sizeof( result ));
  ak_hash_clean( &sk->ctx );
  ak_hash_update( &sk->ctx, vk->number, sizeof( vk->number ));
  ak_hash_finalize( &sk->ctx, sk->key.number, sizeof( sk->key.number ), result, sizeof( result ));
  ak_mpzn_set_little_endian( serialNumber, ak_mpzn256_size, result, 32, ak_true );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param opts указатель на структуру, в которой передаются параметры сертификата
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль), в противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_opts_create( ak_certificate_opts opts )
{
  if( opts == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                              "initializing null pointer to certificate options" );

  memset( opts, 0, sizeof( struct certificate_opts ));

 /* значения по умолчанию */
  opts->ca.is_present = ak_false;
  opts->key_usage.is_present = ak_false;
  opts->subjkey.is_present = ak_false;
  opts->authoritykey.is_present = ak_false;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param opts указатель на структуру, в которой передаются параметры сертификата
    \return В случае успеха функция возвращает \ref ak_error_ok (ноль), в противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_certificate_opts_destroy( ak_certificate_opts opts )
{
  if( opts == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                "destroying null pointer to certificate options" );
  memset( opts, 0, sizeof( struct certificate_opts ));

 return ak_error_ok;
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

   \param subject_vkey контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param issuer_skey контекст ключа подписи
   \param issuer_vkey контект ключа проверки подписи, содержащий параметры центра сертификации
   \param opts набор опций, формирующих помещаемые в сертификат расширения
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 static ak_tlv ak_verifykey_export_to_tbs( ak_verifykey subject_vkey, ak_signkey issuer_skey,
                                               ak_verifykey issuer_vkey, ak_certificate_opts opts )
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
  ak_verifykey_generate_certificate_serial_number( subject_vkey, issuer_skey, serialNumber );
  ak_asn1_add_mpzn( tbasn, TINTEGER, serialNumber, ak_mpzn256_size );

 /* signature: указываем алгоритм подписи (это будет повторено еще раз при выработке подписи) */
  ak_asn1_add_algorithm_identifier( tbasn, issuer_skey->key.oid, NULL );

 /* issuer: вставляем информацию о расширенном имени лица, подписывающего ключ
    (эмитента, выдающего сертификат) */
  ak_asn1_add_tlv( tbasn, ak_tlv_duplicate_global_name( issuer_vkey->name ));

 /* validity: вставляем информацию в времени действия ключа */
  ak_asn1_add_validity( tbasn, issuer_skey->key.resource.time.not_before,
                                                        issuer_skey->key.resource.time.not_after );
 /* subject: вставляем информацию о расширенном имени владельца ключа  */
  ak_asn1_add_tlv( tbasn, ak_tlv_duplicate_global_name( subject_vkey->name ));

 /* subjectPublicKeyInfo: вставляем информацию об открытом ключе */
  ak_asn1_add_tlv( tbasn, tlv = ak_verifykey_export_to_asn1_value( subject_vkey ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                               "incorrect generation of subject public key info" );
    goto labex;
  }

 /* теперь мы принимаем решение - сертификат самоподписанный или нет
    выполняется проверка на совпадение subjectKeyIdentifier (номера открытого ключа)  */
  if( ak_ptr_is_equal( subject_vkey->number, issuer_vkey->number, 32 )) {
    opts->ca.is_present = ak_true;
    opts->ca.value = ak_true;
    if( !opts->key_usage.is_present ) opts->key_usage.is_present = ak_true;
    if( !(opts->key_usage.bits&bit_keyCertSign )) opts->key_usage.bits ^= bit_keyCertSign;
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
  ak_asn1_add_tlv( asn, tlv = ak_tlv_new_subject_key_identifier( subject_vkey->number, 32 ));
  if( tlv == NULL ) {
    ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
    goto labex;
  }

 /* 2. Если определено расширение BasicConstraints, то добавляем его
      (расширение может добавляться не только в самоподписаные сертификаты) */
  if( opts->ca.is_present ) {
    ak_asn1_add_tlv( asn,
                tlv = ak_tlv_new_basic_constraints( opts->ca.value , opts->ca.pathlenConstraint ));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
      goto labex;
    }
  }

 /* 3. Если определены флаги keyUsage, то мы добавляем соответствующее расширение */
  if( opts->key_usage.is_present ) {
    ak_asn1_add_tlv( asn, tlv = ak_tlv_new_key_usage( opts->key_usage.bits ));
    if( tlv == NULL ) {
      ak_error_message( ak_error_get_value(), __func__,
                                        "incorrect generation of SubjectKeyIdentifier extension" );
      goto labex;
    }
  }

 /* 4. Добавляем имена для поиска ключа проверки подписи (Authority Key Identifier)
                                                       данное расширение будет добавляться всегда */
  ak_asn1_add_tlv( asn, tlv = ak_tlv_new_authority_key_identifier( issuer_skey,
                                                   issuer_vkey, opts->authoritykey.include_name ));
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
/*! \brief Функция создает asn1 дерево, содержащее сертификат открытого ключа.

   \param subject_vkey контекст открытого ключа, помещаемого в asn1 дерево сертификата
   \param issuer_skey контекст ключа подписи
   \param issuer_vkey контект ключа проверки подписи, содержащий параметры центра сертификации
   \param generator геератор случайных последовательностей, используемый для подписи сертификата
   \param opts набор опций, формирующих помещаемые в сертификат расширения
   \return Функция возвращает указатель на созданный объект.
   В случае ошибки возвращается NULL.                                                              */
/* ----------------------------------------------------------------------------------------------- */
 static ak_asn1 ak_verifykey_export_to_asn1_certificate( ak_verifykey subject_vkey,
  ak_signkey issuer_skey, ak_verifykey issuer_vkey, ak_random generator, ak_certificate_opts opts )
{
  size_t len = 0;
  struct bit_string bs;
  int error = ak_error_ok;
  ak_asn1 certificate = NULL;
  ak_uint8 encode[4096], out[128];
  ak_tlv tlv = NULL, ta = NULL, tbs = NULL;

 /* создаем контейнер для сертификата */
  if(( error = ak_asn1_add_tlv( certificate = ak_asn1_new(),
                                         tlv = ak_tlv_new_sequence( ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect addition of tlv context" );
    goto labex;
  }
  if( tlv == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "incorrect creation of tlv context" );
    goto labex;
  }

 /* создаем поле tbsCertificate */
  if(( tbs = ak_verifykey_export_to_tbs( subject_vkey, issuer_skey, issuer_vkey, opts )) == NULL ) {
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

 /* вырабатываем подпись */
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

  labex: if( certificate != NULL ) certificate = ak_asn1_delete( certificate );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает информацию об открытом ключе в asn1 дерево, подписывает эту информацию,
    помещает в это же asn1 дерево информацию о подписывающем лице и правилах применения ключа.
    После этого сформированное дерево сохраняется в файл (сертификат открытого ключа)
    в заданном пользователем формате.

   \param subject_vkey контекст открытого ключа, который помещается в сертификат; контекст должен
   содержать расширенное имя лица (subject), владеющего открытым ключом.
   \param issuer_skey контекст секретного ключа, с помощью которого подписывается создаваемый сертификат;
   \param issuer_vkey контекст открытого ключа, соответствующий секретному ключу подписи;
   данный контекст используется для получения расширенного имени лица,
   подписывающего сертификат (issuer), а также для проверки разрешений на использование сертификата.
   \param generator генератор слечайных последовательностей, используемый для подписи сертификата.
   \param opts набор опций, формирующих помещаемые в сертификат расширения
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
 int ak_verifykey_export_to_certificate( ak_verifykey subject_vkey,
          ak_signkey issuer_skey, ak_verifykey issuer_vkey, ak_random generator,
              ak_certificate_opts opts, char *filename, const size_t size, export_format_t format )
{
  ak_mpzn256 serialNumber;
  int error = ak_error_ok;
  ak_asn1 certificate = NULL;
  const char *file_extensions[] = { /* имена параметризуются значениями типа export_format_t */
   "cer",
   "crt"
  };

 /* необходимые проверки */
  if( subject_vkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                            "using null pointer to subject's public key context" );
  if( issuer_skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                             "using null pointer to issuer's secret key context" );
  if( issuer_vkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                             "using null pointer to issuer's public key context" );

 /* проверяем, что секретный ключ соответствует открытому */
  if( memcmp( issuer_skey->verifykey_number, issuer_vkey->number, 32 ) != 0 )
    return ak_error_message( ak_error_not_equal_data, __func__,
                           "the issuer's secret key does not correspond to the given public key" );

  /* вырабатываем asn1 дерево */
  if(( certificate = ak_verifykey_export_to_asn1_certificate(
                               subject_vkey, issuer_skey, issuer_vkey, generator, opts )) == NULL )
    return ak_error_message( ak_error_get_value(), __func__,
                                            "incorrect creation of asn1 context for certificate" );
 /* формируем имя файла для хранения ключа
    (данное имя в точности совпадает с номером ключа) */
  if( size ) {
    if( size < ( 5 + 2*sizeof( subject_vkey->number )) ) {
      ak_error_message( error = ak_error_out_of_memory, __func__,
                                              "insufficent buffer size for certificate filename" );
      goto labex;
    }
    memset( filename, 0, size );
    ak_verifykey_generate_certificate_serial_number( subject_vkey, issuer_skey, serialNumber );
    ak_snprintf( filename, size, "%s.%s",
          ak_mpzn_to_hexstr( serialNumber, ak_mpzn256_size ), file_extensions[format] );
  }

 /* сохраняем созданное дерево в файл */
  if(( error = ak_asn1_export_to_file( certificate, filename,
                                        format, public_key_certificate_content )) != ak_error_ok )
    ak_error_message_fmt( error, __func__,
                              "incorrect export asn1 context to file %s in pem format", filename );

  labex: if( certificate != NULL ) ak_asn1_delete( certificate );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
                     /* Функции импорта открытых ключей из сертификата */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция импортирует базовую часть сертификата                                           */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_import_from_asn1_tbs_base( ak_verifykey subject_vkey,
                          ak_verifykey *issuer_vkey, ak_asn1 sequence , ak_certificate_opts opts,
                                                                  ak_function_file_output verbose )
{
  char message[512];
  ak_pointer ptr = NULL;
  int error = ak_error_ok;
  time_t not_before, not_after;
  ak_oid algoid = NULL, paroid = NULL;
  ak_tlv subject_name = NULL;

 /* 1. получаем версию сертификата */
  ak_asn1_first( sequence );
  if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
     ( DATA_CLASS( sequence->current->tag ) != ( CONTEXT_SPECIFIC^0x00 ))) {
    ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__,
               "incorrect tag value for certificate's version (tag: %x)", sequence->current->tag );
    goto lab1;
  }
   else
    if(( error = ak_tlv_get_uint32(
                sequence->current->data.constructed->current, &opts->version )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect reading of certificate's version" );
      goto lab1;
    }
  if( verbose ) {
    ak_snprintf( message, sizeof( message ), " Version: v%d\n", opts->version+1 );
    verbose( message );
  }

 /* 2. определяем серийный номер сертификата (вырабатывается при подписи сертификата)
       и помещаем его в структуру с опциями */
  ak_asn1_next( sequence );
  if(( DATA_STRUCTURE( sequence->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( sequence->current->tag ) != TINTEGER )) {
    ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__,
         "incorrect tag value for certificate's serial number (tag: %x)", sequence->current->tag );
    goto lab1;
  }
  if(( ak_tlv_get_octet_string( sequence->current,
                                &ptr, &opts->serialnumlen ) != ak_error_ok ) || ( ptr == NULL )) {
    ak_error_message( error, __func__, "incorrect reading of certificate's serial number" );
    goto lab1;
  } else {
      memset( opts->serialnum, 0, sizeof( opts->serialnum ));
      memcpy( opts->serialnum, ptr,
                      opts->serialnumlen = ak_min( opts->serialnumlen, sizeof( opts->serialnum )));
    }
  if( verbose ) {
    ak_snprintf( message, sizeof( message ), " Serial number:\n    %s\n",
                                ak_ptr_to_hexstr( opts->serialnum, opts->serialnumlen, ak_false ));
    verbose( message );
  }

 /* 3. Получаем алгоритм подписи (oid секретного ключа) */
  ak_asn1_next( sequence );
  if(( error = ak_tlv_get_algorithm_identifier( sequence->current,
                                                            &algoid, &paroid )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect reading of signature algorithm" );
    goto lab1;
  }
  if( algoid->engine != sign_function ) {
    ak_error_message( error = ak_error_oid_engine, __func__,
                   "the certificate has incorrect or unsupported signature algorithm identifier" );
    goto lab1;
  }
  if( verbose ) {
    ak_snprintf( message, sizeof( message ), " Algorithm:\n    %s", algoid->name[0] );
    verbose( message );
    if( paroid != NULL ) {
      ak_snprintf( message, sizeof( message ), " (params: %s)\n", paroid->name[0] );
      verbose( message );
    }
     else verbose( "\n" );
  }

 /* 4. Получаем имя эмитента (лица подписавшего сертификат)
       и сравниваем с тем, что у нас есть (если сертификат был создан ранее)
       иначе просто присваиваем имя в контекст */
  ak_asn1_next( sequence );
  if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( sequence->current->tag ) != TSEQUENCE )) {
    ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__,
                    "unexpected tag value for generalized name of certificate's issuer (tag: %x)",
                                                                          sequence->current->tag );
    goto lab1;
  }
  if( *issuer_vkey != NULL ) { /* в функцию передан созданный ранее открытый ключ проверки подписи,
                                  поэтому мы должны проверить совпадение имен, т.е. то,
                                  что переданный ключ совпадает с тем, что был использован
                                                                           при подписи сертификата */
    if( ak_tlv_compare_global_names( sequence->current, (*issuer_vkey)->name ) != ak_error_ok ) {
      error = ak_error_certificate_verify_names;
      goto lab1;
    }
  }
  if( verbose ) {
    verbose(" Issuer:\n");
    ak_tlv_snprintf_global_name( sequence->current, message, sizeof( message ));
    verbose( message ); verbose( "\n" );
  }
  // opts->issuer_name = ak_tlv_duplicate_global_name( sequence->current );

 /* 5. Получаем интервал времени действия */
  ak_asn1_next( sequence );
  if(( error =  ak_tlv_get_validity( sequence->current,
                                                     &not_before, &not_after )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect reading a validity value from asn1 context" );
    goto lab1;
  }
  if( verbose ) {
   #ifdef AK_HAVE_WINDOWS_H
    ak_snprintf( message, sizeof( message ), " Validity:\n    from: %s\n", ctime( &not_before ));
    verbose( message );
    ak_snprintf( message, sizeof( message ), "      to: %s\n", ctime( &not_after ));
    verbose( message );
   #else
    char output_buffer[128];
    strftime( output_buffer, sizeof( output_buffer ), /* локализованный вывод */
                                            "%e %b %Y %H:%M:%S (%A) %Z", localtime( &not_before ));
    ak_snprintf( message, sizeof( message ), " Validity:\n    from: %s\n", output_buffer );
    verbose( message );
    strftime( output_buffer, sizeof( output_buffer ), /* локализованный вывод */
                                             "%e %b %Y %H:%M:%S (%A) %Z", localtime( &not_after ));
    ak_snprintf( message, sizeof( message ), "      to: %s\n", output_buffer );
    verbose( message );
   #endif
  }

 /* 6. Получаем имя владельца импортируемого ключа */
  ak_asn1_next( sequence );
  if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( sequence->current->tag ) != TSEQUENCE )) {
    ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__,
                   "unexpected tag value for generalized name of certificate's subject (tag: %x)",
                                                                          sequence->current->tag );
    goto lab1;
  }
  subject_name = ak_tlv_duplicate_global_name( sequence->current );
  if( verbose ) {
    verbose(" Subject:\n");
    ak_tlv_snprintf_global_name( sequence->current, message, sizeof( message ));
    verbose( message ); verbose( "\n" );
  }

 /* 7. Получаем значение открытого ключа */
  if( ak_asn1_next( sequence ) != ak_true ) {
    ak_error_message( ak_error_invalid_asn1_count, __func__, "unexpected end of asn1 tree" );
    goto lab1;
  }

 /* проверяем наличие последовательности верхнего уровня */
  if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( sequence->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                      "the element of root asn1 tree must be a sequence with object identifiers" );
  if(( error = ak_verifykey_import_from_asn1_value( subject_vkey,
                                sequence->current->data.constructed, verbose )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect import of public key value" );
    goto lab1;
  }

 /* присваиваем значения полей */
  subject_vkey->name = subject_name;
  subject_vkey->time.not_after = not_after;
  subject_vkey->time.not_before = not_before;
  opts->created = ak_true;

  lab1:
    if( !opts->created ) {
      if( subject_vkey != NULL ) ak_tlv_delete( subject_name );
    }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция импортирует в секретный ключ расширения сертификата и определяет открытый ключ
    для проверки                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_import_from_asn1_extensions( ak_verifykey subject_vkey,
                            ak_verifykey *issuer_vkey, ak_asn1 sequence, ak_certificate_opts opts,
                                                                  ak_function_file_output verbose )
{
  size_t size = 0;
  char message[256];
  ak_oid oid = NULL;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;
  char certname[512];
  const char *sptr = NULL;
  struct certificate_opts vopts;

  if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( sequence->current->tag ) != TSEQUENCE ))
    return ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                              "incorrect asn1 tree for certificate's extensions" );
    else ak_asn1_first( sequence = sequence->current->data.constructed ); /* все расширения здесь */
  if( sequence->count == 0 ) goto lab1;
  if( verbose ) verbose(" Extensions:\n");

 /* -- часть кода, отвечающая за разбор расширений сертификата */
  do{
    ak_asn1 ext = NULL, vasn = NULL;
    if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
                                   ( TAG_NUMBER( sequence->current->tag ) != TSEQUENCE )) continue;

    ak_asn1_first( ext = sequence->current->data.constructed ); /* текущее расширение */
    if(( DATA_STRUCTURE( ext->current->tag ) != PRIMITIVE ) ||
                          ( TAG_NUMBER( ext->current->tag ) != TOBJECT_IDENTIFIER )) continue;
    if( ak_tlv_get_oid( ext->current, &ptr ) != ak_error_ok ) continue;
    if(( oid = ak_oid_find_by_id( ptr )) == NULL ) continue;
    ak_asn1_last( ext ); /* перемещаемся к данным */

   /* теперь мы разбираем поступившие расширения */
   /* ----------------------------------------------------------------------------------------- */
    if( strcmp( oid->id[0], "2.5.29.14" ) == 0 ) { /* это subjectKeyIdentifier,
                                                        т.е. номер считываемого открытого ключа */
      if(( DATA_STRUCTURE( ext->current->tag ) != PRIMITIVE ) ||
                          ( TAG_NUMBER( ext->current->tag ) != TOCTET_STRING )) continue;
     /* декодируем номер ключа */
      opts->subjkey.is_present = ak_true;
      ak_tlv_get_octet_string( ext->current, &ptr, &size );
      memcpy( subject_vkey->number, ((ak_uint8 *)ptr)+2,
                                                    opts->subjkey.length = ak_min( 32, size-2 ));
      if( verbose ) {
        ak_snprintf( message, sizeof( message ), " x509v3 Subject Key Identifier:\n    %s\n",
                       ak_ptr_to_hexstr( subject_vkey->number, opts->subjkey.length, ak_false ));
        verbose( message );
      }
    }

   /* ----------------------------------------------------------------------------------------- */
    if( strcmp( oid->id[0], "2.5.29.19" ) == 0 ) { /* это basicConstraints
                                                        т.е. принадлежность центрам сертификации */
      opts->ca.is_present = ak_true;
      if(( DATA_STRUCTURE( ext->current->tag ) != PRIMITIVE ) ||
                          ( TAG_NUMBER( ext->current->tag ) != TOCTET_STRING )) continue;
      ak_tlv_get_octet_string( ext->current, &ptr, &size );

     /* теперь разбираем поля */
      if( ak_asn1_decode( vasn = ak_asn1_new(), ptr, size, ak_false ) == ak_error_ok ) {

        if(( DATA_STRUCTURE( vasn->current->tag ) == CONSTRUCTED ) ||
           ( TAG_NUMBER( vasn->current->tag ) != TSEQUENCE )) {

           ak_asn1 vasn2 = vasn->current->data.constructed;
           if( vasn2->current != NULL ) {
             ak_asn1_first( vasn2 );
             if(( DATA_STRUCTURE( vasn2->current->tag ) == PRIMITIVE ) &&
                ( TAG_NUMBER( vasn2->current->tag ) == TBOOLEAN )) {
                  ak_tlv_get_bool( vasn2->current, &opts->ca.value );
             }
             if( ak_asn1_next( vasn2 ) ) {
               if(( DATA_STRUCTURE( vasn2->current->tag ) != PRIMITIVE ) &&
                  ( TAG_NUMBER( vasn2->current->tag ) != TINTEGER ))
                    ak_tlv_get_uint32( vasn2->current, &opts->ca.pathlenConstraint );
             }
           }
        }

        if( verbose ) {
          ak_snprintf( message, sizeof( message ),
            " x509v3 Basic Constraints:\n    ca: %s, pathlen: %d\n",
                            ( opts->ca.value ? "true" : "false" ), opts->ca.pathlenConstraint );
          verbose( message );
        }
      }
      if( vasn ) ak_asn1_delete( vasn );
    }

   /* ----------------------------------------------------------------------------------------- */
    if( strcmp( oid->id[0], "2.5.29.15" ) == 0 ) { /* это keyUsage
                                                        т.е. область применения сертификата */
      opts->key_usage.is_present = ak_true;
      if(( DATA_STRUCTURE( ext->current->tag ) != PRIMITIVE ) ||
         ( TAG_NUMBER( ext->current->tag ) != TOCTET_STRING )) continue;

     /* декодируем битовую последовательность */
      ak_tlv_get_octet_string( ext->current, &ptr, &size );
      if( ak_asn1_decode( vasn = ak_asn1_new(), ptr, size, ak_false ) == ak_error_ok ) {
        if(( DATA_STRUCTURE( vasn->current->tag ) == PRIMITIVE ) &&
           ( TAG_NUMBER( vasn->current->tag ) == TBIT_STRING )) {

          struct bit_string bs;
          ak_tlv_get_bit_string( vasn->current, &bs );
          opts->key_usage.bits = bs.value[0]; /* TODO: это фрагмент необходимо оттестировать */
          opts->key_usage.bits <<= 1;
          if( bs.len > 1 ) {
            opts->key_usage.bits <<= 8-bs.unused;
            opts->key_usage.bits ^= bs.value[1];
          }
        }
        if( verbose ) {
          verbose(" x509v3 Basic Usage:\n    " );
          if( opts->key_usage.bits&bit_decipherOnly) verbose( "Decipher " );
          if( opts->key_usage.bits&bit_encipherOnly) verbose("Encipher ");
          if( opts->key_usage.bits&bit_cRLSign) verbose("CRL sign ");
          if( opts->key_usage.bits&bit_keyCertSign) verbose("Certificate sign, ");
          if( opts->key_usage.bits&bit_keyAgreement) verbose("Key agreement ");
          if( opts->key_usage.bits&bit_dataEncipherment) verbose("Data encipherment ");
          if( opts->key_usage.bits&bit_keyEncipherment) verbose("Key encipherment ");
          if( opts->key_usage.bits&bit_contentCommitment) verbose("Content commitment ");
          if( opts->key_usage.bits&bit_digitalSignature) verbose("Digital signature");
          verbose("\n");
        }
      }
       else opts->key_usage.bits = 0;
      if( vasn ) ak_asn1_delete( vasn );
    }

   /* ----------------------------------------------------------------------------------------- */
    if( strcmp( oid->id[0], "2.5.29.35" ) == 0 ) { /* это authorityKeyIdentifier
                                                                  т.е. номера ключа проверки */
      if(( DATA_STRUCTURE( ext->current->tag ) != PRIMITIVE ) ||
         ( TAG_NUMBER( ext->current->tag ) != TOCTET_STRING )) continue;
      ak_tlv_get_octet_string( ext->current, &ptr, &size );
      if( ak_asn1_decode( vasn = ak_asn1_new(), ptr, size, ak_false ) == ak_error_ok ) {

     /* здесь мы должны иметь последовательность, примерно, такого вида

        └SEQUENCE┐
                 ├[0] 8b983b891851e8ef9c0278b8eac8d420b255c95d
                 ├[1]┐
                 │   └[4]┐
                 │       └SEQUENCE┐
                 │                ├SET┐
                 │                │   └SEQUENCE┐
                 │                │            ├OBJECT IDENTIFIER 1.2.840.113549.1.9.1 (email-address)
                 │                │            └IA5 STRING dit@minsvyaz.ru
                 └[2] 34681e40cb41ef33a9a0b7c876929a29

        где
          - [0] - номер открытого ключа, используемого для проверки подписи
                  (в openssl для самоподписанных сертификатов совпадает с SubjectKeyIdentifer (vkey->number)
          - [1] - расширенное имя владельца
          - [2] - номер сертификата открытого ключа, используемого для проверки подписи

        может быть конечно не все, например, у корневого сертификата ГУЦ нет этого расширения */

        ak_asn1 lasn = NULL;
        if(( DATA_STRUCTURE( vasn->current->tag ) != CONSTRUCTED ) ||
           ( TAG_NUMBER( vasn->current->tag ) != TSEQUENCE )) {
           ak_error_message( ak_error_invalid_asn1_tag, __func__,
                                    "incorrect asn1 tree for authorithyKeyIdentifier extension" );
           goto labstop;
        }

        lasn = vasn->current->data.constructed;
        opts->authoritykey.is_present = ak_true;
        if( verbose ) verbose(" x509v3 Authority Key Identifier:\n" );

        ak_asn1_first( lasn );
        do{
         if(( DATA_STRUCTURE( lasn->current->tag ) == CONSTRUCTED ) ||
            (( DATA_CLASS( lasn->current->tag )) == CONTEXT_SPECIFIC )) {
            switch( TAG_NUMBER( lasn->current->tag )) {
              case 0x00:
                if( verbose ) {
                  ak_snprintf( message, sizeof( message ), "    %s (unique key number)\n",
                   ak_ptr_to_hexstr( lasn->current->data.primitive, lasn->current->len, ak_false ));
                  verbose( message );
                }
                if( *issuer_vkey == NULL ) {
              /* в данной ситуации ключ проверки подписи не известен.
                 поскольку мы можем считывать из файла и искать только ключи по серийным номерам,
                 то использовать данный номер мы можем только для проверки того, что сертификат
                 является самоподписанным  т.е. subject_key.number =?  lasn->current->data.primitive */
                 if( memcmp( lasn->current->data.primitive,
                                               subject_vkey->number, lasn->current->len ) == 0 ) {
                   *issuer_vkey = subject_vkey; /* ключ проверки совпадает с ключом в сертификате */
                 }
                }
                break;

              case 0x01:
                break;

              case 0x02:
                sptr = ak_ptr_to_hexstr( lasn->current->data.primitive, lasn->current->len, ak_false );
                if( verbose ) {
                  ak_snprintf( message, sizeof( message ), "    %s (serial number)\n", sptr );
                  verbose( message );
                }

               /* теперь надо найти в каталоге с сертификатами нужный с заданым серийным номером */
                ak_snprintf( certname, sizeof( certname ), "%s/%s.cer", LIBAKRYPT_CA_PATH, sptr );
                if( *issuer_vkey == NULL ) {
                  /* у нас есть номер сертификата, пытаемся в случае необходимости считать ключ */
                  if( ak_file_or_directory( certname ) == DT_REG ) {
                    ak_certificate_opts_create( &vopts );

                    printf("import: %d\n", error =
                      ak_verifykey_import_from_certificate( *issuer_vkey, NULL,
                                                                    certname, &vopts, verbose ));
                    ak_certificate_opts_destroy( &vopts );
                    if( verbose ) {
                      ak_snprintf( message, sizeof( message ),
                                                    "    load a certificate %s\n", certname );
                      verbose( message );
                    }
                  }
                   else
                    if( verbose ) {
                      ak_snprintf( message, sizeof( message ),
                                                    "    [root certificate %s not found]\n", certname );
                      verbose( message );
                    }
                }
                break;

              default:
                break;
            }
         }
        } while( ak_asn1_next( lasn ));
        labstop:;

      }
      if( vasn ) ak_asn1_delete( vasn );
    }

   /* ----------------------------------------------------------------------------------------- */
   } while( ak_asn1_next( sequence )); /* конец цикла перебора расширений */

  /* для самоподписанных сертификатов может быть не установлено расширение 2.5.29.35,
     в этом случае, все-равно необходимо попробовать проверить подпись. */
  if(( *issuer_vkey == NULL ) && ( opts->created )) {
    if( opts->ca.is_present ) *issuer_vkey = subject_vkey; /* ключ проверки совпадает с ключом в сертификате */
  }

 lab1:
  return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция импортирует в секретный ключ значения, содержащиеся
    в последовательности TBSCerfificate                                                            */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_import_from_asn1_tbs( ak_verifykey subject_vkey,
                                 ak_verifykey *issuer_vkey, ak_tlv tbs , ak_certificate_opts opts,
                                                                  ak_function_file_output verbose )
{
  ak_asn1 sequence = NULL;
  int error = ak_error_ok;
  if( verbose ) verbose(" Type:\n    Public Key Certificate\n");

 /* считываем основные поля сертификата, определеные для версий 1 или 2. */
  if(( error = ak_verifykey_import_from_asn1_tbs_base( subject_vkey,
                issuer_vkey, sequence = tbs->data.constructed, opts, verbose )) != ak_error_ok ) {
    return ak_error_message( error, __func__, "incorrect loading a base part of certificate" );
  }

 /* пропускаем поля второй версии и переходим к третьей версии, а именно, к расширениям.
    поля расширений должны нам разъяснить, является ли данный ключ самоподписанным или нет.
    если нет, и issuer_vkey не определен, то мы должны считать его с диска */
  ak_asn1_last( sequence );
  if( opts->version != 2 ) return error; /* нам достался сертификат версии один или два */

 /* проверяекм узел */
  if(( DATA_STRUCTURE( sequence->current->tag ) != CONSTRUCTED ) ||
     (( DATA_CLASS( sequence->current->tag )) != CONTEXT_SPECIFIC ) ||
     ( TAG_NUMBER( sequence->current->tag ) != 0x3 )) {
    return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
              "incorrect tag value for certificate extensions (tag: %x)", sequence->current->tag );
  }

 /* считываем доступные расширения сертификата */
  if(( error = ak_verifykey_import_from_asn1_extensions( subject_vkey,
               issuer_vkey, sequence->current->data.constructed, opts, verbose )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect loading a certificate's extensions" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Считывание открытого ключа из сертификата, представленного в виде ASN.1 дерева.

    Функция выполняет основные действия по проверке электронной подписи
    под импортируемым сертификатом.

    \param subject_vkey контекст создаваемого открытого ключа асимметричного криптографического
    алгоритма
    \param issuer_vkey открытый ключ, с помощью которого можно проверить подпись под сертификатом;
    может принимать значение `NULL`
    \param root asn1 дерево, содержащее сертификат создаваемого открытого ключа
    \param opts структура, в которую помещаются параметры созданного открытого ключа
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_verifykey_import_from_asn1_certificate( ak_verifykey subject_vkey,
                                 ak_verifykey issuer_vkey, ak_asn1 root, ak_certificate_opts opts,
                                                                   ak_function_file_output verbose )
{
  size_t size = 0;
  ak_tlv tbs = NULL;
  ak_asn1 lvs = NULL;
  struct bit_string bs;
  ak_uint8 buffer[4096];
  int error = ak_error_ok;
  time_t now = time( NULL );
  ak_verifykey vkey = issuer_vkey;


  if( subject_vkey == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to secret key context" );
 /* 1. проверяем устройство asn1 дерева */
  if( root->count != 1 )  {
    /* здесь мы проверяем, что это сертификат, а не коллекция сертификатов, т.е.
       asn1 дерево содержит только 1 элемент верхнего уровня */
    ak_error_message( error = ak_error_invalid_asn1_count, __func__,
                                         "unexpected count of top level elements (certificates)" );
    goto lab1;
  }
  if(( DATA_STRUCTURE( root->current->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( root->current->tag ) != TSEQUENCE )) {
   /* здесь мы проверили, что внутри находится sequence */
     ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__ ,
                      "unexpected type of certificate's container (tag: %x)", root->current->tag );
     goto lab1;
  } else lvs = root->current->data.constructed;

  if( lvs->count != 3 )  {
   /* здесь мы проверяем, что это последовательность из трех элементов
      - tbs
      - параметры подписи
      - собственно сама подпись */
    ak_error_message_fmt( error = ak_error_invalid_asn1_count, __func__,
                      "incorrect count of top level certificate elements (value: %u, must be: 3)",
                                                                       (unsigned int) lvs->count );
    goto lab1;
  }

 /* 2. считываем информацию о ключе из tbsCertificate */
  ak_asn1_first( lvs );
  tbs = lvs->current;
  if(( DATA_STRUCTURE( tbs->tag ) != CONSTRUCTED ) ||
     ( TAG_NUMBER( tbs->tag ) != TSEQUENCE )) {
   /* здесь мы проверили, что внутри находится sequence */
     ak_error_message_fmt( error = ak_error_invalid_asn1_tag, __func__ ,
                  "unexpected type of TBSCertificate's container (tag: %x)", root->current->tag );
     goto lab1;
  }

 /* устанавливаем флаг, что ключ не создан, и переходим к его созданию */
  opts->created = ak_false;
  if(( error = ak_verifykey_import_from_asn1_tbs( subject_vkey,
                                                   &vkey, tbs, opts, verbose )) != ak_error_ok ) {
    if( opts->created )
      ak_error_message( error, __func__, "incorrect validating of TBSCertificate's parameters");
     else ak_error_message( error, __func__ ,
                                         "incorrect decoding of TBSCertificate's asn1 container" );
     goto lab1;
  }
  if( !opts->created ) {
    ak_error_message( error = ak_error_undefined_function, __func__ ,
                                           "incorrect import TBSCertificate from asn1 container" );
    goto lab1;
  }

 /* 3. проверяем валидность сертификата */
 /* 3.1 - наличие ключа проверки */
  if( vkey == NULL ) {
    ak_error_message( error = ak_error_certificate_verify_key, __func__,
                                   "using an undefined public key to verify a given certificate" );
    goto lab1;
  }
 /* 3.2 - проверяем срок действия сертификата */
  if(( subject_vkey->time.not_before > now ) || ( subject_vkey->time.not_after < now )) {
    ak_error_message( ak_error_certificate_validity, __func__,
             "the certificate has expired (the current time is not within the specified bounds)" );
    goto lab1;
  }

 /* 3.3 - теперь ничего не остается, как проверять подпись под сертификатом
    3.3.1 - начинаем с того, что готовим данные, под которыми должна быть проверена подпись */
  memset( buffer, 0, size = sizeof( buffer ));
  ak_asn1_first( lvs );
  if(( error = ak_tlv_encode( lvs->current, buffer, &size )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                 "incorrect encoding of tlv context contains of %u octets", (unsigned int) size );
    goto lab1;
  }

 /* 3.3.2 - теперь получаем значение подписи из asn1 дерева и сравниваем его с вычисленным значением */
  ak_asn1_last( lvs );
  if(( DATA_STRUCTURE( lvs->current->tag ) != PRIMITIVE ) ||
     ( TAG_NUMBER( lvs->current->tag ) != TBIT_STRING )) {
    ak_error_message( error = ak_error_invalid_asn1_tag, __func__ ,
                                 "the second element of child asn1 context must be a bit string" );
    goto lab1;
  }
  if(( error = ak_tlv_get_bit_string( lvs->current, &bs )) != ak_error_ok ) {
    ak_error_message( error , __func__ , "incorrect value of bit string in root asn1 context" );
    goto lab1;
  }

 /* 3.3.3  - только сейчас проверяем подпись под данными */
  if( ak_verifykey_verify_ptr( vkey, buffer, size, bs.value ) != ak_true ) {
     ak_error_message( error = ak_error_not_equal_data, __func__, "digital signature isn't valid" );
     goto lab1;
  }

 /* 4. если открытый ключ проверки подписи был создан в ходе работы функции, его надо удалить */
  lab1:
    if( vkey != NULL ) {
      if(( vkey != issuer_vkey ) && ( vkey != subject_vkey ))
        ak_oid_delete_object( vkey->oid, vkey ); /* здесь мы ожидаем, что ключ, созданный
                                       в процессе выполнения функции, был размещен в куче */
    }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция считывает из заданного файла `filename` сертификат открытого ключа,
    хранящийся в виде asn1 дерева, определяемого Р 1323565.1.023-2018.
    Собственно asn1 дерево может быть храниться в файле в виде обычной der-последовательности,
    либо в виде der-последовательности, дополнительно закодированной в `base64` (формат `pem`).

    Функция является конструктором контекста `subject_vkey`.
    После считывания asn1 дерева  функция проверяет подпись под сертификатом открытого ключа и,
    в случае успешной проверки, создает контекст `subject_vkey` и инициирует его необходимыми 
    значениями.

    Ключ проверки сертификата должен быть предварительно создан и передаватьсяс помощью 
    указателя `issuer_vkey` (если номер сертификата проверки подписи или расширенное имя владельца 
    не совпадают с тем, что содержится в issuer_vkey, то возбуждается ошибка)

    Если указатель `issuer_vkey` равен `NULL`, то функция ищет сертифкат с соответствующим серийным 
    номером в устанавливаемом библиотекой `libakrypt` каталоге; данный каталог указывается при сборке 
    библотеки из исходных текстов в параметре `AK_CA_PATH`; для unix-like систем значением по 
    умолчанию является каталог `\usr\share\ca-certificates\libakrypt`.

    \note В случае если проверка валидности сертификата не выполнена и функция возвращает ошибку,
    значение флага `opts.created` позволят определить, создан ли контекст открытого ключа и
    нужно ли в дальнейшем производить его удаление.

    \param vkey контекст создаваемого открытого ключа асимметричного криптографического алгоритма,
    параметры которого считываются из файла `filename`
    \param issuer_vkey открытый ключ, с помощью которого можно проверить подпись под сертификатом;
    может принимать значение `NULL`
    \param filename имя файла, из которого считываются значения параметров открытого ключа
    \param opts структура, в которую помещаются параметры созданного открытого ключа
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_import_from_certificate( ak_verifykey subject_vkey, ak_verifykey issuer_vkey,
                  const char *filename, ak_certificate_opts opts, ak_function_file_output verbose )
{
  ak_asn1 root = NULL;
  int error = ak_error_ok;

 /* стандартные проверки */
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                                "using null pointer to filename" );
  if( ak_certificate_opts_create( opts ) != ak_error_ok )
    return ak_error_message( ak_error_null_pointer, __func__,
                               "using null pointer to context with subject's public key options" );
 /* считываем ключ и преобразуем его в ASN.1 дерево */
  if(( error = ak_asn1_import_from_file( root = ak_asn1_new(), filename )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__,
                                     "incorrect reading of ASN.1 context from %s file", filename );
    goto lab1;
  }

 /* собственно выполняем считывающее преобразование */
  if(( error = ak_verifykey_import_from_asn1_certificate( subject_vkey,
                                            issuer_vkey, root, opts, verbose )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong import of public key from asn.1 context" );
  }

  lab1: if( root != NULL ) ak_asn1_delete( root );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция предполагает, что в области памяти `ptr` располагается сертификат открытого ключа,
    записанныей в der-кодировке.
    Причина использования даной фукции заключается в раскодировании сертификатов,
    передаваемых в ходе выполнения криптографических протоколов, и считываемых, вместе с
    другими данными, в оперативную память.

    Поведение и возвращаетмые значения функции аналогичны поведению и возвращаемым
    значениям функции ak_verifykey_import_from_certificate().

    \param vkey контекст создаваемого открытого ключа асимметричного криптографического алгоритма,
    параметры которого считываются из файла `filename`
    \param issuer_vkey открытый ключ, с помощью которого можно проверить подпись под сертификатом;
    может принимать значение `NULL`
    \param указатель на область памяти, в которой распологается сертификат открытого ключа
    \param size размер сертификата (в октетах)

    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
   возвращается код ошибки.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_import_from_ptr_as_certificate( ak_verifykey subject_vkey,
                              ak_verifykey issuer_vkey, const ak_pointer ptr, const size_t size,
                                        ak_certificate_opts opts, ak_function_file_output verbose )
{
  ak_asn1 root = NULL;
  int error = ak_error_ok;

 /* стандартные проверки */
  if(( ptr == NULL ) || ( size == 0 ))
    return ak_error_message( ak_error_null_pointer, __func__,
                                       "using null pointer or zero length data with certificate" );

  if( ak_certificate_opts_create( opts ) != ak_error_ok )
    return ak_error_message( ak_error_null_pointer, __func__,
                               "using null pointer to context with subject's public key options" );
 /* считываем ключ и преобразуем его в ASN.1 дерево */
  if(( error = ak_asn1_decode( root = ak_asn1_new(), ptr, size, ak_false )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "incorrect decoding of ASN.1 context from data buffer");
    goto lab1;
  }

 /* собственно выполняем считывающее преобразование */
  if(( error = ak_verifykey_import_from_asn1_certificate( subject_vkey,
                                            issuer_vkey, root, opts, verbose )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong import of public key from asn.1 context" );
  }

  lab1: if( root != NULL ) ak_asn1_delete( root );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_asn1_cert.c  */
/* ----------------------------------------------------------------------------------------------- */
