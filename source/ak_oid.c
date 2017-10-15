/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
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
/*   ak_oid.c                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_parameters.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
 const size_t ak_engine_count( void ) { return 11; }

/* ----------------------------------------------------------------------------------------------- */
/*! @param engine тип криптографического механизма
    @return Функция возвращает указатель на строку, сожержащую описание типа криптографического
    механизма. Если значение engine неверно, то возбуждается ошибка и возвращается указатель на
    null-строку                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_engine_get_str( ak_oid_engine engine )
{
  switch( engine )
 {
   case undefined_engine:  return "undefined_engine";
   case identifier:        return "identifier";
   case block_cipher:      return "block_cipher";
   case stream_cipher:     return "stream_cipher";
   case hybrid_cipher:     return "hybrid_cipher";
   case hash_function:     return "hash_function";
   case hmac_function:     return "hmac_function";
   case mac_function:      return "mac_function";
   case digital_signature: return "digital_signature";
   case random_generator:  return "random_generator";
   case update_engine:     return "update_engine";
   case oid_engine:        return "oid";
   default:                break;
 }
  ak_error_message_fmt( ak_error_undefined_value, __func__,
                                                "using a non defined engine's value %d", engine );
 return ak_null_string;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param str символьное описание, должно в точности совпадать с тем, что возвращает функция
               ak_engine_get_str().
    @return В случае успеха, возвращается значение, соответстующее символьному описанию.
    В случае, если описание неверно, то возбуждается ошибка и возвращается значение
    \ref undefined_engine.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid_engine ak_engine_str( const char *str )
{
  if(( strlen( str ) == 16 ) && ak_ptr_is_equal( "undefined_engine", (void *)str, 16 ))
                                                                            return undefined_engine;
  if(( strlen( str ) == 10 ) && ak_ptr_is_equal( "identifier", (void *)str, 10 )) return identifier;
  if(( strlen( str ) == 12 ) && ak_ptr_is_equal( "block_cipher", (void *)str, 12 ))
                                                                                return block_cipher;
  if(( strlen( str ) == 13 ) && ak_ptr_is_equal( "stream_cipher", (void *)str, 13 ))
                                                                               return stream_cipher;
  if(( strlen( str ) == 13 ) && ak_ptr_is_equal( "hybrid_cipher", (void *)str, 13 ))
                                                                               return hybrid_cipher;
  if(( strlen( str ) == 13 ) && ak_ptr_is_equal( "hash_function", (void *)str, 13 ))
                                                                               return hash_function;
  if(( strlen( str ) == 13 ) && ak_ptr_is_equal( "hmac_function", (void *)str, 12 ))
                                                                               return hmac_function;
  if(( strlen( str ) == 12 ) && ak_ptr_is_equal( "mac_function", (void *)str, 12 ))
                                                                                return mac_function;
  if(( strlen( str ) == 17 ) && ak_ptr_is_equal( "digital_signature", (void *)str, 17 ))
                                                                           return digital_signature;
  if(( strlen( str ) == 16 ) && ak_ptr_is_equal( "random_generator", (void *)str, 16 ))
                                                                            return random_generator;
  if(( strlen( str ) == 13 ) && ak_ptr_is_equal( "update_engine", (void *)str, 13 ))
                                                                               return update_engine;
  if(( strlen( str ) == 3 ) && ak_ptr_is_equal( "oid", (void *)str, 3 )) return oid_engine;

  ak_error_message_fmt( ak_error_undefined_value, __func__,
                                             "string \"%s\" is not valid engine description", str );
 return undefined_engine;
}


/* ----------------------------------------------------------------------------------------------- */
/*! @param mode режим использованиея криптографического механизма
    @return Функция возвращает указатель на строку, сожержащую описание типа криптографического
    механизма. Если значение engine неверно, то возбуждается ошибка и возвращается указатель на
    null-строку                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_mode_get_str( ak_oid_mode mode )
{
  switch( mode )
 {
   case undefined_mode:  return "undefined mode";
   case algorithm:       return "algorithm";
   case parameter:       return "parametr";
   case wcurve_params:   return "weierstrass curve parameters";
   case ecurve_params:   return "edwards curve parameters";
   case kbox_params:     return "kboxes";
   case ecb:             return "ecb mode";
   case ofb:             return "ofb mode";
   case ofb_gost:        return "ofb gost 28147-89 mode";
   case cfb:             return "cfb mode";
   case cbc:             return "cbc mode";
   case xts:             return "xts mode";
   case xts_mac:         return "xts mode with authenication";
   case xcrypt:          return "xor mode";
   case a8:              return "addition mode";
   default:              break;
 }
  ak_error_message_fmt( ak_error_undefined_value, __func__,
                                                      "using a non defined mode's value %d", mode );
 return ak_null_string;
}

/* ----------------------------------------------------------------------------------------------- */
/*                             функции класса ak_oid                                               */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значения внутренних полей структуры, описывающий OID
    криптографического механизма или параметра.

    @param oid Контекст идентификатора криптографическоого механизма
    @param engine тип криптографического механизма
    @param mode режим использования криптографического механизма
    @param name читаемое (пользователем) криптографического механизма или параметра
    @param id строка-идентификатор (последовательность чисел, разделенных точками)
    @param data указатель на данные
    @param func указатель на производящую функцию
    @return В случае успеха возвращается значение ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oid_create( ak_oid oid, ak_oid_engine engine, ak_oid_mode mode,
                        const char *name, const char *id, ak_pointer data, ak_function_void *func )
{
 int error = ak_error_ok;

  if( oid == NULL ) return ak_error_message( ak_error_null_pointer,
                                                         __func__ , "using null pointer to oid" );
  if( name == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                               "using null pointer to oid name" );
  if( id == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "using null pointer to oid numer sequence" );
 /* присваиваем имя */
  ak_buffer_create( &oid->name );
  if(( error = ak_buffer_set_str( &oid->name, name )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning of oid name");
    ak_oid_destroy( oid );
    return error;
  }

 /* присваиваем идентификатор */
  ak_buffer_create( &oid->id );
  if(( error = ak_buffer_set_str( &oid->id, id )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning of oid identifier" );
    ak_oid_destroy( oid );
    return error;
  }

 /* присваиваем остальные поля */
  oid->engine = engine;
  oid->mode = mode;
  oid->data = data;
  oid->func = func;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция уничтожает все данные, хранящиеся в полях структуры struct oid

    @param oid Контекст идентификатора криптографического механизма
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oid_destroy( ak_oid oid )
{
  int error = ak_error_ok;

  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "using null pointer to oid" );
  if(( error = ak_buffer_destroy( &oid->name )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying oid's name buffer" );

  if(( error = ak_buffer_destroy( &oid->id )) != ak_error_ok )
    ak_error_message( error, __func__, "incorrect destroying oid's identifier buffer" );

  oid->engine = undefined_engine;
  oid->mode = undefined_mode;
  oid->data = NULL;
  oid->func = NULL;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст идентификатора криптографического механизма, устанавливает его поля
    в заданные значения по-умолчанию и возвращает указатель на созданную структуру.

    @param engine тип криптографического механизма
    @param mode режим использования криптографического механизма
    @param name читаемое (пользователем) криптографического механизма или параметра
    @param id строка-идентификатор (последовательность чисел, разделенных точками)
    @param data указатель на данные
    @param func указатель на производящую функцию
    @return Если указатель успешно создан, то он и возвращается. В случае возникновения ошибки
    возвращается NULL. Код ошибки помещается в переменную ak_errno.                                */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_new( ak_oid_engine engine, ak_oid_mode mode,
                        const char *name, const char *id, ak_pointer data, ak_function_void *func )
{
  ak_oid oid = ( ak_oid ) malloc( sizeof( struct oid ));

    if( oid != NULL ) ak_oid_create( oid, engine, mode, name, id, data, func );
      else ak_error_message( ak_error_out_of_memory, __func__ , "invalid creation of a new oid" );
  return oid;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает все внутренние поля и уничтожает контекст идентификатора
   криптографического механизма.

    @param oid указатель на структуру struct oid
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_oid_delete( ak_pointer oid )
{
  if( oid != NULL ) {
    ak_oid_destroy( oid );
    free( oid );
  } else ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to oid" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*                     реализация функций доступа к глобальному списку OID                         */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция добавляет новый OID в массив.
    @param manager указатель на структуру truct context_manager
    @param oid Контекст добавляемого OID
    @return В случае успеха функция возвращает ak_error_ok. В случае ошибки возвращается ее код.   */
/* ----------------------------------------------------------------------------------------------- */
 static inline int ak_oids_add_oid( ak_context_manager manager, ak_oid oid )
{
  ak_handle handle = ak_error_wrong_handle;

  if( manager == NULL ) return ak_error_message( ak_error_get_value(), __func__ ,
                                                      "using a non initialized context manager" );
  if( oid == NULL ) return ak_error_message( ak_error_null_pointer, __func__
                                                                , "using a null pointer to oid" );

 /* создаем элемент структуры управления контекстами */
  if(( handle = ak_context_manager_add_node(
                       manager, oid, oid_engine, "", ak_oid_delete )) == ak_error_wrong_handle ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong creation of context manager node" );
    oid = ak_oid_delete( oid );
    return ak_error_wrong_handle;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return функция возвращает \ref ak_error_ok (ноль) в случае успеха. В случае возникновения
    ошибки, возвращается ее код.                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_oids_create( void )
{
  int error = ak_error_ok;
  ak_context_manager manager = NULL;

 /* получаем доступ к структуре управления контекстами */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL )
    return ak_error_message( error = ak_error_get_value(), __func__ ,
                                                        "using a non initialized context manager" );

/* ----------------------------------------------------------------------------------------------- */
/* 1. Добавляем идентификаторы алгоритмов выработки псевдо-случайных последовательностей.
           значения OID находятся в дереве библиотеки: 1.2.643.2.52.1.1 - генераторы ПСЧ  */

  if(( error = ak_oids_add_oid( manager, ak_oid_new( random_generator, algorithm, "lcg",
              "1.2.643.2.52.1.1.1", NULL, (ak_function_void *) ak_random_new_lcg ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

#ifdef __linux__
  if(( error = ak_oids_add_oid( manager, ak_oid_new( random_generator, algorithm, "linux-random",
       "1.2.643.2.52.1.1.2", NULL, (ak_function_void *) ak_random_new_dev_random ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( random_generator, algorithm, "linux-urandom",
      "1.2.643.2.52.1.1.3", NULL, (ak_function_void *) ak_random_new_dev_urandom ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );
#endif
#ifdef _WIN32
  if(( error = ak_oids_add_oid( manager, ak_oid_new( random_generator, algorithm, "winrtl",
           "1.2.643.2.52.1.1.4", NULL, (ak_function_void *) ak_random_new_winrtl ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );
#endif


/* ----------------------------------------------------------------------------------------------- */
/* 2. Добавляем идентификаторы алгоритмов бесключевого хеширования.
      значения OID взяты из перечней КриптоПро и ТК26 (http://tk26.ru/methods/OID_TK_26/index.php) */

  if(( error = ak_oids_add_oid( manager, ak_oid_new( hash_function, algorithm, "streebog256",
    "1.2.643.7.1.1.2.2", NULL, ( ak_function_void * ) ak_hash_new_streebog256 ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( hash_function, algorithm, "streebog512",
    "1.2.643.7.1.1.2.3", NULL, ( ak_function_void * ) ak_hash_new_streebog512 ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( hash_function, algorithm, "gosthash94",
              "1.2.643.2.2.9", NULL,
                            ( ak_function_void * ) ak_hash_new_gosthash94_csp ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

/* ----------------------------------------------------------------------------------------------- */
/* 3. Добавляем идентификаторы параметров алгоритма бесключевого хеширования ГОСТ Р 34.11-94. */

  if(( error = ak_oids_add_oid( manager, ak_oid_new( hash_function, kbox_params,
   "id-gosthash94-test-paramset", "1.2.643.2.2.30.0", (ak_pointer) hash_box, NULL ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( hash_function, kbox_params,
    "id-gosthash94-cryptopro-paramsetA", "1.2.643.2.2.30.1", (ak_pointer) hash_box_CSPA,
                                                                             NULL ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( hash_function, kbox_params,
    "id-gosthash94-verbaO-paramset", "1.2.643.2.2.30.2", (ak_pointer) hash_box_VerbaO,
                                                                             NULL ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

/* ----------------------------------------------------------------------------------------------- */
/* 4. Добавляем идентификаторы алгоритмов HMAC согласно Р 50.1.113-2016 */

  if(( error = ak_oids_add_oid( manager, ak_oid_new( hmac_function, algorithm, "hmac-streebog256",
    "1.2.643.7.1.1.4.1", NULL, ( ak_function_void * ) ak_hmac_new_streebog256 ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( hmac_function, algorithm, "hmac-streebog512",
    "1.2.643.7.1.1.4.2", NULL, ( ak_function_void * ) ak_hmac_new_streebog512 ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( hmac_function, algorithm, "hmac-gosthash94",
    "1.2.643.2.52.1.1.1.4.0", NULL,
                            ( ak_function_void * ) ak_hmac_new_gosthash94_csp ))) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect oid creation" );

/* ----------------------------------------------------------------------------------------------- */
/* 5. Добавляем параметры эллиптических кривых в короткой форме Вейерштрасса, в частности, и3 Р 50.1.114-2016 */

  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-tc26-gost3410-2012-256-test-paramset", "1.2.643.7.1.2.1.1.0",
       (ak_pointer) &id_tc26_gost3410_2012_256_test_paramset, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-tc26-gost3410-2012-256-paramsetA", "1.2.643.7.1.2.1.1.1",
       (ak_pointer) &id_tc26_gost3410_2012_256_paramsetA, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-rfc4357-gost3410-2001-paramsetA", "1.2.643.2.2.35.1",
       (ak_pointer) &id_rfc4357_gost3410_2001_paramsetA, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-rfc4357-gost3410-2001-paramsetB", "1.2.643.2.2.35.2",
       (ak_pointer) &id_rfc4357_gost3410_2001_paramsetB, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-rfc4357-gost3410-2001-paramsetC", "1.2.643.2.2.35.3",
       (ak_pointer) &id_rfc4357_gost3410_2001_paramsetC, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-rfc4357-2001dh-paramset", "1.2.643.2.2.36.0",
       (ak_pointer) &id_rfc4357_gost3410_2001_paramsetA, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-axel-gost3410-2012-256-paramsetA", "1.2.643.2.52.1.25.1.2.1",
       (ak_pointer) &id_axel_gost3410_2012_256_paramsetA, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );

 /* значения параметров для 512-ти битных кривых */
  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-tc26-gost3410-2012-512-test-paramset", "1.2.643.7.1.2.1.2.0",
       (ak_pointer) &id_tc26_gost3410_2012_512_test_paramset, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-tc26-gost3410-2012-512-paramsetA", "1.2.643.7.1.2.1.2.1",
       (ak_pointer) &id_tc26_gost3410_2012_512_paramsetA, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-tc26-gost3410-2012-512-paramsetB", "1.2.643.7.1.2.1.2.2",
       (ak_pointer) &id_tc26_gost3410_2012_512_paramsetB, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-tc26-gost3410-2012-512-paramsetC", "1.2.643.7.1.2.1.2.3",
       (ak_pointer) &id_tc26_gost3410_2012_512_paramsetC, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );

  if(( error = ak_oids_add_oid( manager, ak_oid_new( identifier, wcurve_params,
    "id-axel-gost3410-2012-512-paramsetA", "1.2.643.2.52.1.27.1.2.1",
       (ak_pointer) &id_axel_gost3410_2012_512_paramsetA, NULL )) != ak_error_ok ))
    return ak_error_message( error, __func__, "incorrect oid creation" );


 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_oid_get_name( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );

  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return ak_null_string;
  }

 return ak_buffer_get_str( &oid->name );
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_oid_get_id( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );

  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return ak_null_string;
  }

 return ak_buffer_get_str( &oid->id );
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_oid_get_engine_str( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );

  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return ak_null_string;
  }

 return ak_engine_get_str( oid->engine );
}

/* ----------------------------------------------------------------------------------------------- */
 const ak_oid_engine ak_oid_get_engine( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );

  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return undefined_engine;
  }

 return oid->engine;
}

/* ----------------------------------------------------------------------------------------------- */
 const char *ak_oid_get_mode_str( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );

  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return ak_null_string;
  }

 return ak_mode_get_str( oid->mode );
}

/* ----------------------------------------------------------------------------------------------- */
 const ak_oid_mode ak_oid_get_mode( ak_handle handle )
{
  ak_oid oid = ak_handle_get_context( handle, oid_engine );

  if( oid == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong handle" );
    return undefined_mode;
  }

 return oid->mode;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция ищет в структуре управления контекстами первый OID с заданным значением engine и
    возвращает его дескриптор.
    Если такое значение не найдено, возвращается значение \ref ak_error_wrong_handle.
    Если значение engine равно \ref undefined_engine, то возвращается
    первый OID в списке, следовательно, значение \ref undefined_engine может использоваться
    для перебора всех возможных OID библиотеки.

    @param engine тип криптографического механизма.
    @return Функция возвращает дескриптор найденного OID. В случае неверного поиска возвращается
    \ref ak_error_wrong_handle, код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_oid_find_by_engine( ak_oid_engine engine )
{
  size_t idx = 0;
  ak_handle handle = ak_error_wrong_handle;
  ak_context_manager manager = ak_libakrypt_get_context_manager();

  if( manager == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to context manager" );
    return ak_error_wrong_handle;
  }

 /* переборный цикл с первого элемента массива */
  for( idx = 0; idx < manager->size; idx++ ) {
     ak_context_node node = manager->array[idx];
     if(( node != NULL ) && ( node->engine == oid_engine )) {
       ak_oid oid = (ak_oid) node->ctx;
       if( engine == undefined_engine ) break; /* случай поиска первого OID */
       if( oid->engine == engine ) break; /* случай совпадения engine */
     }
  }

  if( idx < manager->size )
    handle = ak_context_manager_idx_to_handle( manager, idx );

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция продолжает поиск  в структуре управления контекстами OID'а с заданным значением engine и
    возвращает его дескриптор.
    Если такое значение не найдено, возвращается значение \ref ak_error_wrong_handle.
    Если значение engine равно \ref undefined_engine, то возвращается
    следующий OID в списке, следовательно, значение \ref undefined_engine может использоваться
    для перебора всех возможных OID библиотеки.

    Пример для перебора всех существующих OID блочного шифрования.

   \code
     ak_handle handle = ak_oid_find_by_engine( block_cipher );

     while( handle != ak_error_wrong_handle )
       handle = ak_oid_findnext_by_engine( handle, block_cipher );
   \endcode

    @param handle Дескриптор, начиная с которого производится поиск.
    @param engine тип криптографического механизма.
    @return Функция возвращает дескриптор найденного OID. В случае неверного поиска возвращается
    \ref ak_error_wrong_handle, код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_oid_findnext_by_engine( ak_handle handle, ak_oid_engine engine )
{
  size_t idx = 0, current = 0;
  ak_handle retandle = ak_error_wrong_handle;
  ak_context_manager manager = ak_libakrypt_get_context_manager();
  int error = ak_context_manager_handle_check( manager, handle, &current );

 /* мы получили в качестве параметра неверное значение handle */
  if( error != ak_error_ok ) return ak_error_wrong_handle;

 /* переборный цикл с элемента, следующего за тем, которому соответствует handle */
  for( idx = current+1; idx < manager->size; idx++ ) {
     ak_context_node node = manager->array[idx];
     if(( node != NULL ) && ( node->engine == oid_engine )) {
       ak_oid oid = (ak_oid) node->ctx;
       if( engine == undefined_engine ) break; /* случай поиска первого OID */
       if( oid->engine == engine ) break; /* случай совпадения engine */
     }
  }

  if( idx < manager->size )
    retandle = ak_context_manager_idx_to_handle( manager, idx );

 return retandle;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_oid_find_by_name( const char *name )
{
  size_t idx = 0;
  ak_handle handle = ak_error_wrong_handle;
  ak_context_manager manager = ak_libakrypt_get_context_manager();

  if( manager == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to context manager" );
    return ak_error_wrong_handle;
  }

 /* переборный цикл с первого элемента массива */
  for( idx = 0; idx < manager->size; idx++ ) {
     ak_context_node node = manager->array[idx];
     if(( node != NULL ) && ( node->engine == oid_engine )) {
       ak_oid oid = (ak_oid) node->ctx;
       if( ak_ptr_is_equal( (void *) name, oid->name.data, oid->name.size )) break;
     }
  }

  if( idx < manager->size )
    handle = ak_context_manager_idx_to_handle( manager, idx );

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_oid_find_by_id( const char *id )
{
  size_t idx = 0;
  ak_handle handle = ak_error_wrong_handle;
  ak_context_manager manager = ak_libakrypt_get_context_manager();


  if( manager == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to context manager" );
    return ak_error_wrong_handle;
  }

 /* переборный цикл с первого элемента массива */
  for( idx = 0; idx < manager->size; idx++ ) {
     ak_context_node node = manager->array[idx];
     if(( node != NULL ) && ( node->engine == oid_engine )) {
       ak_oid oid = (ak_oid) node->ctx;
       if( ak_ptr_is_equal( (void *) id, oid->id.data, oid->id.size )) break;
     }
  }

  if( idx < manager->size )
    handle = ak_context_manager_idx_to_handle( manager, idx );

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  \example example-oid.c                                                                        */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.c  */
/* ----------------------------------------------------------------------------------------------- */
