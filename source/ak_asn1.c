/* ----------------------------------------------------------------------------------------------- */
 #include <ak_asn1.h>

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

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Символ '─' в кодировке юникод */
 #define HOR_LINE    "\u2500"
/*! \brief Символ '│' в кодировке юникод */
 #define VER_LINE    "\u2502"
/*! \brief Символ '┌' в кодировке юникод */
 #define LT_CORNER   "\u250C"
/*! \brief Символ '┐' в кодировке юникод */
 #define RT_CORNER   "\u2510"
/*! \brief Символ '└' в кодировке юникод */
 #define LB_CORNER   "\u2514"
/*! \brief Символ '┘' в кодировке юникод */
 #define RB_CORNER   "\u2518"
/*! \brief Символ '├' в кодировке юникод */
 #define LTB_CORNERS "\u251C"
/*! \brief Символ '┤' в кодировке юникод */
 #define RTB_CORNERS "\u2524"

/* ----------------------------------------------------------------------------------------------- */
 #define TEXT_COLOR_DEFAULT ("\x1b[0m")
 #define TEXT_COLOR_RED     ("\x1b[31m")
 #define TEXT_COLOR_BLUE    ("\x1b[34m")

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Макрос для подсчета кол-ва байтов, которыми кодируется символ юникода */
 #define UNICODE_SYMBOL_LEN(x) strlen(x)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Массив, содержащий символьное представление тега. */
 static char tag_description[32] = "\0";
/*! \brief Массив, содержащий префикс в выводимой строке с типом данных. */
 static char prefix[1024] = "";

/* ----------------------------------------------------------------------------------------------- */
                                      /*  служебные функции */
/* ----------------------------------------------------------------------------------------------- */
/*! \param len длина данных
    \return Кол-во байтов, необходимое для хранения закодированной длины.                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_uint8 ak_asn1_get_length_size( const size_t len )
{
    if (len < 0x80u && len >= 0)
        return 1;
    if (len <= 0xFFu)
        return 2;
    if (len <= 0xFFFFu)
        return 3;
    if (len <= 0xFFFFFFu)
        return 4;
    if (len <= 0xFFFFFFFFu)
        return 5;
    else
        return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! На данный момент разбираюся только теги, представленные одним байтом.
    Указатель на данные сдвигается на длину тега (1 октет).

    @param pp_data указатель на тег
    @param p_tag указатель на переменную, содержащую тег
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_get_tag_from_der( ak_uint8** pp_data, ak_uint8 *p_tag )
{
  if ( !pp_data || !p_tag ) return ak_error_null_pointer;

 /* записываем тег */
  *p_tag = **pp_data;
 /* смещаем указатель на данные */
  (*pp_data)++;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! На данный момент определяется длинна, представленная не более, чем в 4 байтах.

    @param pp_data указатель на длину данных
    @param p_len указатель переменную, содержащую длинну блока данных
    @param p_len_byte_cnt указатель переменную, содержащую кол-во памяти (в байтах),
           необходимое для хранения длины блока данных в DER последовательности
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int ak_asn1_get_length_from_der( ak_uint8** pp_data, size_t *p_len )
{
    ak_uint8 len_byte_cnt; /* Кол-во байтов, которыми представлена длина */
    ak_uint8 i; /* Индекс */

    if (!pp_data || !p_len) return ak_error_null_pointer;

    *p_len = 0;

    if (**pp_data & 0x80u)
    {
        len_byte_cnt = (ak_uint8) ((**pp_data) & 0x7Fu);
        (*pp_data)++;

        if (len_byte_cnt > 4)
            return ak_error_wrong_length;

        for (i = 0; i < len_byte_cnt; i++)
        {
            *p_len = (*p_len << 8u) | (**pp_data);
            (*pp_data)++;
        }
    }
    else
    {
        *p_len = **pp_data;
        (*pp_data)++;
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tag тег данных
    \return Строка с символьным представлением тега                                                */
/* ----------------------------------------------------------------------------------------------- */
 const char* ak_asn1_get_tag_description( ak_uint8 tag )
{
    /* используется tag_description - статическая переменная */

    if( DATA_CLASS( tag ) == UNIVERSAL ) {
      switch( tag & 0x1F )
     {
      case TEOC :              ak_snprintf( tag_description, sizeof(tag_description), "EOC" ); break;
      case TBOOLEAN:           ak_snprintf( tag_description, sizeof(tag_description), "BOOLEAN" ); break;
      case TINTEGER:           ak_snprintf( tag_description, sizeof(tag_description), "INTEGER" ); break;
      case TBIT_STRING:        ak_snprintf( tag_description, sizeof(tag_description), "BIT STRING"); break;
      case TOCTET_STRING:      ak_snprintf( tag_description, sizeof(tag_description), "OCTET STRING"); break;
      case TNULL:              ak_snprintf( tag_description, sizeof(tag_description), "NULL"); break;
      case TOBJECT_IDENTIFIER: ak_snprintf( tag_description, sizeof(tag_description), "OBJECT IDENTIFIER"); break;
      case TOBJECT_DESCRIPTOR: ak_snprintf( tag_description, sizeof(tag_description), "OBJECT DESCRIPTOR"); break;
      case TEXTERNAL:          ak_snprintf( tag_description, sizeof(tag_description), "EXTERNAL"); break;
      case TREAL:              ak_snprintf( tag_description, sizeof(tag_description), "REAL"); break;
      case TENUMERATED:        ak_snprintf( tag_description, sizeof(tag_description), "ENUMERATED"); break;
      case TUTF8_STRING:       ak_snprintf( tag_description, sizeof(tag_description), "UTF8 STRING"); break;
      case TSEQUENCE:          ak_snprintf( tag_description, sizeof(tag_description), "SEQUENCE"); break;
      case TSET:               ak_snprintf( tag_description, sizeof(tag_description), "SET"); break;
      case TNUMERIC_STRING:    ak_snprintf( tag_description, sizeof(tag_description), "NUMERIC STRING"); break;
      case TPRINTABLE_STRING:  ak_snprintf( tag_description, sizeof(tag_description), "PRINTABLE STRING"); break;
      case TT61_STRING:        ak_snprintf( tag_description, sizeof(tag_description), "T61 STRING"); break;
      case TVIDEOTEX_STRING:   ak_snprintf( tag_description, sizeof(tag_description), "VIDEOTEX STRING"); break;
      case TIA5_STRING:        ak_snprintf( tag_description, sizeof(tag_description), "IA5 STRING"); break;
      case TUTCTIME:           ak_snprintf( tag_description, sizeof(tag_description), "UTC TIME"); break;
      case TGENERALIZED_TIME:  ak_snprintf( tag_description, sizeof(tag_description), "GENERALIZED TIME"); break;
      case TGRAPHIC_STRING:    ak_snprintf( tag_description, sizeof(tag_description), "GRAPHIC STRING"); break;
      case TVISIBLE_STRING:    ak_snprintf( tag_description, sizeof(tag_description), "VISIBLE STRING"); break;
      case TGENERAL_STRING:    ak_snprintf( tag_description, sizeof(tag_description), "GENERAL STRING"); break;
      case TUNIVERSAL_STRING:  ak_snprintf( tag_description, sizeof(tag_description), "UNIVERSAL STRING"); break;
      case TCHARACTER_STRING:  ak_snprintf( tag_description, sizeof(tag_description), "CHARACTER STRING"); break;
      case TBMP_STRING:        ak_snprintf( tag_description, sizeof(tag_description), "BMP STRING"); break;
      default:                 ak_snprintf( tag_description, sizeof(tag_description), "UNKNOWN TYPE"); break;
     }
    return  tag_description;
    }
     else
      if( DATA_CLASS( tag ) == CONTEXT_SPECIFIC )
    {
        /* Добавляем номер тега (младшие 5 бит) */
        ak_snprintf( tag_description, sizeof( tag_description ), "[%u]", tag & 0x1F);
        return tag_description;
    }
 return ak_null_string;
}

/* ----------------------------------------------------------------------------------------------- */
                       /*  функции для разбора/создания узлов ASN1 дерева */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция заполняет поля структуры примитивного узла ASN1 дерева заданными значениями.

    \param tlv указатель на структуру узла, память под tlv структуру должна быть выделена заранее.
    \param tag тип размещаемого элемента
    \param len длина кодированного представления элемента
    \param data собственно кодированные данные
    \param free флаг, определяющий, нужно ли выделять память под кодированные данные
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_context_create_primitive( ak_tlv tlv, ak_uint8 tag,
                                                        size_t len, ak_pointer data, bool_t free )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  if( DATA_STRUCTURE( tag ) != PRIMITIVE )
    return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                            "data must be primitive, but tag has value: %u", tag );
 /* Добавляем тег и длину */
  tlv->tag = tag;
  tlv->len = (ak_uint32) len;

  if( len == 0 ) tlv->data.primitive = NULL;
   else { /* добавляем данные */

    if( free ) {
      if(( tlv->data.primitive = malloc( len )) == NULL )
        return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
      if( data != NULL ) memcpy( tlv->data.primitive, data, len );

    } else tlv->data.primitive = data;
   }
  tlv->free = free;
  tlv->prev = tlv->next = NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_context_create_constructed( ak_tlv tlv, ak_uint8 tag, ak_asn1 asn1 )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  if( DATA_STRUCTURE( tag ) != CONSTRUCTED )
    return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                          "data must be constructed, but tag has value: %u", tag );
  tlv->tag = tag;
  tlv->len = 0;
  tlv->data.constructed = asn1;
  tlv->free = ak_false;
  tlv->prev = tlv->next = NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_context_destroy( ak_tlv tlv )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  switch( DATA_STRUCTURE( tlv->tag )) {
    case PRIMITIVE: /* уничтожаем примитивный узел */
      if(( tlv->free ) && ( tlv->data.primitive != NULL )) free( tlv->data.primitive );
     break;

    case CONSTRUCTED: /* уничтожаем составной узел */
      if( tlv->data.constructed != NULL )
        tlv->data.constructed = ak_asn1_context_delete( tlv->data.constructed );
     break;

    default: ak_error_message( ak_error_invalid_asn1_tag, __func__ ,
                                                   "destroying tlv context with wrong tag value" );
  }
  tlv->tag = TEOC;
  tlv->len = 0;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_tlv_context_delete( ak_pointer tlv )
{
  if( tlv == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "deleting null pointer to tlv element" );
    return NULL;
  }
  ak_tlv_context_destroy( (ak_tlv) tlv );
  free( tlv );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param fp Файловый дескриптор, в  который выводится информация об узле ASN1 дерева; дескриптор
    должен быть предварительно связан с файлом.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_context_print( ak_tlv tlv, FILE *fp )
{
  const char *dp = NULL;
  char tmp[ sizeof(prefix) ];
  size_t plen = strlen( prefix );

  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
 /* выводим информацию об узле */
  dp = ak_asn1_get_tag_description( tlv->tag );

  if( DATA_STRUCTURE( tlv->tag) == CONSTRUCTED) {
    const char *corner = LTB_CORNERS;

   /* вычисляем уголочек */
    if( tlv->next == NULL ) corner = LB_CORNER;
    if(( plen == 0 ) && ( tlv->prev == NULL )) corner = LT_CORNER;

   /* выводим префикс и тег */
    fprintf( fp, "%s%s%s%s\n", prefix, corner, dp, RT_CORNER );

    memset( tmp, 0, sizeof( tmp ));
    memcpy( tmp, prefix, ak_min( sizeof(tmp)-1, strlen( prefix )));
    if( tlv->next == NULL )
      ak_snprintf( prefix, sizeof( prefix ), "%s%s%*s", tmp, " ", strlen(dp), " " );
     else ak_snprintf( prefix, sizeof( prefix ), "%s%s%*s", tmp, VER_LINE, strlen(dp), " " );

    ak_asn1_context_print( tlv->data.constructed, fp );
    prefix[plen] = 0;
  }
   else {
        /* выводим префикс и тег */
         if( tlv->next == NULL ) fprintf( fp, "%s%s%s ", prefix, LB_CORNER, dp );
          else fprintf( fp, "%s%s%s ", prefix, LTB_CORNERS, dp );

        /* теперь собственно данные */
         if( DATA_CLASS( tlv->tag) == UNIVERSAL )
           ak_tlv_context_print_primitive( tlv, fp );
          else {
            if( DATA_CLASS( tlv->tag ) == CONTEXT_SPECIFIC ) {
              if( tlv->data.primitive != NULL )
                fprintf( fp, "%s\n", ak_ptr_to_hexstr( tlv->data.primitive, tlv->len, ak_false ));
               else  fprintf( fp, "%s(null)%s", TEXT_COLOR_RED, TEXT_COLOR_DEFAULT );
            }
             else fprintf( fp, "%sUnknown data%s\n", TEXT_COLOR_RED, TEXT_COLOR_DEFAULT );
          } /* конец else UNIVERSAL */
   }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_context_print_primitive( ak_tlv tlv, FILE *fp )
{
  ak_uint32 u32 = 0;
  ak_pointer ptr = NULL;
  int error = ak_error_ok;
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  switch( TAG_NUMBER( tlv->tag )) {

    case TBOOLEAN:
      if( *tlv->data.primitive == 0x00 ) fprintf( fp, "FALSE\n" );
        else fprintf( fp, "TRUE\n");
      break;

    case TINTEGER:
      if(( error = ak_tlv_context_get_uint32( tlv, &u32 )) == ak_error_ok )
        fprintf( fp, "%u\n", u32 );
       else {
         switch( error ) {
//           case ak_error_invalid_asn1_length:  /* здесь нужно чтение mpzn */ break;
//           case ak_error_invalid_asn1_significance: /* здесь нужно чтение знаковых целых */ break;
           default:
            if( tlv->data.primitive != NULL )
               fprintf( fp, " [len: %u, data: 0x%s]\n", tlv->len,
                                      ak_ptr_to_hexstr( tlv->data.primitive, tlv->len, ak_false ));
              else  fprintf( fp, " [len: %u, data: (null)]\n", tlv->len );
         }
       }
      break;

    case TOCTET_STRING:
      if(( error = ak_tlv_context_get_octet_string( tlv, &ptr, (size_t *)&u32 )) == ak_error_ok )
        fprintf( fp, "%s\n", ak_ptr_to_hexstr( ptr, u32, ak_false ));
      break;

    default: if( tlv->data.primitive != NULL )
               fprintf( fp, " [len: %u, data: 0x%s]\n", tlv->len,
                                      ak_ptr_to_hexstr( tlv->data.primitive, tlv->len, ak_false ));
              else fprintf( fp, " [len: %u, data: (null)]\n", tlv->len );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param bool Указатель на переменную, в которую будет помещено булево значение.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае, когда узел действительно содержит
    булево значение. В противном случае возвращается код ошибки.                                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_context_get_bool( ak_tlv tlv, bool_t *bool )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  if(( DATA_CLASS( tlv->tag) == UNIVERSAL ) && ( TAG_NUMBER( tlv->tag ) == TBOOLEAN )) {
    if( *tlv->data.primitive == 0x00 ) *bool = ak_false;
     else *bool = ak_true;
   return ak_error_ok;
  }

 return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                              "incorrect tag value of tlv context: %u", tlv->tag );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param u32 Указатель на переменную, в которую будет помещено значение.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае, когда узел действительно содержит
    целое значение. В противном случае возвращается код ошибки.                                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_context_get_uint32( ak_tlv tlv, ak_uint32 *u32 )
{
  ak_uint32 idx = 0;
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  if(( DATA_CLASS( tlv->tag) == UNIVERSAL ) && ( TAG_NUMBER( tlv->tag ) == TINTEGER )) {
    /* если длина больше 5, то преобразование невозможно */
     if(( tlv->len > 5 ) || (( tlv->len == 5 ) && ( tlv->data.primitive[0] != 0 )))
       return ak_error_invalid_asn1_length;

    /* если данные отрицательны, нужна другая функция для чтения */
     if(( tlv->data.primitive[0] != 0 ) && ( tlv->data.primitive[0]&0x80 ))
       return ak_error_invalid_asn1_significance;

    /* теперь обычное чтение */
     *u32 = 0;
     while( idx < tlv->len ) {
       *u32 <<= 8; *u32 += tlv->data.primitive[idx]; idx++;
     }
    return ak_error_ok;
  }

 return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                              "incorrect tag value of tlv context: %u", tlv->tag );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param tlv указатель на структуру узла ASN1 дерева.
    \param ptr указатель на область памяти, в которой располагается последовательность октетов
    \param len переменная, куда будет помещена длина данных
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в противном
    случае возвращается код ошибки.                                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_tlv_context_get_octet_string( ak_tlv tlv, ak_pointer *ptr, size_t *len )
{
  if( tlv == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to tlv element" );
  *len = tlv->len;
  *ptr = tlv->data.primitive;

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
                       /*  функции для разбора/создания слоев ASN1 дерева */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_create( ak_asn1 asn1 )
{
  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  asn1->current = NULL;
  asn1->count = 0;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_context_next( ak_asn1 asn1 )
{
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return ak_false;
  }
  if( asn1->current == NULL ) return ak_false;
  if( asn1->current->next != NULL ) { asn1->current = asn1->current->next; return ak_true; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_context_prev( ak_asn1 asn1 )
{
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return ak_false;
  }
  if( asn1->current == NULL ) return ak_false;
  if( asn1->current->prev != NULL ) { asn1->current = asn1->current->prev; return ak_true; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_context_last( ak_asn1 asn1 )
{
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return ak_false;
  }
  if( asn1->current == NULL ) return ak_false;
  while( asn1->current->next != NULL ) { asn1->current = asn1->current->next; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_context_first( ak_asn1 asn1 )
{
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return ak_false;
  }
  if( asn1->current == NULL ) return ak_false;
  while( asn1->current->prev != NULL ) { asn1->current = asn1->current->prev; }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_asn1_context_remove( ak_asn1 asn1 )
{
  ak_tlv n = NULL, m = NULL;
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return ak_false;
  }

 /* если список пуст */
  if( asn1->current == NULL ) return ak_false;
 /* если в списоке только один элемент */
  if(( asn1->current->next == NULL ) && ( asn1->current->prev == NULL )) {
    asn1->current = ak_tlv_context_delete( asn1->current );
    asn1->count = 0;
    return ak_false;
  }

 /* теперь список полон */
  n = asn1->current->prev;
  m = asn1->current->next;
  if( m != NULL ) { /* делаем активным (замещаем удаляемый) следующий элемент */
    ak_tlv_context_delete( asn1->current );
    asn1->current = m;
    if( n == NULL ) asn1->current->prev = NULL;
      else { asn1->current->prev = n; n->next = m; }
    asn1->count--;
    return ak_true;
  } else /* делаем активным предыдущий элемент */
       {
         ak_tlv_context_delete( asn1->current );
         asn1->current = n; asn1->current->next = NULL;
         asn1->count--;
         return ak_true;
       }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_destroy( ak_asn1 asn1 )
{
  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  while( ak_asn1_context_remove( asn1 ) == ak_true );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_asn1_context_delete( ak_pointer asn1 )
{
  if( asn1 == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to asn1 element" );
    return NULL;
  }
  ak_asn1_context_destroy( (ak_asn1) asn1 );
  free( asn1 );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_add_tlv( ak_asn1 asn1, ak_tlv tlv )
{
  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  ak_asn1_context_last( asn1 );
  if( asn1->current == NULL ) asn1->current = tlv;
   else {
          tlv->prev = asn1->current;
          asn1->current->next = tlv;
          asn1->current = tlv;
        }
  asn1->count++;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция кодирует значение, которое содержится в переменной `bool`, и помещает его на
    текущий уровень ASN1 дерева.
    \param asn1 указатель на текущий уровень ASN1 дерева.
    \param bool булева переменная.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_add_bool( ak_asn1 asn1, const bool_t bool )
{
  ak_tlv tlv = NULL;
  ak_uint8 val = 0x00;
  int error = ak_error_ok;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  if( bool ) val = 0xFFu;
  if(( error = ak_tlv_context_create_primitive(
                tlv = malloc( sizeof( struct tlv )), TBOOLEAN, 1, &val, ak_true )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of tlv element" );

 return ak_asn1_context_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция кодирует значение, которое содержится в переменной `u32`, и помещает его на
    текущий уровень ASN1 дерева.
    \param asn1 указатель на текущий уровень ASN1 дерева.
    \param u32 целочисленная беззнаковая переменная.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_add_uint32( ak_asn1 asn1, const ak_uint32 u32 )
{
  size_t len = 0;
  ak_uint8 byte = 0;
  ak_tlv tlv = NULL;
  ak_uint32 val = u32;
  int error = ak_error_ok;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
 /* вычисляем количество значащих октетов */
  if(( byte = (ak_uint8)( u32 >> 24 )) != 0 ) len = 4;
   else if(( byte = (ak_uint8)( u32>>26 )) != 0 ) len = 3;
         else if(( byte = (ak_uint8)( u32>>8 )) != 0 ) len = 2;
                else { len = 1; byte = (ak_uint8) u32; }

 /* проверяем старший бит, если он установлен, т.е. byte > 127,
    то при кодировании будем использовать дополнительный октет */
  if( byte&0x80 ) len++;

 /* создаем элемент и выделяем память */
  if(( error = ak_tlv_context_create_primitive(
              tlv = malloc( sizeof( struct tlv )), TINTEGER, len, NULL, ak_true )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of tlv element" );

 /* заполняем выделенную память значениями */
  memset( tlv->data.primitive, 0, len );
  do{
      tlv->data.primitive[len-1] = val&0xFF;  val >>= 8;
  } while( --len > 0 );

 return ak_asn1_context_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция кодирует значение, которое содержится в переменной `u32`, и помещает его на
    текущий уровень ASN1 дерева.
    \param asn1 указатель на текущий уровень ASN1 дерева.
    \param u32 целочисленная беззнаковая переменная.
    \return Функция возвращает \ref ak_error_ok (ноль) в случае успеха, в случае неудачи
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_add_octet_string( ak_asn1 asn1, const ak_pointer ptr, const size_t len )
{
  ak_tlv tlv = NULL;
  int error = ak_error_ok;

 /* создаем элемент и выделяем память */
  if(( error = ak_tlv_context_create_primitive(
          tlv = malloc( sizeof( struct tlv )), TOCTET_STRING, len, ptr, ak_true )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of tlv element" );

 return ak_asn1_context_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_add_asn1( ak_asn1 asn1, ak_uint8 tag, ak_asn1 down )
{
  ak_tlv tlv = NULL;
  ak_uint8 contag = tag;
  int error = ak_error_ok;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to root asn1 element" );
  if( down == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  if( !( contag&CONSTRUCTED )) contag ^= CONSTRUCTED;
  if(( error = ak_tlv_context_create_constructed(
                                 tlv = malloc( sizeof( struct tlv )), contag, down )) != ak_error_ok )
    return ak_error_message( error, __func__, "incorrect creation of tlv element" );

 return ak_asn1_context_add_tlv( asn1, tlv );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_print( ak_asn1 asn1, FILE *fp )
{
  ak_tlv x = NULL;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  if( fp == NULL )  return ak_error_message( ak_error_null_pointer, __func__,
                                                            "using null pointer to file context" );
 /* перебираем все узлы текущего слоя, начиная с первого */
  x = asn1->current;
  ak_asn1_context_first( asn1 );
  if( asn1->current == NULL ) /* это некорректная ситуация, поэтому сообщение выделяется красным */
    fprintf( fp, "%s%s (null)%s\n", TEXT_COLOR_RED, prefix, TEXT_COLOR_DEFAULT );

   else { /* перебор всех доступных узлов */
    do{
      ak_tlv_context_print( asn1->current, fp );
    } while( ak_asn1_context_next( asn1 ));
  }

 /* восстанавливаем исходное состояние */
  asn1->current = x;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_asn1_context_decode( ak_asn1 asn1, const ak_pointer ptr, const size_t size )
{
  size_t len = 0;
  ak_tlv tlv = NULL;
  ak_asn1 asnew = NULL;
  int error = ak_error_ok;
  ak_uint8 *pcurr = NULL, *pend = NULL, tag = 0;

  if( asn1 == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to asn1 element" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                             "using null pointer to der-sequence" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__,
                                                            "using der-sequence with zero length" );
 /* инициируем переменные */
  pcurr = (ak_uint8 *) ptr;
  pend = pcurr + size;

 /* перебираем все возможные фрагменты */
  while( pcurr < pend ) {
    ak_asn1_get_tag_from_der( &pcurr, &tag );

    if(( error = ak_asn1_get_length_from_der( &pcurr, &len )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect decoding of data's length" );
    if( pcurr + len > pend )
      return ak_error_message( ak_error_wrong_length, __func__, "wrong der-sequence length");

    switch( DATA_STRUCTURE( tag )) {
      case PRIMITIVE:
        ak_tlv_context_create_primitive( tlv = malloc( sizeof( struct tlv )),  tag, len, pcurr, ak_false );
        ak_asn1_context_add_tlv( asn1, tlv );
        break;

      case CONSTRUCTED:
        ak_asn1_context_create( asnew = malloc( sizeof( struct asn1 )));
        ak_asn1_context_decode( asnew, pcurr, len );
        ak_asn1_context_add_asn1( asn1, tag, asnew );
        break;

      default: return ak_error_message_fmt( ak_error_invalid_asn1_tag, __func__,
                                                         "unexpected tag's value of tlv element" );
    }
    pcurr += len;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_asn1.c  */
/* ----------------------------------------------------------------------------------------------- */
