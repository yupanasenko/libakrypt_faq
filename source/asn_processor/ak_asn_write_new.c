#include "ak_asn_codec_new.h"

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
#ifdef LIBAKRYPT_HAVE_CTYPE_H
#include <ctype.h>
#include <printf.h>
#else
#error Library cannot be compiled without ctype.h header
#endif

int ak_asn_encode_universal_data(ak_uint8 tag_number, ak_pointer p_data, char* p_name, ak_asn_tlv p_tlv)
{
    int error; /* код ошибки */

    if(!p_data || !p_tlv)
        return ak_error_null_pointer;

    if(tag_number > 0x1E)
        return ak_error_invalid_value;

    /* Создаем пустой контекст */
    error = ak_asn_primitive_data_ctx_create(p_tlv, (tag)(UNIVERSAL | PRIMITIVE | tag_number), 0, NULL, p_name);
    if(error != ak_error_ok)
        return ak_error_message(error, __func__, "failure in creating context");

    /* Заполняем контекст закодированным значением */
    switch (tag_number)
    {
    case TBOOLEAN:
        error = new_asn_put_bool(*(boolean*)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    case TINTEGER:
        error = new_asn_put_int(*(integer*)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    case TBIT_STRING:
        error = new_asn_put_bitstr(*(bit_string*)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    case TOCTET_STRING:
        error = new_asn_put_octetstr(*(octet_string*)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    case TOBJECT_IDENTIFIER:
        error = new_asn_put_objid((object_identifier)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    case TUTF8_STRING:
        error = new_asn_put_utf8string((utf8_string)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    case TGENERALIZED_TIME:
        error = new_asn_put_generalized_time((generalized_time)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    case TUTCTIME:
        error = new_asn_put_utc_time((utc_time)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    case TVISIBLE_STRING:
        error = new_asn_put_vsblstr((visible_string)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    case TIA5_STRING:
        error = new_asn_put_ia5string((ia5_string)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    case TPRINTABLE_STRING:
        error = new_asn_put_printable_string((printable_string)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    case TNUMERIC_STRING:
        error = new_asn_put_numeric_string((numeric_string)p_data, &p_tlv->m_data.m_primitive_data, &p_tlv->m_data_len);
        break;
    default:
        return ak_error_message(ak_error_invalid_value, __func__, "unsupported data type");
    }

    if(error != ak_error_ok)
        return ak_error_message(error, __func__, "failure in encoding");

    p_tlv->m_len_byte_cnt = new_asn_get_len_byte_cnt(p_tlv->m_data_len);

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param tag тег
    @param pp_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int new_asn_put_tag(tag tag, ak_byte** pp_buff)
{
    if (!pp_buff)
        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");

    **pp_buff = tag;
    (*pp_buff)++;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param len длина данных
    @param p_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int new_asn_put_len(size_t len, ak_uint32 len_byte_cnt, ak_byte** pp_buff)
{
//    if (!pp_buff)
//        return ak_error_message(ak_error_null_pointer, __func__, "bad pointer to buffer");
//
//    if (!len_byte_cnt)
//        return ak_error_message(ak_error_null_pointer, __func__, "wrong length");

    if (len_byte_cnt == 1)
    {
        (**pp_buff) = (ak_byte) len;
        (*pp_buff)++;
    }
    else
    {
        (**pp_buff) = (ak_byte) (0x80u ^ (ak_uint8) (--len_byte_cnt));
        (*pp_buff)++;

        do
        {
            (**pp_buff) = (ak_byte) ((len >> (8u * --len_byte_cnt)) & 0xFFu);
            (*pp_buff)++;
        }while (len_byte_cnt != 0);
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param val входное значение (описание формата значения находится в определении типа integer)
    @param pp_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int new_asn_put_int(integer val, ak_byte** pp_buff, ak_uint32* p_size)
{
    bool_t high_bit;
    ak_uint8 val_len_byte_cnt;
    ak_byte* p_val;
    if (!pp_buff)
        return ak_error_null_pointer;

    if (val <= 0xFFu)
        val_len_byte_cnt = 1;
    else if (val <= 0xFFFFu)
        val_len_byte_cnt = 2;
    else if (val <= 0xFFFFFFu)
        val_len_byte_cnt = 3;
    else if (val <= 0xFFFFFFFFu)
        val_len_byte_cnt = 4;
    else
    {
        *pp_buff = NULL;
        *p_size = 0;
        return ak_error_invalid_value;
    }

    /* Проверям, возведен ли старший бит в числе */
    if((val >> ((val_len_byte_cnt - 1) * 8)) & 0x80)
    {
        high_bit = ak_true;
        *p_size = val_len_byte_cnt + 1;
    }
    else
    {
        high_bit = ak_false;
        *p_size = val_len_byte_cnt;
    }

    *pp_buff = p_val = malloc(*p_size);
    if(!p_val)
    {
        *p_size = 0;
        return ak_error_out_of_memory;
    }

    if(high_bit)
    {
        *(p_val++) = 0x00;
    }

    while(--val_len_byte_cnt > 0)
    {
        *(p_val ++) = (ak_byte)((val >> (val_len_byte_cnt * 8)) & 0xFF);
    }

    *p_val = (ak_byte)(val & 0xFF);

//    if (!val.mp_value)
//        return ak_error_message(ak_error_null_pointer, __func__, "null value");
//
//    if (!val.m_positive && !(val.mp_value[0] & 0x80u))
//        return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");
//
//    if (!val.m_positive)
//    {
//        memcpy(pp_buff, val.mp_value, val.m_val_len);
//    }
//    else
//    {
//        if (val.mp_value[0] & 0x80u)
//        {
//            *pp_buff = 0x00;
//            pp_buff++;
//        }
//
//        memcpy(pp_buff, val.mp_value, val.m_val_len);
//    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param str входная UTF-8 строка
    @param pp_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int new_asn_put_utf8string(utf8_string str, ak_byte** pp_buff, ak_uint32* p_size)
{
    *p_size = (ak_uint32)strlen((char*)str);

    if (!str || !pp_buff)
        return ak_error_null_pointer;

    *pp_buff = malloc(*p_size);
    if(!(*pp_buff))
    {
        *p_size = 0;
        return ak_error_out_of_memory;
    }

    memcpy(*pp_buff, str, *p_size);

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param src массив октетов
    @param pp_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int new_asn_put_octetstr(octet_string src, ak_byte** pp_buff, ak_uint32* p_size)
{
    if (!pp_buff || !src.mp_value)
        return ak_error_null_pointer;

    *pp_buff = malloc(src.m_val_len);
    if(!(*pp_buff))
        return ak_error_out_of_memory;

    memcpy(*pp_buff, src.mp_value, src.m_val_len);

    *p_size = src.m_val_len;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param src входная строка
    @param pp_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int new_asn_put_vsblstr(visible_string str, ak_byte** pp_buff, ak_uint32* p_size)
{
    *p_size = (ak_uint32)strlen(str);
    if (!str || !pp_buff)
        return ak_error_null_pointer;

    *pp_buff = malloc(*p_size);
    if(!(*pp_buff))
    {
        *p_size = 0;
        return ak_error_out_of_memory;
    }

    memcpy(*pp_buff, str, strlen(str));

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! На данный момент добавляются только идентификаторы, у который первое число 1 или 2,
    а второе не превосходит 32

    @param obj_id входная строка, содержая идентификатор в виде чисел, разделенных точками
    @param pp_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int new_asn_put_objid(object_identifier obj_id, ak_byte** pp_buff, ak_uint32* p_size)
{
    // FIXME: Реализовать кодирования произовльного идентификатора
    ak_uint64 num;
    object_identifier p_objid_end;
    ak_byte* p_enc_oid;

    if (!obj_id || !pp_buff)
        return ak_error_null_pointer;

    *p_size = new_asn_get_oid_byte_cnt(obj_id);

    *pp_buff = p_enc_oid = malloc(*p_size);
    if(!(p_enc_oid))
    {
        *p_size = 0;
        return ak_error_out_of_memory;
    }

    num = strtoul((char *) obj_id, &p_objid_end, 10);
    obj_id = ++p_objid_end;
    num = num * 40 + strtol((char *) obj_id, &p_objid_end, 10);
    *(p_enc_oid++) = (ak_byte) num;

    while (*p_objid_end != '\0')
    {
        obj_id = ++p_objid_end;
        num = strtoul((char *) obj_id, &p_objid_end, 10);

        if (num > 0x7Fu)
        {
            ak_byte seven_bits;
            int8_t i;
            i = 3;
            while (i > 0)
            {
                seven_bits = (ak_byte) ((num >> ((ak_uint8) i * 7u)) & 0x7Fu);
                if (seven_bits)
                    *(p_enc_oid++) = (ak_byte) (0x80u ^ seven_bits);
                i--;
            }
        }

        *(p_enc_oid++) = (ak_byte) (num & 0x7Fu);
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param src входные данные (описание формата данных находится в определении типа bit_string)
    @param pp_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int new_asn_put_bitstr(bit_string src, ak_byte** pp_buff, ak_uint32* p_size)
{
    ak_byte* p_res;

    if (!src.mp_value || !pp_buff)
        return ak_error_null_pointer;

    if (src.m_unused > 7 || !src.m_val_len)
        return ak_error_invalid_value;

    /* 1 дополнительный байт для хранения кол-ва неиспользуемых бит в послднем байте данных */
    *p_size = 1 + src.m_val_len;

    *pp_buff = p_res =  malloc(*p_size);
    if(!p_res)
    {
        *p_size = 0;
        return ak_error_out_of_memory;
    }

    *(p_res++) = src.m_unused;
    memcpy(p_res, src.mp_value, src.m_val_len);

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param val входное значение
    @param pp_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int new_asn_put_bool(boolean val, ak_byte** pp_buff, ak_uint32* p_size)
{
    if (!pp_buff)
        return ak_error_null_pointer;

    *p_size = 1;

    *pp_buff = malloc(*p_size);
    if(!(*pp_buff))
    {
        *p_size = 0;
        return ak_error_out_of_memory;
    }

    if (val)
        **pp_buff = 0xFFu;
    else
        **pp_buff = 0x00;

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param time строка в формате "YYYY-MM-DD HH:MM:SS[.ms] UTC"
    @param pp_buff указатель на область памяти, в которую записывается результат кодирования
    @return В случае успеха функция возввращает ak_error_ok (ноль).
    В противном случае, возвращается код ошибки.                                                   */
/* ----------------------------------------------------------------------------------------------- */
int new_asn_put_generalized_time(generalized_time time, ak_byte** pp_buff, ak_uint32* p_size)
{
    ak_uint8 i; /* индекс */
    ak_byte* p_val;
    if (!time || !pp_buff)
        return ak_error_null_pointer;

    *p_size = new_asn_get_gentime_byte_cnt(time);
    if (*p_size < 15)
        return ak_error_message(ak_error_invalid_value, __func__, "wrong length of time string");

    *pp_buff = p_val = malloc(*p_size);
    if(!p_val)
    {
        *p_size = 0;
        return ak_error_out_of_memory;
    }

    /* YYYY */
    for (ak_uint8 i = 0; i < 4; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of year value");
        *(p_val++) = (ak_byte) *(time++);
    }
    time++;

    /* MM */
    for (i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of month value");
        *(p_val++) = (ak_byte) *(time++);
    }
    time++;

    /* DD */
    for (i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of day value");
        *(p_val++) = (ak_byte) *(time++);
    }
    time++;

    /* HH */
    for (i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of hour value");
        *(p_val++) = (ak_byte) *(time++);
    }
    time++;

    /* MM */
    for (i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of minute value");
        *(p_val++) = (ak_byte) *(time++);
    }
    time++;

    /* SS */
    for (i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of second value");
        *(p_val++) = (ak_byte) *(time++);
    }

    /* .mmm */
    if (*time == '.')
    {
        int8_t ms_cnt = (int8_t) ((strchr(time, ' ') - time) - 1);
        if (ms_cnt == 0)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "quota of second absent");

        if (time[ms_cnt] == '0')
            return ak_error_message(ak_error_wrong_asn1_encode,
                                    __func__,
                                    "wrong format of quota of second value (it can't end by 0 symbol)");

        *(p_val++) = (ak_byte) *(time++); // помещаем символ точки
        for (i = 0; i < ms_cnt; i++)
        {
            if (!isdigit(*time))
                return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of quota of second value");
            *(p_val++) = (ak_byte) *(time++);
        }
    }

    *p_val = 'Z';

    return ak_error_ok;
}

int new_asn_put_ia5string(ia5_string str, ak_byte** pp_buff, ak_uint32* p_size)
{
    ak_uint32 str_len;
    ak_uint32 i;

    str_len = (ak_uint32)strlen(str);

    for(i = 0; i < str_len; i++)
    {
        if((unsigned char)str[i] > 127)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "unallowable symbol");
    }

    *pp_buff = malloc(str_len);
    if(!(*pp_buff))
        return ak_error_out_of_memory;

    memcpy(*pp_buff, str, str_len);

    *p_size = str_len;

    return ak_error_ok;
}

int new_asn_put_printable_string(printable_string str, ak_byte** pp_buff, ak_uint32* p_size)
{
    ak_uint32 str_len;

    if(check_prntbl_str(str, (ak_uint32)strlen(str)) == ak_false)
        return ak_error_message(ak_error_wrong_asn1_encode, __func__, "unallowable symbol");

    str_len = (ak_uint32)strlen(str);

    *pp_buff = malloc(str_len);
    if(!(*pp_buff))
        return ak_error_out_of_memory;

    memcpy(*pp_buff, str, str_len);

    *p_size = str_len;

    return ak_error_ok;
}

int new_asn_put_numeric_string(numeric_string str, ak_byte** pp_buff, ak_uint32* p_size)
{
    ak_uint32 str_len;
    ak_uint32 i;
    char c;

    str_len = (ak_uint32)strlen(str);

    for(i = 0; i < str_len; i++)
    {
        c = str[i];
        if(!((c >= '0' && c <= '9') || c == ' '))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "unallowable symbol");
    }

    *pp_buff = malloc(str_len);
    if(!(*pp_buff))
        return ak_error_out_of_memory;

    memcpy(*pp_buff, str, str_len);

    *p_size = str_len;

    return ak_error_ok;
}

int new_asn_put_utc_time(utc_time time, ak_byte** pp_buff, ak_uint32* p_size)
{
    ak_uint8 i; /* Индекс */
    ak_byte* p_val;

    if (!time || !pp_buff)
        return ak_error_null_pointer;

    *p_size = new_asn_get_gentime_byte_cnt(time);
    if (*p_size < 13)
        return ak_error_message(ak_error_invalid_value, __func__, "wrong length of time string");

    *pp_buff = p_val = malloc(*p_size);
    if(!p_val)
    {
        *p_size = 0;
        return ak_error_out_of_memory;
    }

    /* YY */
    for (i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of year value");
        *(p_val++) = (ak_byte) *(time++);
    }
    time++;

    /* MM */
    for (i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of month value");
        *(p_val++) = (ak_byte) *(time++);
    }
    time++;

    /* DD */
    for (i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of day value");
        *(p_val++) = (ak_byte) *(time++);
    }
    time++;

    /* HH */
    for (i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of hour value");
        *(p_val++) = (ak_byte) *(time++);
    }
    time++;

    /* MM */
    for (i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of minute value");
        *(p_val++) = (ak_byte) *(time++);
    }
    time++;

    /* SS */
    for (i = 0; i < 2; i++)
    {
        if (!isdigit(*time))
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of second value");
        *(p_val++) = (ak_byte) *(time++);
    }

    /* .mmm */
    if (*time == '.')
    {
        int8_t ms_cnt = (int8_t) ((strchr(time, ' ') - time) - 1);
        if (ms_cnt == 0)
            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "quota of second absent");

        if (time[ms_cnt] == '0')
            return ak_error_message(ak_error_wrong_asn1_encode,
                    __func__,
                    "wrong format of quota of second value (it can't end by 0 symbol)");

        *(p_val++) = (ak_byte) *(time++); // помещаем символ точки
        for (i = 0; i < ms_cnt; i++)
        {
            if (!isdigit(*time))
                return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong format of quota of second value");
            *(p_val++) = (ak_byte) *(time++);
        }
    }

    *p_val = 'Z';

    return ak_error_ok;
}

bool_t check_prntbl_str(printable_string str, ak_uint32 len)
{
    ak_uint32 i;
    char c;

    for(i = 0; i < len; i++)
    {
        c = str[i];
        if (!(
                (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                (c == ' ')             ||
                (c == '\'')            ||
                (c == '(')             ||
                (c == ')')             ||
                (c == '+')             ||
                (c == ',')             ||
                (c == '-')             ||
                (c == '.')             ||
                (c == '/')             ||
                (c == ':')             ||
                (c == '=')             ||
                (c == '?')                  ))
            return ak_false;
    }

    return ak_true;
}

///* ----------------------------------------------------------------------------------------------- */
///*! Функция добавляет стандартный тег ASN.1, длину данных, данные (если они присутствуют).
//    В случае, когда tag_number = TSEQUENCE | TSET, параметр p_data должен быть равен NULL,
//    а seq_or_set_len содержать длину данных, которые объединются в объект sequence или set.
//    В остальных случаях параметр p_data указывает на область памяти с данными, а seq_or_set_len
//    должен быть равен 0.
//
//    @param tag_number номер стандартного тега
//    @param p_data указатель на область памяти, в которой находятся данные для кодирования
//    @param seq_or_set_len длина закодированных данных
//    @param p_main_ps указатель на главный объект типа s_ptr_server
//    @param p_result указатель на объект типа s_ptr_server, в который поместиться блок
//           закодированных данных
//    @return В случае успеха функция возввращает ak_error_ok (ноль).
//    В противном случае, возвращается код ошибки.                                                   */
///* ----------------------------------------------------------------------------------------------- */
//int new_asn_put_universal_tlv(uint8_t tag_number,
//                          void *p_data,
//                          size_t seq_or_set_len,
//                          s_ptr_server *p_main_ps,
//                          s_ptr_server *p_result) {
//    int error;
//    size_t value_len;
//    size_t len_byte_cnt;
//
//    if (!tag_number || !p_main_ps || !p_result)
//        return ak_error_message(ak_error_null_pointer, __func__, "input argument is null");
//
//    value_len = 0;
//    len_byte_cnt = 0;
//
//    if (tag_number == TOCTET_STRING)
//    {
//        octet_string str = *((octet_string *) p_data);
//
//        if (!p_data)
//            return ak_error_message(ak_error_null_pointer, __func__, "null value");
//
//        if (!str.mp_value)
//            return ak_error_message(ak_error_null_pointer, __func__, "null value");
//
//        value_len = str.m_val_len;
//        len_byte_cnt = new_asn_get_len_byte_cnt(value_len);
//        if (!len_byte_cnt)
//            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");
//
//        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with moving cursor");
//
//        if ((error = new_asn_put_octetstr(str, p_main_ps->mp_curr + 1 + len_byte_cnt)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with adding octet string value");
//    }
//    else if (tag_number == TINTEGER)
//    {
//        integer num = *((integer *) p_data);
//        if (!p_data)
//            return ak_error_message(ak_error_null_pointer, __func__, "null value");
//
//        if (!num.mp_value)
//            return ak_error_message(ak_error_null_pointer, __func__, "null value");
//
//        value_len = num.m_val_len;
//        if (num.m_positive && (num.mp_value[0] & 0x80u))
//            value_len += 1;
//
//        len_byte_cnt = new_asn_get_len_byte_cnt(value_len);
//        if (!len_byte_cnt)
//            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");
//
//        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with moving cursor");
//
//        if ((error = new_asn_put_int(num, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with adding integer value");
//    }
//    else if (tag_number == TBIT_STRING)
//    {
//        bit_string str = *((bit_string *) p_data);
//
//        if (!p_data)
//            return ak_error_message(ak_error_null_pointer, __func__, "null value");
//
//        if (!str.mp_value)
//            return ak_error_message(ak_error_null_pointer, __func__, "null value");
//
//        value_len = str.m_val_len + 1; // 1 - для хранения кол-ва неиспользуемых битов
//
//        len_byte_cnt = new_asn_get_len_byte_cnt(value_len);
//        if (!len_byte_cnt)
//            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");
//
//        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with moving cursor");
//
//        if ((error = new_asn_put_bitstr(str, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with adding bit string value");
//    }
//    else if (tag_number == TGENERALIZED_TIME)
//    {
//        generalized_time time = *((generalized_time *) p_data);
//
//        if (!p_data)
//            return ak_error_message(ak_error_null_pointer, __func__, "null value");
//
//        value_len = new_asn_get_gentime_byte_cnt(time);
//        len_byte_cnt = new_asn_get_len_byte_cnt(value_len);
//
//        if (!len_byte_cnt)
//            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");
//
//        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with moving cursor");
//
//        if ((error = new_asn_put_generalized_time(time, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with adding generalized time value");
//    }
//    else if (tag_number == TOBJECT_IDENTIFIER)
//    {
//        object_identifier oid = *((object_identifier *) p_data);
//
//        if (!p_data)
//            return ak_error_message(ak_error_null_pointer, __func__, "null value");
//
//        value_len = new_asn_get_oid_byte_cnt(oid);
//
//        len_byte_cnt = new_asn_get_len_byte_cnt(value_len);
//        if (!len_byte_cnt)
//            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");
//
//        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with moving cursor");
//
//        if ((error = new_asn_put_objid(oid, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with adding object identifier value");
//    }
//    else if (tag_number == TUTF8_STRING)
//    {
//        utf8_string str = *((utf8_string *) p_data);
//        value_len = strlen((char *) str);
//
//        if (!p_data)
//            return ak_error_message(ak_error_null_pointer, __func__, "null value");
//
//        len_byte_cnt = new_asn_get_len_byte_cnt(value_len);
//        if (!len_byte_cnt)
//            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");
//
//        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with moving cursor");
//
//        if ((error = new_asn_put_utf8string(str, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with adding utf8 string value");
//    }
//    else if (tag_number == TBOOLEAN)
//    {
//        boolean bval = *((boolean *) p_data);
//
//        if (!p_data)
//            return ak_error_message(ak_error_null_pointer, __func__, "null value");
//
//        value_len = 1;
//
//        len_byte_cnt = new_asn_get_len_byte_cnt(value_len);
//        if (!len_byte_cnt)
//            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");
//
//        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt + value_len)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with moving cursor");
//
//        if ((error = new_asn_put_bool(bval, p_main_ps->mp_curr + len_byte_cnt + 1)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with adding boolean value");
//    }
//    else if (tag_number == TSEQUENCE || tag_number == TSET)
//    {
//        value_len = seq_or_set_len;
//        tag_number |= CONSTRUCTED;
//
//        len_byte_cnt = new_asn_get_len_byte_cnt(value_len);
//        if (!len_byte_cnt)
//            return ak_error_message(ak_error_wrong_asn1_encode, __func__, "wrong asn1 encode");
//
//        if ((error = ps_move_cursor(p_main_ps, 1 + len_byte_cnt)) != ak_error_ok)
//            return ak_error_message(error, __func__, "problems with moving cursor");
//    }
//
//    new_asn_put_tag(tag_number, p_main_ps->mp_curr);
//
//    if ((error = new_asn_put_len(value_len, p_main_ps->mp_curr + 1)) != ak_error_ok)
//        return ak_error_message(error, __func__, "problem with adding data length");
//
//    if ((error = ps_set(p_result, p_main_ps->mp_curr, 1 + len_byte_cnt + value_len, PS_U_MODE)) != ak_error_ok)
//        return ak_error_message(error, __func__, "problems with making union of asn data");
//    return error;
//}
//
