//
// Created by Anton Sakharov on 2019-08-08.
//

#include "ak_asn_codec_new.h"
#include "ak_oid.h"

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
#else
#error Library cannot be compiled without ctype.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! @param len длина данных
    @return Кол-во байтов, необходимое для хранения закодированной длины.                          */
/* ----------------------------------------------------------------------------------------------- */
ak_uint8 new_asn_get_len_byte_cnt(size_t len)
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
/*! @param oid строка, содержая идентификатор в виде чисел, разделенных точками
    @return Кол-во байтов, необходимое для хранения закодированного идентификатора.                */
/* ----------------------------------------------------------------------------------------------- */
ak_uint8 new_asn_get_oid_byte_cnt(object_identifier oid) {
    ak_uint8 byte_cnt;
    object_identifier p_end;
    size_t num;

    if (!oid)
        return 0;

    byte_cnt = 1;

    /* Пропускаем 2 первых идентификатора */
    strtoul((char *) oid, &p_end, 10);
    oid = ++p_end;
    strtol((char *) oid, &p_end, 10);

    while (*p_end != '\0')
    {
        oid = ++p_end;
        num = (size_t) strtol((char *) oid, &p_end, 10);
        if (num <= 0x7Fu)             /*                               0111 1111 -  7 бит */
            byte_cnt += 1;
        else if (num <= 0x3FFFu)      /*                     0011 1111 1111 1111 - 14 бит */
            byte_cnt += 2;
        else if (num <= 0x1FFFFFu)    /*           0001 1111 1111 1111 1111 1111 - 21 бит */
            byte_cnt += 3;
        else if (num <= 0x0FFFFFFFu)  /* 0000 1111 1111 1111 1111 1111 1111 1111 - 28 бит */
            byte_cnt += 4;
        else
            return 0;
    }
    return byte_cnt;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param time строка, содержая время в формате "YYYY-MM-DD HH:MM:SS.[ms] UTC"
    @return Кол-во байтов, необходимое для хранения закодированного времени.                       */
/* ----------------------------------------------------------------------------------------------- */
ak_uint8 new_asn_get_gentime_byte_cnt(generalized_time time) {
    if (!time)
        return 0;
    /*
     * 8 имеет след. смысл:
     * - из строки "YYYY-MM-DD HH:MM:SS.[ms] UTC" удалить символы "-- :: UTC"
     * - добавить символ "Z"
     * Примечание: эл-ов ms может быть неограниченное кол-во.
    */
    return (ak_uint8) (strlen(time) - 8);
}

int ak_bitstr_set_str(bit_string* p_bit_str, char* str)
{
    // Todo: подумать над более оптимальной и наглядной реализацией
    size_t i, j, k;
    size_t str_len;
    ak_byte byte;

    if(!p_bit_str || !str)
        return ak_error_null_pointer;

    str_len = strlen(str);

    if(!str_len)
        return ak_error_invalid_value;

    p_bit_str->m_unused = (str_len % 8) ? (ak_uint8)(8 - str_len % 8) : (ak_uint8)0;

    if(p_bit_str->m_unused == 0)
        p_bit_str->m_val_len = (ak_uint32)(str_len / 8);
    else
        p_bit_str->m_val_len = (ak_uint32)(str_len / 8 + 1);

    if(p_bit_str->m_unused == 0)
        p_bit_str->m_val_len++;

    p_bit_str->mp_value = calloc(p_bit_str->m_val_len, sizeof(ak_byte));
    if(!p_bit_str->mp_value)
        return ak_error_null_pointer;

    byte = 0;
    for(i = 0, k = 0; i < str_len && k < p_bit_str->m_val_len; i += 8, k++)
    {
        for (j = i; j < i + 8; j++)
        {
            if (str[j] == '1')
                byte += 1;
            else if (str[j] != '0')
            {
                free(p_bit_str->mp_value);
                p_bit_str->m_val_len = p_bit_str->m_unused = 0;
                p_bit_str->mp_value = NULL;
                return ak_error_invalid_value;
            }

            if(j == str_len - 1)
            {
                byte = byte << p_bit_str->m_unused;
                break;
            }

            if (!((j > 0) && (!(j % 7))))
                byte = byte << 1;
        }

        p_bit_str->mp_value[k] = byte;
        byte = 0;
    }

    return ak_error_ok;
}

int ak_bitstr_set_ui(bit_string* p_bit_str, ak_uint64 val64, ak_uint8 used_bits)
{
    ak_int8 i;

    if(!p_bit_str)
        return ak_error_null_pointer;

    if(used_bits > sizeof(val64) * 8)
        return ak_error_invalid_value;

//    if(used_bits < 8)
//        p_bit_str->m_val_len = 1;
//    else
    p_bit_str->m_val_len = (used_bits % 8) ? (ak_uint32)(used_bits / 8 + 1) : (ak_uint32)(used_bits / 8);

    p_bit_str->m_unused = (used_bits % 8) ? (ak_uint8)(8 - (used_bits % 8)) : (ak_uint8)0;

    val64 = val64 << p_bit_str->m_unused;

    p_bit_str->mp_value = malloc(p_bit_str->m_val_len);
    if(!p_bit_str->mp_value)
        return ak_error_out_of_memory;

    for(i = 0; i < p_bit_str->m_val_len - 1; i++)
        p_bit_str->mp_value[i] = (ak_byte)((val64 >> (8 * (p_bit_str->m_val_len - 1 - i))) & 0xFF);

    p_bit_str->mp_value[p_bit_str->m_val_len - 1] = (ak_byte)(val64 & 0xFF);

    return ak_error_ok;
}

int ak_bitstr_set_arr(bit_string* p_bit_str, ak_byte* p_data, ak_uint32 size, ak_uint8 unused_bits)
{
    if(!p_bit_str || !p_data)
        return ak_error_null_pointer;

    if(!size || unused_bits > 7)
        return ak_error_invalid_value;

    p_bit_str->mp_value = malloc(size);
    if(p_bit_str->mp_value)
        return ak_error_out_of_memory;

    memcpy(p_bit_str->mp_value, p_data, size);
    p_bit_str->m_val_len = size;
    p_bit_str->m_unused = unused_bits;

    return ak_error_ok;
}


int ak_bitstr_get_str(bit_string* p_bit_str, char** pp_str)
{
    ak_uint32 i;
    ak_uint32 pos;
    ak_uint8  unused_bits;
    ak_int8   j;

    if(!p_bit_str || !pp_str)
        return ak_error_null_pointer;

    *pp_str = calloc(p_bit_str->m_val_len * 8, sizeof(char));
    if(!(*pp_str))
        return ak_error_out_of_memory;

    pos = 0;
    unused_bits = 0;
    for(i = 0; i < p_bit_str->m_val_len; i++)
    {
        if (i == p_bit_str->m_val_len - 1)
            unused_bits = p_bit_str->m_unused;

        for(j = 7; j >= (ak_int8)unused_bits; j--)
        {
            (*pp_str)[pos] = ((p_bit_str->mp_value[i] >> j) & 0x01) ? (char)'1' : (char)'0';
            pos++;
        }
    }

    return ak_error_ok;
}

int ak_bitstr_get_ui(bit_string* p_bit_str, ak_uint64* p_val64, ak_uint8* p_used_bits)
{
    if(!p_bit_str || !p_val64 || !p_used_bits)
        return ak_error_null_pointer;

    if(p_bit_str->m_val_len > sizeof(*p_val64))
        return ak_error_invalid_value;

    *p_val64 = 0;
    for(ak_int8 i = 0; i < p_bit_str->m_val_len; i++)
    {
        *p_val64 += p_bit_str->mp_value[i];
        if(i != p_bit_str->m_val_len - 1)
            *p_val64 = *p_val64 << 8;
    }

    if(p_bit_str->m_unused > 0)
    {
        *p_val64 = *p_val64 >> p_bit_str->m_unused;
        *p_used_bits = (ak_uint8) ((p_bit_str->m_val_len - 1) * 8 + (8 - p_bit_str->m_unused));
    }
    else
        *p_used_bits = (ak_uint8)(p_bit_str->m_val_len * 8);


    return ak_error_ok;
}

int ak_bitstr_get_arr(bit_string* p_bit_str, ak_byte** pp_data, ak_uint32* p_size, ak_uint8* p_unused_bits)
{
    if(!p_bit_str || !pp_data || !p_size || !p_unused_bits)
        return ak_error_null_pointer;

    *pp_data = malloc(p_bit_str->m_val_len);
    if(!(*pp_data))
        return ak_error_out_of_memory;

    memcpy(*pp_data, p_bit_str->mp_value, p_bit_str->m_val_len);
    *p_size = p_bit_str->m_val_len;
    *p_unused_bits = p_bit_str->m_unused;

    return ak_error_ok;
}

int ak_asn_get_oid_desc(object_identifier oid, char** pp_desc)
{
    int error;
    char* p_desc = NULL;
    ak_oid p_oid_obj;

    /* Получаем текущее значение кода ошибки */
    error = ak_error_get_value();

    p_oid_obj = ak_oid_context_find_by_id(oid);

    if(p_oid_obj)
    {
        p_desc = calloc(strlen(p_oid_obj->name) + 1, 1);
        if(!p_desc)
            return ak_error_out_of_memory;

        /* Копируем описание OID'а */
        strcat(p_desc, p_oid_obj->name);
    }
    else
    {
        /* В случае отсутствия искомого OID'а в библиотеке
         * значение текущего кода ошибки меняется на другое,
         * но мы его с чистой совестью возвращаем обратно */
        ak_error_set_value(error);
    }

    *pp_desc = p_desc;

    return  ak_error_ok;
}
