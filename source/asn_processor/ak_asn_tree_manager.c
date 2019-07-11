//
// Created by Anton Sakharov on 2019-07-07.
//

#include "ak_asn_codec_new.h"

// TODO: проверить необходимость в подключении файлов

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

#ifdef LIBAKRYPT_HAVE_STDIO_H
#include <stdio.h>
#else
#error Library cannot be compiled without stdio.h header
#endif

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


/*! \brief Массив, содержащий символьное представление тега. */
static char tag_description[20] = "\0";
/*! \brief Массив, содержащий префикс в выводимой строке с типом данных. */
static char prefix[1000] = "\0";

int ak_asn_create_constructed_tlv(ak_asn_tlv p_tlv, tag data_tag, bool_t free_mem)
{
    if(!(data_tag & CONSTRUCTED))
        return ak_error_message(ak_error_invalid_value, __func__, "data must be constructed");;

    /* Добавляем тег */
    p_tlv->m_tag = data_tag;

    /* Инициализируем переменные, хранящие информацию о длине */
    p_tlv->m_data_len = p_tlv->m_len_byte_cnt = 0;

    /* Выделяем память под составной объект и производим инициализацию */
    p_tlv->m_data.m_constructed_data = malloc(sizeof(s_constructed_data_t));
    if(!p_tlv->m_data.m_constructed_data)
        return ak_error_out_of_memory;

    p_tlv->m_data.m_constructed_data->m_arr_of_data = malloc(sizeof(s_asn_tlv_t) * 10);
    if(!p_tlv->m_data.m_constructed_data->m_arr_of_data)
    {
        free(p_tlv->m_data.m_constructed_data);
        return ak_error_out_of_memory;
    }

    p_tlv->m_data.m_constructed_data->m_alloc_size = 10;
    p_tlv->m_data.m_constructed_data->m_curr_size = 0;

    p_tlv->m_free_mem = free_mem;

    return ak_error_ok;
}

int ak_asn_create_primitive_tlv(ak_asn_tlv p_tlv, tag data_tag, size_t data_len, ak_pointer p_data, bool_t free_mem)
{
    if((data_tag & PRIMITIVE) != 0)
        return ak_error_message(ak_error_invalid_value, __func__, "data must be primitive");

    /* Добавляем тег */
    p_tlv->m_tag = data_tag;

    /* Добавляем длину, и кол-во байт, необходиоме для кодирования длины */
    p_tlv->m_data_len = (ak_uint32)data_len;
    p_tlv->m_len_byte_cnt = new_asn_get_len_byte_cnt(data_len);

    /* Добавляем данные */
    p_tlv->m_data.m_primitive_data = p_data;

    p_tlv->m_free_mem = free_mem;

    return ak_error_ok;
}

int ak_asn_add_nested_elem(ak_asn_tlv p_tlv_parent, ak_asn_tlv p_tlv_child)
{
    ak_uint8 index; /* Индекс элемента */
    if(!p_tlv_parent || !p_tlv_child)
        return ak_error_null_pointer;

    if(!(p_tlv_parent->m_tag & CONSTRUCTED))
        return ak_error_message(ak_error_invalid_value, __func__, "parent element must be constructed");

    if(p_tlv_parent->m_data.m_constructed_data->m_curr_size == p_tlv_parent->m_data.m_constructed_data->m_alloc_size)
    {
        ak_asn_tlv* pp_new_mem;
        ak_uint32  new_size;


        new_size = p_tlv_parent->m_data.m_constructed_data->m_curr_size + 10;
        if(new_size > 255)
            return ak_error_message(ak_error_out_of_memory, __func__, "change type for storing number of nested elements");

        pp_new_mem = malloc(new_size * sizeof(ak_asn_tlv));
        if(!pp_new_mem)
            return ak_error_out_of_memory;

        memcpy(pp_new_mem, p_tlv_parent->m_data.m_constructed_data->m_arr_of_data, p_tlv_parent->m_data.m_constructed_data->m_curr_size);

        p_tlv_parent->m_data.m_constructed_data->m_alloc_size = (ak_uint8)new_size;

        free(p_tlv_parent->m_data.m_constructed_data->m_arr_of_data);

        p_tlv_parent->m_data.m_constructed_data->m_arr_of_data = pp_new_mem;
    }

    index = p_tlv_parent->m_data.m_constructed_data->m_curr_size;
    p_tlv_parent->m_data.m_constructed_data->m_arr_of_data[index] = p_tlv_child;
    p_tlv_parent->m_data.m_constructed_data->m_curr_size++;
    p_tlv_parent->m_data_len += TAG_LEN + p_tlv_child->m_len_byte_cnt + p_tlv_child->m_data_len;
    p_tlv_parent->m_len_byte_cnt = new_asn_get_len_byte_cnt(p_tlv_parent->m_data_len);
    return ak_error_ok;
}

int ak_asn_get_size(ak_asn_tlv p_tlv, ak_uint32* p_size)
{
    if (!p_tlv || !p_size)
        return ak_error_null_pointer;

    /* Вычисляем кол-во памяти в байтах, необходимое для кодирования блока TLV */
    *p_size = TAG_LEN + p_tlv->m_len_byte_cnt + p_tlv->m_data_len;

    return ak_error_ok;
}

int ak_asn_update_size(ak_asn_tlv p_root_tlv)
{
    ak_uint32 size; /* Размер блока данных в TLV */

    if (!p_root_tlv)
        return ak_error_null_pointer;

    if(p_root_tlv->m_tag & CONSTRUCTED)
    {
        p_root_tlv->m_data_len = 0;
        for(ak_uint8 i = 0; i < p_root_tlv->m_data.m_constructed_data->m_curr_size; i++)
        {
            if(p_root_tlv->m_data.m_constructed_data->m_arr_of_data[i]->m_tag & CONSTRUCTED)
                ak_asn_update_size(p_root_tlv->m_data.m_constructed_data->m_arr_of_data[i]);

            ak_asn_get_size(p_root_tlv->m_data.m_constructed_data->m_arr_of_data[i], &size);

            p_root_tlv->m_data_len += size;
        }
        p_root_tlv->m_len_byte_cnt = new_asn_get_len_byte_cnt(p_root_tlv->m_data_len);

    }
    else
        return ak_error_message(ak_error_invalid_value, __func__, "root TLV must be constructed");

    return ak_error_ok;
}

static char* get_universal_tag_description(tag data_tag)
{
    /* tag_description - статическая переменная */

    switch(data_tag & 0x1F)
    {
    case TEOC :              sprintf(tag_description, "EOC"); break;
    case TBOOLEAN:           sprintf(tag_description, "BOOLEAN"); break;
    case TINTEGER:           sprintf(tag_description, "INTEGER"); break;
    case TBIT_STRING:        sprintf(tag_description, "BIT STRING"); break;
    case TOCTET_STRING:      sprintf(tag_description, "OCTET STRING"); break;
    case TNULL:              sprintf(tag_description, "NULL"); break;
    case TOBJECT_IDENTIFIER: sprintf(tag_description, "OBJECT IDENTIFIER"); break;
    case TOBJECT_DESCRIPTOR: sprintf(tag_description, "OBJECT DESCRIPTOR"); break;
    case TEXTERNAL:          sprintf(tag_description, "EXTERNAL"); break;
    case TREAL:              sprintf(tag_description, "REAL"); break;
    case TENUMERATED:        sprintf(tag_description, "ENUMERATED"); break;
    case TUTF8_STRING:       sprintf(tag_description, "UTF8 STRING"); break;
    case TSEQUENCE:          sprintf(tag_description, "SEQUENCE"); break;
    case TSET:               sprintf(tag_description, "SET"); break;
    case TNUMERIC_STRING:    sprintf(tag_description, "NUMERIC STRING"); break;
    case TPRINTABLE_STRING:  sprintf(tag_description, "PRINTABLE STRING"); break;
    case TT61_STRING:        sprintf(tag_description, "T61 STRING"); break;
    case TVIDEOTEX_STRING:   sprintf(tag_description, "VIDEOTEX STRING"); break;
    case TIA5_STRING:        sprintf(tag_description, "IA5 STRING"); break;
    case TUTCTIME:           sprintf(tag_description, "UTC TIME"); break;
    case TGENERALIZED_TIME:  sprintf(tag_description, "GENERALIZED TIME"); break;
    case TGRAPHIC_STRING:    sprintf(tag_description, "GRAPHIC STRING"); break;
    case TVISIBLE_STRING:    sprintf(tag_description, "VISIBLE STRING"); break;
    case TGENERAL_STRING:    sprintf(tag_description, "GENERAL STRING"); break;
    case TUNIVERSAL_STRING:  sprintf(tag_description, "UNIVERSAL STRING"); break;
    case TCHARACTER_STRING:  sprintf(tag_description, "CHARACTER STRING"); break;
    case TBMP_STRING:        sprintf(tag_description, "BMP STRING"); break;
    default:                 sprintf(tag_description, "UNKNOWN TYPE"); break;
    }

    return  tag_description;
}

static char* get_tag_description(tag data_tag)
{
    /* tag_description - статическая переменная */

    if((data_tag & 0xC0) == UNIVERSAL)
        return get_universal_tag_description(data_tag);
    else if(data_tag & CONTEXT_SPECIFIC)
    {
        /* Добавляем номер тега (младшие 5 бит) */
        sprintf(tag_description, "[%u]", data_tag & 0x1F);
        return tag_description;
    }
    else
        return NULL;
}

static void asn_print_universal_data(tag data_tag, ak_uint32 data_len, ak_byte* p_data)
{
    bit_string bit_string_data;
    char* str;
    ak_uint32 integer_val;

    if ((data_tag & UNIVERSAL) == 0)
    {
        switch (data_tag & 0x1F)
        {
        case TBOOLEAN:
            if(*p_data == 0x00)
                printf("False\n");
            else
                printf("True\n");
            break;
        case TINTEGER:
            //FIXME: переделать под вовод нормельного значения
//            ak_asn_print_hex_data(p_data, data_len);
//            putchar('\n');
            new_asn_get_int(p_data, data_len, &integer_val);
            printf("%u\n", integer_val);
            break;
        case TBIT_STRING:
            new_asn_get_bitstr(p_data, data_len, &bit_string_data);

            for(size_t i = 0; i < bit_string_data.m_val_len; i++)
            {
                ak_uint8 unused_bits = 0;
                if (i == bit_string_data.m_val_len - 1)
                    unused_bits = bit_string_data.m_unused;

                for(ak_int8 j = 7; j >= (ak_int8)unused_bits; j--)
                {
                    ak_uint8 bit = (bit_string_data.mp_value[i] >> j) & (ak_uint8)0x01;
                    printf("%u", bit);
                }
            }
            putchar('\n');
            free(bit_string_data.mp_value);
            break;
        case TOCTET_STRING:
            ak_asn_print_hex_data(p_data, data_len);
            putchar('\n');
            break;
        case TOBJECT_IDENTIFIER:
            new_asn_get_objid(p_data, data_len, &str);
            printf("%s\n", str);
            free(str);
            break;
        case TUTF8_STRING:
            // FIXME: Подправить, чтобы выводились произвольные символы, а не только символы ASCII
            new_asn_get_vsblstr(p_data, data_len, &str);
            printf("%s\n", str);
            free(str);
            break;
            break;
        case TGENERALIZED_TIME:
            new_asn_get_generalized_time(p_data, data_len, &str);
            printf("%s\n", str);
            free(str);
            break;
        case TVISIBLE_STRING:
            new_asn_get_vsblstr(p_data, data_len, &str);
            printf("%s\n", str);
            free(str);
            break;
        default: printf("bad data");
        }
    }

}

static void asn_print_last_elem(ak_asn_tlv p_last_elem, ak_uint32 level)
{
    if(p_last_elem->m_tag & CONSTRUCTED)
    {
        char* p_tag_desc;
        int tag_desc_len;
        p_tag_desc = get_tag_description(p_last_elem->m_tag);
        tag_desc_len = (int)strlen(p_tag_desc);

        /* Заменяем символ вертикальной черты на символ уголка '└' */
        sprintf(prefix + strlen(prefix) - 3, "%s", LB_CORNER);

        printf("%s%s%s\n", prefix,get_tag_description(p_last_elem->m_tag), RT_CORNER);

        /* Заменяем символ уголка '└' на пробел */
        prefix[strlen(prefix) - 3] = ' ';
        prefix[strlen(prefix) - 2] = '\0';

        /* Добавляем к префику вертикальную черту, сдвинутую на длину тега */
        sprintf(prefix + strlen(prefix), "%*s", tag_desc_len + 3, VER_LINE);

        /* Выводим вложенные данные */
        for(ak_uint8 i = 0; i < p_last_elem->m_data.m_constructed_data->m_curr_size; i++)
        {
            if(i == p_last_elem->m_data.m_constructed_data->m_curr_size - 1)
                asn_print_last_elem(p_last_elem->m_data.m_constructed_data->m_arr_of_data[i], level);
            else
                ak_asn_print_tree(p_last_elem->m_data.m_constructed_data->m_arr_of_data[i]);
        }
    }
    else
    {
        /* Заменяем символ вертикальной черты на символ уголка '└' */
        sprintf(prefix + strlen(prefix) - 3, "%s", LB_CORNER);

        /* Выводим префикс, горизонтальную черту и тега */
        printf("%s%s%s ", prefix, HOR_LINE, get_tag_description(p_last_elem->m_tag));
        /* Выводим данные */
        if((p_last_elem->m_tag & 0xC0) == UNIVERSAL)
            asn_print_universal_data(p_last_elem->m_tag, p_last_elem->m_data_len, p_last_elem->m_data.m_primitive_data);
        else if((p_last_elem->m_tag & 0xC0) == CONTEXT_SPECIFIC)
        {
            /* Выводим данные */
            ak_asn_print_hex_data(p_last_elem->m_data.m_primitive_data, p_last_elem->m_data_len);
            putchar('\n');
        }
        else
            printf("Unknown data\n");
    }
}

void ak_asn_print_tree(ak_asn_tlv p_tree)
{
    static ak_uint32 uiLevel = 0; /* Уровень вложенности элемента */

    if(p_tree->m_tag & CONSTRUCTED)
    {
        char* p_tag_desc;
        int tag_desc_len;
        p_tag_desc = get_tag_description(p_tree->m_tag);
        tag_desc_len = (int)strlen(p_tag_desc);

        /* Заменяем символ вертикальной черты на символ Т - образного уголка '├' */
        if(uiLevel != 0)
            sprintf(prefix + strlen(prefix) - 3, "%s", LTB_CORNERS);

        /* Выводим префик, тег, символ уголка '┐' */
        printf("%s%s%s\n", prefix,get_tag_description(p_tree->m_tag), RT_CORNER);

        /* Заменяем символ Т - образного уголка '├' на символ вертикальной черты */
        if(uiLevel != 0)
            sprintf(prefix + strlen(prefix) - 3, "%s", VER_LINE);

        /* Добавляем к префику вертикальную черту, сдвинутую на длину тега */
        sprintf(prefix + strlen(prefix), "%*s", tag_desc_len + 3, VER_LINE);

        /* Выводим вложенные данные */
        uiLevel++;
        for(ak_uint8 i = 0; i < p_tree->m_data.m_constructed_data->m_curr_size; i++)
        {
            if(i == p_tree->m_data.m_constructed_data->m_curr_size - 1)
                asn_print_last_elem(p_tree->m_data.m_constructed_data->m_arr_of_data[i], uiLevel);
            else
                ak_asn_print_tree(p_tree->m_data.m_constructed_data->m_arr_of_data[i]);
        }

        /* Отрезаем от префикса лишнее (поднимаемся на уровень выше) */
        uiLevel--;
        uint32_t curr_lvl = uiLevel;
        char* tmp = prefix;
        while(curr_lvl > 0)
        {
            tmp = strstr(tmp, VER_LINE);
            tmp += 3;
            curr_lvl--;
        }
        *(tmp) = 0;

//        printf("%*c%s%s\n", uiLevel * 2, ' ', get_tag_description(p_tree->m_tag), RT_CORNER);
//        printf("%*c\n", uiLevel * 2 + 1, '{');
//        uiLevel++;
//        for(ak_uint8 i = 0; i < p_tree->m_data.m_constructed_data->m_curr_size; i++)
//            ak_asn_print_tree(p_tree->m_data.m_constructed_data->m_arr_of_data[i]);
//        uiLevel--;
//        printf("%*c\n", uiLevel * 2 + 1, '}');
    }
    else
    {
        /* Заменяем символ вертикальной черты на символ Т - образного уголка '├' */
        if(uiLevel != 0)
            sprintf(prefix + strlen(prefix) - 3, "%s", LTB_CORNERS);

        /* Выводим префикс, горизонтальную линию, тег */
        printf("%s%s%s ", prefix, HOR_LINE, get_tag_description(p_tree->m_tag));

        if((p_tree->m_tag & 0xC0) == UNIVERSAL)
            asn_print_universal_data(p_tree->m_tag, p_tree->m_data_len, p_tree->m_data.m_primitive_data);
        else if((p_tree->m_tag & 0xC0) == CONTEXT_SPECIFIC)
        {
            /* Выводим данные */
            ak_asn_print_hex_data(p_tree->m_data.m_primitive_data, p_tree->m_data_len);
            putchar('\n');
        }
        else
            printf("Unknown data\n");

        /* Заменяем символ Т - образного уголка '├' на символ вертикальной черты */
        if(uiLevel != 0)
            sprintf(prefix + strlen(prefix) - 3, "%s", VER_LINE);

//        printf("%*c%s : (hex) ", uiLevel * 2, ' ', get_tag_description(p_tree->m_tag));
//        for(ak_uint32 i = 0; i < p_tree->m_data_len; i++)
//        {
//            printf("%02X", p_tree->m_data.m_primitive_data[i]);
//        }
//        putchar('\n');
    }
}

void ak_asn_print_hex_data(ak_byte* p_data, ak_uint32 size)
{
    ak_uint32 i; /* индекс */
    for (i = 0; i < size; i++)
    {
        printf("%02X ", p_data[i]);
    }
}
