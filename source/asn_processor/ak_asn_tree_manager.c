//
// Created by Anton Sakharov on 2019-07-07.
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

/*! \brief Макрос для подсчета кол-ва байтов, которыми кодируется символ юникода */
#define UNICODE_SYMBOL_LEN(x) strlen(x)


/*! \brief Массив, содержащий символьное представление тега. */
static char tag_description[20] = "\0";
/*! \brief Массив, содержащий префикс в выводимой строке с типом данных. */
static char prefix[1000] = "\0";

#define SET_TEXT_COLOR_DEFAULT  printf("\x1b[0m")
#define SET_TEXT_COLOR_RED      printf("\x1b[31m")
#define SET_TEXT_COLOR_BLUE     printf("\x1b[34m")

static int ak_asn_create_constructed_tlv(ak_asn_tlv p_tlv, tag data_tag)
{
    if(DATA_STRUCTURE(data_tag) != CONSTRUCTED)
        return ak_error_message(ak_error_invalid_value, __func__, "data must be constructed");;

    /* Добавляем тег */
    p_tlv->m_tag = data_tag;

    /* Инициализируем переменные, хранящие информацию о длине */
    p_tlv->m_data_len = p_tlv->m_len_byte_cnt = 0;

    /* Выделяем память под составной объект и производим инициализацию */
    p_tlv->m_data.m_constructed_data = malloc(sizeof(s_constructed_data_t));
    if(!p_tlv->m_data.m_constructed_data)
        return ak_error_out_of_memory;

    p_tlv->m_data.m_constructed_data->mp_arr_of_data = malloc(sizeof(s_asn_tlv_t) * 10);
    if(!p_tlv->m_data.m_constructed_data->mp_arr_of_data)
    {
        free(p_tlv->m_data.m_constructed_data);
        return ak_error_out_of_memory;
    }

    memset(p_tlv->m_data.m_constructed_data->mp_arr_of_data, 0, sizeof(s_asn_tlv_t) * 10);
    p_tlv->m_data.m_constructed_data->m_alloc_size = 10;
    p_tlv->m_data.m_constructed_data->m_curr_size = 0;

    p_tlv->m_free_mem = ak_false;

    p_tlv->p_name = NULL;

    return ak_error_ok;
}

static int ak_asn_create_primitive_tlv(ak_asn_tlv p_tlv, tag data_tag, size_t data_len, ak_pointer p_data, bool_t free_mem)
{
    if(DATA_STRUCTURE(data_tag) != PRIMITIVE)
        return ak_error_message(ak_error_invalid_value, __func__, "data must be primitive");

    /* Добавляем тег */
    p_tlv->m_tag = data_tag;

    /* Добавляем длину, и кол-во байт, необходиоме для кодирования длины */
    if(data_len)
    {
        p_tlv->m_data_len = (ak_uint32) data_len;
        p_tlv->m_len_byte_cnt = new_asn_get_len_byte_cnt(data_len);
    }

    /* Добавляем данные */
    if(free_mem && p_data)
    {
        p_tlv->m_data.m_primitive_data = malloc(data_len * sizeof(ak_byte));
        if(!p_tlv->m_data.m_primitive_data)
            return ak_error_out_of_memory;

        memcpy(p_tlv->m_data.m_primitive_data, p_data, data_len);
    }
    else
        p_tlv->m_data.m_primitive_data = p_data;

    p_tlv->m_free_mem = free_mem;

    p_tlv->p_name = NULL;

    return ak_error_ok;
}

int ak_asn_construct_data_ctx_create(ak_asn_tlv p_tlv, tag constructed_data_tag, char* p_data_name)
{
    int error; /* Код ошибки */

    if(!p_tlv)
        return ak_error_null_pointer;

    if(DATA_STRUCTURE(constructed_data_tag) == CONSTRUCTED)
    {
        if((error = ak_asn_create_constructed_tlv(p_tlv, constructed_data_tag)) != ak_error_ok)
            return ak_error_message(error, __func__, "failure to create constructed tlv");

        if(p_data_name)
        {
            size_t len = strlen(p_data_name) + 1;
            p_tlv->p_name = malloc(len);
            memcpy(p_tlv->p_name, p_data_name, len);
        }
    }
    else
        return ak_error_message(ak_error_invalid_value, __func__, "tag must specify constructed data");

    return ak_error_ok;
}


int ak_asn_primitive_data_ctx_create(ak_asn_tlv p_tlv, tag data_tag, ak_uint32 data_len, ak_pointer p_data, char* p_data_name)
{
    int error; /* Код ошибки */

    /* Передача p_data == NULL разрешена, чтобы можно было создать пустой контекст и заполнить его позже */
    if(!p_tlv)
        return ak_error_null_pointer;

    if(DATA_STRUCTURE(data_tag) == PRIMITIVE)
    {
        if((error = ak_asn_create_primitive_tlv(p_tlv, data_tag, data_len, p_data, ak_true)) != ak_error_ok)
            return ak_error_message(error, __func__, "failure to create primitive tlv");

        if(p_data_name)
        {
            size_t len = strlen(p_data_name) + 1;
            p_tlv->p_name = malloc(len);
            memcpy(p_tlv->p_name, p_data_name, len);
        }
    }
    else
        return ak_error_message(ak_error_invalid_value, __func__, "tag must specify primitive data");

    return ak_error_ok;
}

int ak_asn_add_nested_elems(ak_asn_tlv p_tlv_parent, s_asn_tlv_t p_tlv_children[], ak_uint8 count)
{
    ak_uint8 index; /* Индекс элемента */
    ak_uint8 curr_size; /* Текущее кол-во элементов в массиве */
    ak_uint32  new_size;

    if(!p_tlv_parent || !p_tlv_children)
        return ak_error_null_pointer;

    if(DATA_STRUCTURE(p_tlv_parent->m_tag) != CONSTRUCTED)
        return ak_error_message(ak_error_invalid_value, __func__, "parent element must be constructed");

    if(!count)
        return ak_error_message(ak_error_invalid_value, __func__, "children count equal to zero");

    curr_size = p_tlv_parent->m_data.m_constructed_data->m_curr_size;
    new_size = curr_size;
    while(curr_size + count > p_tlv_parent->m_data.m_constructed_data->m_alloc_size)
    {
        new_size += count + 10;
        if(new_size > 255) /* Проверка, чтобы не переполнить тип ak_uint8 */
            return ak_error_message(ak_error_out_of_memory, __func__, "change type for storing number of nested elements");


        p_tlv_parent->m_data.m_constructed_data->mp_arr_of_data = realloc(p_tlv_parent->m_data.m_constructed_data->mp_arr_of_data, new_size * sizeof(s_asn_tlv_t));
        if(!p_tlv_parent->m_data.m_constructed_data->mp_arr_of_data)
            return ak_error_out_of_memory;

        //ak_asn_realloc((ak_pointer*)&p_tlv_parent->m_data.m_constructed_data->mp_arr_of_data, curr_size * sizeof(s_asn_tlv_t), new_size * sizeof(s_asn_tlv_t));

        p_tlv_parent->m_data.m_constructed_data->m_alloc_size = (ak_uint8)new_size;
    }

    for(index = 0; index < count; index++)
    {
        p_tlv_parent->m_data.m_constructed_data->mp_arr_of_data[curr_size + index] = p_tlv_children[index];
        p_tlv_parent->m_data_len += TAG_LEN + p_tlv_children[index].m_len_byte_cnt + p_tlv_children[index].m_data_len;
    }

    p_tlv_parent->m_data.m_constructed_data->m_curr_size += count;
    p_tlv_parent->m_len_byte_cnt = new_asn_get_len_byte_cnt(p_tlv_parent->m_data_len);

    return ak_error_ok;
}

int ak_asn_delete_nested_elem(ak_asn_tlv p_tlv_parent, ak_uint32 index)
{
    ak_uint32 child_size; /* Рамзер дочернего элемента */

    if(!p_tlv_parent)
        return ak_error_null_pointer;

    if(DATA_STRUCTURE(p_tlv_parent->m_tag) != CONSTRUCTED)
        return ak_error_message(ak_error_invalid_value, __func__, "parent element must be constructed");

    if(index + 1 > p_tlv_parent->m_data.m_constructed_data->m_curr_size)
        return ak_error_message(ak_error_invalid_value, __func__, "bad index");

    /* Вычисляем размер дочернего элемента */
    ak_asn_get_size(&p_tlv_parent->m_data.m_constructed_data->mp_arr_of_data[index], &child_size);

    /* Уменьшаем размер родительского элемента */
    p_tlv_parent->m_data_len -= child_size;
    p_tlv_parent->m_len_byte_cnt = new_asn_get_len_byte_cnt(p_tlv_parent->m_data_len);

    /* Удаляем дочерний элемент */
    ak_asn_free_tree(&p_tlv_parent->m_data.m_constructed_data->mp_arr_of_data[index]);
    //p_tlv_parent->m_data.m_constructed_data->mp_arr_of_data[index] = NULL;

    /* Сдвигаем все элементы в массиве, которы находятся за удаляемым */
    if((index + 1) < p_tlv_parent->m_data.m_constructed_data->m_curr_size)
    {
        ak_uint32 j;
        for (j = index + 1; j < p_tlv_parent->m_data.m_constructed_data->m_curr_size; j++)
            p_tlv_parent->m_data.m_constructed_data->mp_arr_of_data[j - 1] = p_tlv_parent->m_data.m_constructed_data->mp_arr_of_data[j];

        /* Зануляем копию адреса последнего элемента, которая образовалась в процессе смещения объектов */
        //p_tlv_parent->m_data.m_constructed_data->mp_arr_of_data[j - 1] = NULL;
        p_tlv_parent->m_data.m_constructed_data->m_curr_size--;
    }

    return ak_error_ok;
}

void ak_asn_free_tree(ak_asn_tlv p_tlv_root)
{
    if(p_tlv_root)
    {
        if(DATA_STRUCTURE(p_tlv_root->m_tag) == CONSTRUCTED)
        {
            ak_uint32 index;
            for(index = 0; index < p_tlv_root->m_data.m_constructed_data->m_curr_size; index++)
            {
                ak_asn_free_tree(&p_tlv_root->m_data.m_constructed_data->mp_arr_of_data[index]);
            }

            free(p_tlv_root->m_data.m_constructed_data->mp_arr_of_data);
        }
        else
        {
            /* Очищаем данные, если объект ими владеет */
            if(p_tlv_root->m_free_mem && p_tlv_root->m_data.m_primitive_data)
                free(p_tlv_root->m_data.m_primitive_data);
        }

        /* Очищаем название данных, если оно указано */
        if(p_tlv_root->p_name)
            free(p_tlv_root->p_name);

        /* Очищаем структуру для хранения данных */
        //free(p_tlv_root);
    }
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
    ak_uint8 i = 0;
    ak_uint32 size = 0; /* Размер блока данных в TLV */

    if (!p_root_tlv)
        return ak_error_null_pointer;

    if(DATA_STRUCTURE(p_root_tlv->m_tag) == CONSTRUCTED)
    {
        p_root_tlv->m_data_len = 0;
        for( i = 0; i < p_root_tlv->m_data.m_constructed_data->m_curr_size; i++)
        {
            if(DATA_STRUCTURE(p_root_tlv->m_data.m_constructed_data->mp_arr_of_data[i].m_tag) == CONSTRUCTED)
                ak_asn_update_size(&p_root_tlv->m_data.m_constructed_data->mp_arr_of_data[i]);

            ak_asn_get_size(&p_root_tlv->m_data.m_constructed_data->mp_arr_of_data[i], &size);

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

    if(DATA_CLASS(data_tag) == UNIVERSAL)
        return get_universal_tag_description(data_tag);
    else if(DATA_CLASS(data_tag) == CONTEXT_SPECIFIC)
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
    size_t i = 0;
    bit_string bit_string_data;
    char *str, *oid;
    ak_uint32 integer_val;

    if (DATA_CLASS(data_tag) == UNIVERSAL)
    {
        switch (TAG_NUMBER(data_tag))
        {
        case TBOOLEAN:
            if(*p_data == 0x00)
                printf("False\n");
            else
                printf("True\n");
            break;
        case TINTEGER:
            new_asn_get_int(p_data, data_len, &integer_val);
            printf("%u\n", integer_val);
            break;
        case TBIT_STRING:
            new_asn_get_bitstr(p_data, data_len, &bit_string_data);

            for( i = 0; i < bit_string_data.m_val_len; i++)
            {
                ak_int8 j = 0;
                ak_uint8 unused_bits = 0;
                if (i == bit_string_data.m_val_len - 1)
                    unused_bits = bit_string_data.m_unused;

                for( j = 7; j >= (ak_int8)unused_bits; j--)
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
            new_asn_get_objid(p_data, data_len, &oid);
            printf("%s", oid);

            ak_asn_get_oid_desc(oid, &str);
            if(str)
            {
                printf(" (%s)", str);
                free(str);
            }

            putchar('\n');

            free(oid);
            break;
        case TUTF8_STRING:
            new_asn_get_utf8string(p_data, data_len, (unsigned char**)&str);
            printf("%s\n", str);
            free(str);
            break;
        case TGENERALIZED_TIME:
            new_asn_get_generalized_time(p_data, data_len, &str);
            printf("%s\n", str);
            free(str);
            break;
        case TUTCTIME:
            new_asn_get_utc_time(p_data, data_len, &str);
            printf("%s\n", str);
            free(str);
            break;
        case TVISIBLE_STRING:
            new_asn_get_vsblstr(p_data, data_len, &str);
            printf("%s\n", str);
            free(str);
            break;
        case TIA5_STRING:
            new_asn_get_ia5string(p_data, data_len, &str);
            printf("%s\n", str);
            free(str);
            break;
        case TPRINTABLE_STRING:
            new_asn_get_printable_string(p_data, data_len, &str);
            printf("%s\n", str);
            free(str);
            break;
        case TNUMERIC_STRING:
            new_asn_get_numeric_string(p_data, data_len, &str);
            printf("%s\n", str);
            free(str);
            break;
        default:
            SET_TEXT_COLOR_RED;
            printf("Unknown data! ");
            ak_asn_print_hex_data(p_data, data_len);
            putchar('\n');
            SET_TEXT_COLOR_DEFAULT;
        }
    }

}

static void new_ak_asn_print_tlv(ak_asn_tlv p_tlv, bool_t is_last)
{
    size_t p_curr_prefix_len;
    char* p_tag_desc;
    int tag_desc_len;
    p_tag_desc = get_tag_description(p_tlv->m_tag);
    tag_desc_len = (int)strlen(p_tag_desc);

    /* Если данный TLV является последним элементом, то заменяем вертикальную
     * черту в префиксе на символ '└', а иначе на символ '├' */
    if(is_last)
        sprintf(prefix + strlen(prefix) - UNICODE_SYMBOL_LEN(VER_LINE), "%s", LB_CORNER);
    else
        sprintf(prefix + strlen(prefix) - UNICODE_SYMBOL_LEN(VER_LINE), "%s", LTB_CORNERS);


    if(DATA_STRUCTURE(p_tlv->m_tag) == CONSTRUCTED)
    {
        ak_uint8 i = 0;
        size_t suffix_len = strlen(p_tag_desc) + UNICODE_SYMBOL_LEN(VER_LINE);
        /* Выводим префик, тег */
        printf("%s%s", prefix, p_tag_desc);

        if(p_tlv->p_name)
        {
            /* Выводим название TLV */
            SET_TEXT_COLOR_BLUE;
            printf(" (%s) ", p_tlv->p_name);
            SET_TEXT_COLOR_DEFAULT;
            suffix_len += strlen(p_tlv->p_name) + 4;
        }

        /* Выводим символ уголка '┐' */
        printf("%s\n", RT_CORNER);

        /* Запоминаем длину тега на данном уровне вложенности TLV */
        p_curr_prefix_len = strlen(prefix);

        /* Если данный TLV является последним элементом, то заменяем последний символ в префиксе
         * на символ пробела, а иначе на символ вертикальной черты */
        if(is_last == ak_true)
        {
            prefix[strlen(prefix) - UNICODE_SYMBOL_LEN(VER_LINE)] = ' ';
            prefix[strlen(prefix) - UNICODE_SYMBOL_LEN(VER_LINE) + 1] = '\0';
        }
        else
            sprintf(prefix + strlen(prefix) - UNICODE_SYMBOL_LEN(VER_LINE), "%s", VER_LINE);

        /* Добавляем к префику вертикальную черту, сдвинутую на длину тега */
        sprintf(prefix + strlen(prefix), "%*s", (int)suffix_len, VER_LINE);

        /* Выводим вложенные данные */
        for( i = 0; i < p_tlv->m_data.m_constructed_data->m_curr_size; i++)
        {
            if(i == p_tlv->m_data.m_constructed_data->m_curr_size - 1)
                new_ak_asn_print_tlv(&p_tlv->m_data.m_constructed_data->mp_arr_of_data[i], ak_true);
            else
                new_ak_asn_print_tlv(&p_tlv->m_data.m_constructed_data->mp_arr_of_data[i], ak_false);
        }

        /* Отрезаем от префикса лишнее (поднимаемся на уровень выше) */
        prefix[p_curr_prefix_len] = 0;
    }
    else
    {
        /* Выводим префикс, тег */
        printf("%s%s ", prefix, get_tag_description(p_tlv->m_tag));

        if(p_tlv->p_name)
        {
            SET_TEXT_COLOR_BLUE;
            printf("(%s) ", p_tlv->p_name);
            SET_TEXT_COLOR_DEFAULT;
        }

        /* Заменям последний символ в префиксе на символ вертикальной черты */
        sprintf(prefix + strlen(prefix) - UNICODE_SYMBOL_LEN(VER_LINE), "%s", VER_LINE);

        /* Выводим значение данных */
        if(DATA_CLASS(p_tlv->m_tag) == UNIVERSAL)
            asn_print_universal_data(p_tlv->m_tag, p_tlv->m_data_len, p_tlv->m_data.m_primitive_data);
        else if(DATA_CLASS(p_tlv->m_tag) == CONTEXT_SPECIFIC)
        {
            ak_asn_print_hex_data(p_tlv->m_data.m_primitive_data, p_tlv->m_data_len);
            putchar('\n');
        }
        else
        {
            SET_TEXT_COLOR_RED;
            puts("Unknown data!");
            SET_TEXT_COLOR_DEFAULT;
        }
    }
}

void new_ak_asn_print_tree(ak_asn_tlv p_tree)
{
    new_ak_asn_print_tlv(p_tree, ak_false);
}

void ak_asn_print_hex_data(ak_byte* p_data, ak_uint32 size)
{
    ak_uint32 i; /* индекс */
    for (i = 0; i < size; i++) printf("%02X", p_data[i]);
}

int ak_asn_parse_data(ak_pointer p_asn_data, size_t size, ak_asn_tlv* pp_tlv)
{
    ak_byte* p_curr;   /* Указатель на текущую позицию */
    ak_byte* p_end;    /* Указатель на конец tlv */
    tag      data_tag; /* Тег данных */
    size_t   data_len; /* Длина данных */
    int error;         /* Код ошибки */

    if(!p_asn_data || !size || !pp_tlv)
        return ak_error_null_pointer;

    *pp_tlv = malloc(sizeof(s_asn_tlv_t));
    if (!(*pp_tlv))
        return ak_error_out_of_memory;

    p_curr = p_asn_data;
    p_end = (ak_byte*)p_asn_data + size;

    new_asn_get_tag(&p_curr, &data_tag);
    if(DATA_STRUCTURE(data_tag) == CONSTRUCTED)
    {
        ak_uint32  index;        /* Индекс дочернего элемента */
        ak_asn_tlv p_nested_tlv; /* Дочерний элемент */
        ak_uint32  child_size;   /* Размер дочернего элемента */

        if ((error = ak_asn_create_constructed_tlv(*pp_tlv, data_tag)) != ak_error_ok)
            return ak_error_message(error, __func__, "failure to create constructed context");

        new_asn_get_len(&p_curr, &data_len);

        index = 0;
        while((*pp_tlv)->m_data_len < data_len)
        {
            ak_asn_parse_data(p_curr, data_len, &p_nested_tlv);
            ak_asn_add_nested_elems(*pp_tlv, p_nested_tlv, 1);
            ak_asn_get_size(p_nested_tlv, &child_size);
            p_curr += child_size;
            index++;
        }
//        pp_tlv->m_data.m_constructed_data->mp_arr_of_data[0] = p_nested_tlv;
//        pp_tlv->m_data.m_constructed_data->m_curr_size++;
    }
    else
    {
        new_asn_get_len(&p_curr, &data_len);
        if(p_curr + data_len > p_end)
            return ak_error_message(ak_error_wrong_length, __func__, "wrong data length");

        if((error = ak_asn_create_primitive_tlv(*pp_tlv, data_tag, data_len, p_curr, ak_false)) != ak_error_ok)
            return ak_error_message(error, __func__, "can not create primitive tlv");
    }

    return ak_error_ok;
}

static int ak_asn_encode_tlv(ak_asn_tlv p_tlv, ak_byte** pp_pos, ak_byte* p_end)
{
    int error;      /* Код ошибки */
    ak_uint32 size; /* Размер кодируемых данных */

    if(!pp_pos || !p_end || !p_tlv)
        return ak_error_null_pointer;

    /* Вычисляем длину кодируемых в данный момент данных,
     * чтобы проверить выход за границы выделенной памяти */
    ak_asn_get_size(p_tlv, &size);
    if((*pp_pos + size) > p_end)
        return ak_error_message(ak_error_out_of_memory, __func__, "need more memory for encoding");

    if(DATA_STRUCTURE(p_tlv->m_tag) == CONSTRUCTED) /* Кодирование составных данных */
    {
        ak_uint8 index; /* Индекс элемента в массиве элементов составного объекта */

        if((error = new_asn_put_tag(p_tlv->m_tag, pp_pos)) != ak_error_ok)
            return ak_error_message(error, __func__, "failure in adding tag");

        if((error = new_asn_put_len(p_tlv->m_data_len, p_tlv->m_len_byte_cnt, pp_pos)) != ak_error_ok)
            return ak_error_message(error, __func__, "failure in adding data length");

        for(index = 0; index < p_tlv->m_data.m_constructed_data->m_curr_size; index++)
        {
            if((error = ak_asn_encode_tlv(&p_tlv->m_data.m_constructed_data->mp_arr_of_data[index], pp_pos, p_end)) != ak_error_ok)
                return error; /* Никакого сообщения не выводится, иначе выведется много одинаковых строчек (из-за рекурсии) */
        }
    }
    else /* Кодирование примитивных данных */
    {
        new_asn_put_tag(p_tlv->m_tag, pp_pos);
        new_asn_put_len(p_tlv->m_data_len, p_tlv->m_len_byte_cnt, pp_pos);
        memcpy(*pp_pos, p_tlv->m_data.m_primitive_data, p_tlv->m_data_len);
        (*pp_pos) +=  p_tlv->m_data_len;
    }

    return ak_error_ok;
}

int ak_asn_build_data(ak_asn_tlv p_tlv, ak_byte** pp_asn_data, ak_uint32* p_size)
{
    int error; /* Код ошибки */
    ak_byte* p_curr_pos; /* Указатель на текущую позицию в буфере с ASN.1 данными */

    if(!pp_asn_data || !p_size || !p_tlv)
        return ak_error_null_pointer;

    /* Пересчитываем длины, чтобы защититься от нежелательных ошибок */
    if((error = ak_asn_update_size(p_tlv)) != ak_error_ok)
        return ak_error_message(error, __func__, "failure in recalculating size");

    /* Вычисляем объем памяти, необходимый для кодирования данных */
    if((error = ak_asn_get_size(p_tlv, p_size)) != ak_error_ok)
        return ak_error_message(error, __func__, "failure in getting size");

    /* Выделяем память */
    *pp_asn_data = p_curr_pos = (ak_byte*)malloc(*p_size);
    if(!p_curr_pos)
    {
        *p_size = 0;
        return ak_error_out_of_memory;
    }

    /* Кодируем данные */
    if((error = ak_asn_encode_tlv(p_tlv, &p_curr_pos, p_curr_pos + (*p_size))) != ak_error_ok)
        return ak_error_message(error, __func__, "failure in encoding ASN.1 data");

    return ak_error_ok;
}

int ak_asn_realloc(ak_pointer* pp_mem, size_t old_size, size_t new_size)
{
    ak_pointer p_new_mem;

    if(!pp_mem)
        return ak_error_wrong_length;

    if(!(*pp_mem) || (new_size <= old_size))
        return ak_error_invalid_value;

    p_new_mem = malloc(new_size * sizeof(ak_asn_tlv));
    if(!p_new_mem)
        return ak_error_out_of_memory;

    memcpy(p_new_mem, *pp_mem, old_size);

    free(*pp_mem);

    *pp_mem = p_new_mem;

    return ak_error_ok;
}

