//
// Created by gerg on 2019-05-15.
//

#include <kc_tools.h>
#include "kc_tools.h"
#include <wchar.h>
#include <ak_skey.h>
#include <kc_libakrypt.h>
#include <ak_context_manager.h>


int parse_to_boolean(boolean* p_asn_1_bool, bool val) {

    if(!p_asn_1_bool)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    *p_asn_1_bool = val;

    return ak_error_ok;
}

int parse_to_utf8_string(utf8_string* p_asn_1_utf8_string, ak_pointer p_val) {

    uint32_t size;

    if(!p_asn_1_utf8_string || !p_val)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    //FIXME работает только для asсii символов
    size = strlen((char*) p_val);

    *p_asn_1_utf8_string = calloc(size + 1, sizeof(char));

    strcpy((char*) *p_asn_1_utf8_string, (char*) p_val);

    return ak_error_ok;

//    uint32_t byte_counter = 0;

//    for (uint32_t i = 0; i < size; ++i) {
//        if (p_val[i] != 0x00) {
//            byte_counter++;
//        }
//    }
//
//    *p_asn_1_utf8_string = (utf8_string) malloc(byte_counter + 1);
//
//    for (uint32_t i =0; i < byte_counter; ++i) {
//        if (p_val[i] != 0x00) {
//            (*p_asn_1_utf8_string)[i] = p_val[i];
//        }
//    }
//
//    (*p_asn_1_utf8_string)[byte_counter] = '\0';
}

int parse_to_visible_string(visible_string* p_asn_1_visible_string, const char* p_val) {

    if(!p_asn_1_visible_string || !p_val)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    *p_asn_1_visible_string = (visible_string) malloc(strlen(p_val) + 1);
    strcpy(*p_asn_1_visible_string, p_val);

    return ak_error_ok;
}

int parse_to_generalized_time(generalized_time* p_asn_1_generalized_time, const char* p_val) {

    if(!p_asn_1_generalized_time || !p_val)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    *p_asn_1_generalized_time = (generalized_time) malloc(strlen(p_val) + 1);
    strcpy(*p_asn_1_generalized_time, p_val);

    return ak_error_ok;
}

int parse_to_object_identifier(object_identifier* p_asn_1_object_identifier, const char* p_val) {

    if(!p_asn_1_object_identifier || !p_val)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    *p_asn_1_object_identifier = (object_identifier) malloc(strlen(p_val) + 1);
    strcpy(*p_asn_1_object_identifier, p_val);

    return ak_error_ok;
}

int parse_to_integer(integer* p_asn_int, int32_t val) {

    if(!p_asn_int)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    p_asn_int->m_positive = (val >= 0);
    int32_t val_len = p_asn_int->m_val_len = sizeof(val);

    if(val == 0 || val == -1)
    {
        p_asn_int->mp_value = malloc(sizeof(byte));
        *p_asn_int->mp_value = val;
        p_asn_int->m_val_len = 1;
        return ak_error_ok;
    }


    if(p_asn_int->m_positive)
    {
        int8_t i = sizeof(val) - 1;
        while (!((val >> (i * 8u)) & 0xFF) && (i >= 0))
        {
            val_len = p_asn_int->m_val_len -= 1;
            i -= 1;
        }
    }
    else
    {
        // todo допилить реализацию добавления отрицательного числа
        //int8_t i = sizeof(val) - 1;
        while ((((val >> ((val_len - 1) * 8u)) & 0xFF) == 0xFF) && (val_len - 1 >= 0))
        {
            val_len = p_asn_int->m_val_len -= 1;
            //i -= 1;
        }
    }

    byte *p_val = p_asn_int->mp_value = (byte *) malloc(val_len);

    if (val_len == 1)
        *p_val = (byte) val;
    else
    {
        while (--val_len >= 0)
            *(p_val++) = (byte) ((val >> (8u * val_len)) & 0xFFu);
    }

    return ak_error_ok;
}

int parse_to_bit_string(bit_string* p_asn_1_bit_string, const byte* p_val, uint32_t size, uint8_t num_of_unused_bits) {

    if(!p_asn_1_bit_string || !p_val || (size <= 0) || (num_of_unused_bits <= 0))
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    p_asn_1_bit_string->mp_value = (byte*) malloc(size);
    p_asn_1_bit_string->m_val_len = size;
    p_asn_1_bit_string->m_unused = num_of_unused_bits;

    memcpy(p_asn_1_bit_string->mp_value, p_val, size);

    return ak_error_ok;
}

int parse_to_octet_string(octet_string* p_asn_1_octet_string, const byte* p_val, uint32_t size) {

    if(!p_asn_1_octet_string || !p_val || (size <= 0))
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    p_asn_1_octet_string->mp_value = (byte*) malloc(size);
    p_asn_1_octet_string->m_val_len = size;

    memcpy(p_asn_1_octet_string->mp_value, p_val, size);

    return ak_error_ok;
}

int asn_integer_to_int64(integer* p_asn_val, ak_int64* p_value)
{

    size_t i;

    if(!p_asn_val || !p_value)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    if(p_asn_val->m_val_len > sizeof(ak_int64) || (p_asn_val->m_positive && (p_asn_val->mp_value[0] & 0x80)))
        return ak_error_invalid_value;

    *p_value = 0;
    for(i = 0; i < p_asn_val->m_val_len; i++)
    {
        *p_value ^= p_asn_val->mp_value[i];
        if(i != p_asn_val->m_val_len - 1)
            *p_value = (*p_value) << 8;
    }

    return ak_error_ok;
}

int asn_utf8_to_byte_arr(utf8_string* p_src, byte** pp_dst)
{
    size_t str_size;

    if(!p_src)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    str_size = strlen((char*)p_src) + 1;
    *pp_dst = malloc(str_size);
    if(!*pp_dst)
        return ak_error_null_pointer;

    memcpy(*pp_dst, p_src, str_size);

    return ak_error_ok;
}

int asn_generalized_time_to_date(generalized_time time, date date)
{
    //TODO проверка??

    char* p_next_num;

    /* year */
    date[0] = (unsigned int)strtoul(time,       &p_next_num, 10);
    /* month */
    date[1] = (unsigned int)strtoul(p_next_num + 1, &p_next_num, 10);
    /* day */
    date[2] = (unsigned int)strtoul(p_next_num + 1, &p_next_num, 10);
    /* hours */
    date[3] = (unsigned int)strtoul(p_next_num + 1, &p_next_num, 10);
    /* minutes */
    date[4] = (unsigned int)strtoul(p_next_num + 1, &p_next_num, 10);
    /* seconds */
    date[5] = (unsigned int)strtoul(p_next_num + 1, &p_next_num, 10);

    return ak_error_ok;
}

int set_usage_flags(bit_string asn_val, key_usage_flags_t* flags)
{
    if(asn_val.m_val_len > 2)
        return ak_error_invalid_value;

    *flags = 0;
    *flags ^= asn_val.mp_value[0];
    *flags = *flags << 8;

    if(asn_val.m_val_len == 2)
        *flags ^= asn_val.mp_value[1];

    return ak_error_ok;
}

int set_key_id(octet_string id, ak_skey p_key)
{

    //TODO проверка??


    // Если под хранение идентификатора недостаточно памяти, то перевыделяем ее
    if(p_key->number.size < id.m_val_len)
    {
        p_key->number.free(&p_key->number);
        p_key->number.alloc(id.m_val_len);
        if(!p_key->number.data)
            return ak_error_null_pointer;
    }
    memcpy(p_key->number.data,id.mp_value, id.m_val_len);
    p_key->number.size = id.m_val_len;

    return ak_error_ok;
}

int parse_date_to_generalized_time(date current_date, generalized_time* result) {

    //TODO проверка??

    generalized_time date_time = (generalized_time)malloc(strlen("YYYY-MM-DD HH:MM:SS UTC") + 1);

    // Корректные значения года: диапазон от 1970 до 9999
    if (current_date[0] < 1970 || current_date[0] > 9999) {
        return ak_error_invalid_value;
    }

    // Корректные значения месяца: диапазон от 1 до 12
    if (current_date[1] < 1 || current_date[1] > 12) {
        return ak_error_invalid_value;
    }

    // Корректные значения дня: диапазон от 1 до 31
    if (current_date[2] < 1 || current_date[2] > 31) {
        return ak_error_invalid_value;
    }

    // Корректные значения часа: диапазон от 0 до 23
    if (current_date[3] < 0 || current_date[3] > 23) {
        return ak_error_invalid_value;
    }

    // Корректные значения минуты: диапазон от 0 до 59
    if (current_date[4] < 0 || current_date[4] > 59) {
        return ak_error_invalid_value;
    }

    // Корректные значения секунды: диапазон от 0 до 59
    if (current_date[5] < 0 || current_date[5] > 59) {
        return ak_error_invalid_value;
    }


    sprintf(date_time, "%d-%02d-%02d %02d:%02d:%02d UTC",
            current_date[0], current_date[1], current_date[2],
            current_date[3], current_date[4], current_date[5]);


    *result = date_time;

    return ak_error_ok;
}


int generate_random_bytes(octet_string *p_data, const size_t size) {
    int error;

    if(!p_data || (size <= 0))
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    ak_context_manager p_context = ak_libakrypt_get_context_manager();

    p_data->mp_value = malloc(size* sizeof(p_data->mp_value));
    p_data->m_val_len = size;

    if (!p_data->mp_value) {
        return ak_error_null_pointer;
    }

    //TODO добавлять проверки или нет
    p_context->key_generator.random(&p_context->key_generator, p_data->mp_value, p_data->m_val_len);

//    if ((error = (p_context->key_generator.random(&p_context->key_generator, p_data->mp_value, p_data->m_val_len))) == ak_error_ok) {
//        return ak_error_message(error, __func__, "error in generating random bytes");
//    }

    return ak_error_ok;
}

int pkcs_15_prepare_gost_key_for_enc(ak_skey gost_key, ak_buffer gost_key_der) {
    if(!gost_key || !gost_key_der)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    uint32_t key_mask_val_len = (uint32_t)(gost_key->key.size + gost_key->mask.size);

    octet_string key_mask_val;
    key_mask_val.m_val_len = key_mask_val_len;
    key_mask_val.mp_value = malloc(key_mask_val_len);
    if(!key_mask_val.mp_value)
        return ak_error_message(ak_error_null_pointer, __func__, "alloc memory fail");

    memcpy(key_mask_val.mp_value, gost_key->key.data, gost_key->key.size);
    memcpy(key_mask_val.mp_value + gost_key->key.size, gost_key->mask.data, gost_key->mask.size);

    gost_key_der->size = key_mask_val_len; // + asn_get_len_byte_cnt(key_mask_val_len) + 1;
    gost_key_der->data = malloc(gost_key_der->size);
//    asn_put_tag(TOCTET_STRING, gost_key_der->data);
//    asn_put_len(key_mask_val_len, gost_key_der->data + 1);
    asn_put_octetstr(key_mask_val, gost_key_der->data); // + 1 + asn_get_len_byte_cnt(key_mask_val_len));

    return ak_error_ok;
}

char* key_usage_flags_to_str(key_usage_flags_t flags)
{
    if (flags == 0)
        return NULL;

    char* str = calloc(112, sizeof(char));
    if(flags & ENCRYPT        ) {strcat(str, "ENCRYPT | "        );}
    if(flags & DECRYPT        ) {strcat(str, "DECRYPT | "        );}
    if(flags & SIGN           ) {strcat(str, "SIGN | "           );}
    if(flags & SIGN_RECOVER   ) {strcat(str, "SIGN_RECOVER | "   );}
    if(flags & WRAP           ) {strcat(str, "WRAP | "           );}
    if(flags & UNWRAP         ) {strcat(str, "UNWRAP | "         );}
    if(flags & VERIFY         ) {strcat(str, "VERIFY | "         );}
    if(flags & VERIFY_RECOVER ) {strcat(str, "VERIFY_RECOVER | " );}
    if(flags & DERIVE         ) {strcat(str, "DERIVE | "         );}
    if(flags & NON_REPUDIATION) {strcat(str, "NON_REPUDIATION | ");}

    str[strlen(str) - 3] = '\0';
    return str;
}

void print_ak_buffer(ak_buffer p_buff) {

    for (int i = 0; i < p_buff->size; i++)
    {
        printf("%02X ", *((unsigned char*)p_buff->data + i));
    }
    printf("\n");
}
