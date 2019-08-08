//
// Created by Anton Sakharov on 2019-08-03.
//

#include <stdlib.h>
#include "asn_processor/ak_asn_codec_new.h"

int main(void)
{
    boolean             bool_val;
    integer             int_val;
    bit_string          bit_str_val;
    octet_string        oct_str_val;

    ak_byte bit_str_val_arr[] = {0x07, 0xe3};
    ak_byte oct_str_val_arr[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    s_asn_tlv_t tlv_sequence;

    s_asn_tlv_t tlv_bool_val;
    s_asn_tlv_t tlv_int_val;
    s_asn_tlv_t tlv_bit_str_val_var1;
    s_asn_tlv_t tlv_bit_str_val_var2;
    s_asn_tlv_t tlv_bit_str_val_var3;

    s_asn_tlv_t tlv_oct_str_val;
    s_asn_tlv_t tlv_obj_id_val;
    s_asn_tlv_t tlv_utf8_str_val;
    s_asn_tlv_t tlv_gen_time_val;
    s_asn_tlv_t tlv_utc_time_val;
    s_asn_tlv_t tlv_vsbl_str_val;
    s_asn_tlv_t tlv_ia5_str_val;
    s_asn_tlv_t tlv_prntbl_str_val;
    s_asn_tlv_t tlv_num_str_val;

    s_asn_tlv_t children[14];
    ak_uint8 index = 0;

    /* Инициализируем библиотеку */
    if (ak_libakrypt_create(NULL/*ak_function_log_stderr*/) != ak_true)
    {
        return ak_libakrypt_destroy();
    }

    /* Создаем составной объект Sequence */
    ak_asn_construct_data_ctx_create(&tlv_sequence, CONSTRUCTED | TSEQUENCE, "common sequence");

    /* Кодируем все поддерживаемые на данный момент базовые типы ASN.1 */
    bool_val = ak_true;
    if(ak_asn_encode_universal_data(TBOOLEAN, &bool_val, "boolean value", &tlv_bool_val) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_bool_val;

    int_val = 2019;
    if(ak_asn_encode_universal_data(TINTEGER, &int_val, "integer value", &tlv_int_val) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_int_val;

    /* ------------------- Добавление одинакового значения bit string разными способами ------------------- */

    ak_bitstr_set_str(&bit_str_val, "11111100011");
    if(ak_asn_encode_universal_data(TBIT_STRING, &bit_str_val, "bit string value from string", &tlv_bit_str_val_var1) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_bit_str_val_var1;
    free(bit_str_val.mp_value);

    ak_bitstr_set_arr(&bit_str_val, bit_str_val_arr, sizeof(bit_str_val_arr), 5);
    if(ak_asn_encode_universal_data(TBIT_STRING, &bit_str_val, "bit string value from array", &tlv_bit_str_val_var2) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_bit_str_val_var2;
    free(bit_str_val.mp_value);


    ak_bitstr_set_ui(&bit_str_val, 0x7e3, 11);
    if(ak_asn_encode_universal_data(TBIT_STRING, &bit_str_val, "bit string value from int", &tlv_bit_str_val_var3) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_bit_str_val_var3;
    free(bit_str_val.mp_value);

    /* ------------------- /Добавление одинакового значения bit string разными способами ------------------- */

    oct_str_val.mp_value = oct_str_val_arr;
    oct_str_val.m_val_len = sizeof(oct_str_val_arr);
    if(ak_asn_encode_universal_data(TOCTET_STRING, &oct_str_val, "octet string value", &tlv_oct_str_val) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_oct_str_val;

    if(ak_asn_encode_universal_data(TOBJECT_IDENTIFIER, "1.2.3.4.5", "object identifier value", &tlv_obj_id_val) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_obj_id_val;

    if(ak_asn_encode_universal_data(TUTF8_STRING, "Some UTF8 string", "UTF8 string value", &tlv_utf8_str_val) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_utf8_str_val;

    if(ak_asn_encode_universal_data(TGENERALIZED_TIME, "2019-01-01 00:00:00 UTC", "generalized time value", &tlv_gen_time_val) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_gen_time_val;

    if(ak_asn_encode_universal_data(TUTCTIME, "19-01-01 00:00:00 UTC", "UTC time value", &tlv_utc_time_val) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_utc_time_val;

    if(ak_asn_encode_universal_data(TVISIBLE_STRING, "Some visible string", "visible string value", &tlv_vsbl_str_val) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_vsbl_str_val;

    if(ak_asn_encode_universal_data(TIA5_STRING, "Some IA5 string", "IA5 string value", &tlv_ia5_str_val) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_ia5_str_val;

    if(ak_asn_encode_universal_data(TPRINTABLE_STRING, "Some printable string", "printable string value", &tlv_prntbl_str_val) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_prntbl_str_val;

    if(ak_asn_encode_universal_data(TNUMERIC_STRING, "2019", "numeric string value", &tlv_num_str_val) != ak_error_ok)
        return ak_error_wrong_asn1_encode;
    children[index++] = tlv_num_str_val;

    /* Добавляем все элементы в Sequence */
    ak_asn_add_nested_elems(&tlv_sequence, children, index);

    /* Выводим получившуюся структуру */
    new_ak_asn_print_tree(&tlv_sequence);

    /* Освобождаем выделенную память */
    ak_asn_free_tree(&tlv_sequence);

    /* Деинициализируем библиотеку */
    return ak_libakrypt_destroy();
}
