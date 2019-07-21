/* ----------------------------------------------------------------------------------------------- */
/*  Файл ak_asn_codec.h                                                                           */
/*  - содержит перечень стандартных типов ASN.1;                                                   */
/*  - содержит перечень описаний функций кодирования и декодирования стандартных типов ASN.1;      */
/* ----------------------------------------------------------------------------------------------- */

#ifndef __AK_ASN_H__
#define __AK_ASN_H__

#include <libakrypt.h>
#include <pkcs_15_cryptographic_token/ak_pointer_server.h>


/*! \brief флаги, определяющие класс данных ASN.1. */
#define UNIVERSAL           0x00u
#define APPLICATION         0x40u
#define CONTEXT_SPECIFIC    0x80u
#define PRIVATE             0xC0u

/*! \brief флаг, определяющий структуру блока данных ASN.1. */
#define PRIMITIVE           0x00u
#define CONSTRUCTED         0x20u

/*! \brief номера стандартных тегов ASN.1. */
#define TEOC                0x00u
#define TBOOLEAN            0x01u
#define TINTEGER            0x02u
#define TBIT_STRING         0x03u
#define TOCTET_STRING       0x04u
#define TNULL               0x05u
#define TOBJECT_IDENTIFIER  0x06u
#define TOBJECT_DESCRIPTOR  0x07u
#define TEXTERNAL           0x08u
#define TREAL               0x09u
#define TENUMERATED         0x0Au
#define TUTF8_STRING        0x0Cu
#define TSEQUENCE           0x10u
#define TSET                0x11u
#define TNUMERIC_STRING     0x12u
#define TPRINTABLE_STRING   0x13u
#define TT61_STRING         0x14u
#define TVIDEOTEX_STRING    0x15u
#define TIA5_STRING         0x16u
#define TUTCTIME            0x17u
#define TGENERALIZED_TIME   0x18u
#define TGRAPHIC_STRING     0x19u
#define TVISIBLE_STRING     0x1Au
#define TGENERAL_STRING     0x1Bu
#define TUNIVERSAL_STRING   0x1Cu
#define TCHARACTER_STRING   0x1Du
#define TBMP_STRING         0x1Eu

/*! \brief Биты, определяющие класс данных */
#define DATA_CLASS(x)     (x & 0xC0)
/*! \brief Биты, определяющие структуру данных */
#define DATA_STRUCTURE(x) (x & 0x20)
/*! \brief Биты, определяющие номер тега */
#define TAG_NUMBER(x)     (x & 0x1F)

/*! \brief Длина тега (текущая реализация поддерживает кодирование
 *         и декодирование тегов, представленных одним байтом) */
#define TAG_LEN 1

/*! \brief Струкртура, хранящая целочисленые значения в соответствии с ASN.1. */
struct s_asn_int_type {
    /*! \brief массив, содержащий значение в формате big-endian. */
    ak_byte *mp_value;
    /*! \brief размер массива с данными. */
    ak_uint32 m_val_len;
    /*! \brief флаг, определяющий знак числа. */
    bool_t m_positive;
};

/*! \brief Струкртура, хранящая массив байтов в соответствии с ASN.1. */
struct s_asn_oct_str_type {
    /*! \brief массив, содержащий значение. */
    ak_byte *mp_value;
    /*! \brief размер массива с данными. */
    ak_uint32 m_val_len;
};

/*! \brief Струкртура, хранящая "битовую строку" в соответствии с ASN.1. */
struct s_asn_bit_str_type {
    /*! \brief массив, содержащий значение. */
    ak_byte *mp_value;
    /*! \brief размер массива с данными. */
    ak_uint32 m_val_len;
    /*! \brief кол-во неиспользуемых битов в последнем байте
               (возмжные значения от 0 до 7 включительно). */
    ak_uint8 m_unused;
};

typedef ak_byte tag;

/*! \brief Псевдонимы базовых типов ASN.1 */
typedef bool_t boolean;
typedef ak_uint32 integer;
typedef ak_byte *utf8_string;
typedef char *visible_string;
typedef char *generalized_time;
typedef char *object_identifier;
typedef struct s_asn_bit_str_type bit_string;
typedef struct s_asn_oct_str_type octet_string;

/* Создаем псевданимы типов, чтобы можно было сослаться друг на друга при описании стурктур */
typedef struct s_constructed_data s_constructed_data_t;
typedef struct s_asn_tlv s_asn_tlv_t;

/*! \brief Струкртура, хранящая массив указателей на данные, из которых состоит составной TLV. */
struct s_constructed_data
{
  /*! \brief массив указателей на данные. */
  s_asn_tlv_t** m_arr_of_data;
  /*! \brief количество объектов в массиве. */
  ak_uint8 m_curr_size;
  /*! \brief размер массива. */
  ak_uint8 m_alloc_size;
};

/*! \brief Объединение, определяющее способ представления данных (примитивное или составное). */
union u_data_representation
{
  /*! \brief указатель на примитивные данные. (Закодированые по правилам ASN.1 данные) */
  ak_byte* m_primitive_data;
  /*! \brief указатель на составные данные. */
  s_constructed_data_t* m_constructed_data;
};

/*! \brief Струкртура, хранящая массив указателей на данные, из которых состоит составной TLV. */
struct s_asn_tlv
{
  /*! \brief тег, идентифицирующий данные. */
  tag m_tag;
  /*! \brief длинна данных. */
  ak_uint32 m_data_len;
  /*! \brief данные. */
  union u_data_representation m_data;

  /*! \brief количество байтов, необходимое для кодирования длинные данных. */
  ak_uint8 m_len_byte_cnt;
  /*! \brief флаг, определяющий, должен ли объект освобождать память. */
  bool_t m_free_mem;
  /*! \brief название данных. */
  char* p_name;
};

typedef struct s_asn_tlv* ak_asn_tlv;

/*! \brief Функция кодирования ASN.1 данных. */
int ak_asn_encode(ak_asn_tlv p_tlv, ak_byte** pp_asn_data, ak_uint32* p_size);
/*! \brief Функция декодирования ASN.1 данных. */
int ak_asn_decode(ak_pointer p_asn_data, size_t size, ak_asn_tlv* pp_tlv);
/*! \brief Функция создания контекста составных данных. */
int ak_asn_construct_data_ctx_create(ak_asn_tlv p_tlv, tag constructed_data_tag, char* p_data_name);
/*! \brief Функция создания контекста примитивных данных. */

// TODO: Добавить в функцию аргумент, который указывал бы, владеет ли контекст данными
//       или просто указывает на них. bool_t *p_data_copied:
//              1) Если значение *p_data_copied == ak_true, то данные копируются в объект s_asn_tlv;
//              2) Если значение *p_data_copied == ak_false, то объект s_asn_tlv просто ссылается на данные;
//              3) Если значение p_data_copied == NULL, то см. п. 1);

int ak_asn_primitive_data_ctx_create(ak_asn_tlv p_tlv, tag data_tag, ak_uint32 data_len, ak_pointer p_data, char* p_data_name);
/*! \brief Функция получения размера памяти, необходимого для кодирования ASN.1 данных. */
int ak_asn_get_size(ak_asn_tlv p_tlv, ak_uint32* p_size);
/*! \brief Функция пересчета длинны составных данных. (Используется для обновления информации о длинах после изменений.) */
int ak_asn_update_size(ak_asn_tlv p_root_tlv);
/*! \brief Функция отображения структуры ASN.1 данных в виде дерева. */
void ak_asn_print_tree(ak_asn_tlv p_tree);
void new_ak_asn_print_tree(ak_asn_tlv p_tree);

/*! \brief Функция вывода шестнадцатеричных данных. */
void ak_asn_print_hex_data(ak_byte* p_data, ak_uint32 size);

/*! \brief Функция добавления вложенных элементов в составной объект s_asn_tlv. */
int ak_asn_add_nested_elems(ak_asn_tlv p_tlv_parent, ak_asn_tlv pp_tlv_children[], ak_uint8 count);

/*! \brief Функция удаления вложенного элемента из составного объекта s_asn_tlv. */
int ak_asn_delete_nested_elem(ak_asn_tlv p_tlv_parent, ak_uint32 index);

/*! \brief Функция очистки памяти, выделенной под хранения структуры дерева и внутренних данных. */
void ak_asn_free_tree(ak_asn_tlv p_tlv_root);

/*! \brief Декодирование тега из ASN.1 последовательности. */
int new_asn_get_tag(ak_byte** pp_data, tag *p_tag);

/*! \brief Декодирование длины данных из DER последовательности. */
int new_asn_get_len(ak_byte** pp_data, size_t *p_len);

/*! \brief Декодирование целого числа из DER последовательности. */
int new_asn_get_int(ak_byte *p_buff, ak_uint32 len, integer *p_val);

/*! \brief Декодирование UTF-8 строки из DER последовательности. */
int new_asn_get_utf8string(ak_byte *p_buff, size_t len, utf8_string *p_str);

/*! \brief Декодирование массива октетов из DER последовательности. */
int new_asn_get_octetstr(ak_byte *p_buff, size_t len, octet_string *p_dst);

/*! \brief Декодирование строки из DER последовательности. */
int new_asn_get_vsblstr(ak_byte *p_buff, size_t len, visible_string *p_str);

/*! \brief Декодирование идентификатора объекта из DER последовательности. */
int new_asn_get_objid(ak_byte *p_buff, size_t len, object_identifier *p_objid);

/*! \brief Декодирование массива байтов, представляющих произвольные флаги, из DER последовательности. */
int new_asn_get_bitstr(ak_byte *p_buff, size_t len, bit_string *p_dst);

/*! \brief Декодирование значения типа boolean из DER последовательности. */
int new_asn_get_bool(ak_byte *p_buff, size_t len, boolean *p_value);

/*! \brief Декодирование времени, представленном в общепринятом формате, из DER последовательности. */
int new_asn_get_generalized_time(ak_byte *p_buff, size_t len, generalized_time *p_time);

/*! \brief Добавление тега в DER последовательность. */
int new_asn_put_tag(tag tag, ak_byte **pp_buff);

/*! \brief Добавление длины данных в DER последовательность. */
int new_asn_put_len(size_t len, ak_uint32 len_byte_cnt, ak_byte **pp_buff);

/*! \brief Добавление целого числа в DER последовательность. */
int new_asn_put_int(integer val, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Добавление UTF-8 строки в DER последовательность. */
int new_asn_put_utf8string(utf8_string str, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Добавление массива октетов в DER последовательность. */
int new_asn_put_octetstr(octet_string src, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Добавление строки в DER последовательность. */
int new_asn_put_vsblstr(visible_string str, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Добавление идентификатора объекта в DER последовательность. */
int new_asn_put_objid(object_identifier obj_id, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Добавление массива байтов, представляющих произвольные флаги, в DER последовательность. */
int new_asn_put_bitstr(bit_string src, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Добавление значения типа boolean в DER последовательность. */
int new_asn_put_bool(boolean val, ak_byte** pp_buff, ak_uint32* p_size);

/*! \brief Добавление времени, представленном в общепринятом формате, в DER последовательность. */
int new_asn_put_generalized_time(generalized_time time, ak_byte** pp_buff, ak_uint32* p_size);


/* Tools */
/*! \brief Метод для добавления стандартных типов данных в DER последовательность. */
int new_asn_put_universal_tlv(ak_uint8 tag_number, void *p_data, size_t seq_or_set_len, s_ptr_server *p_main_ps, s_ptr_server *p_result);

/*! \brief Метод для декодированния типов данных из DER последовательности. */
int new_asn_get_expected_tlv(tag expected_tag, s_ptr_server *p_curr_ps, void *p_result);

/*! \brief Метод для определения кол-ва элементов в блоке данных DER последовательности. */
int new_asn_get_num_of_elems_in_constructed_obj(s_ptr_server *p_data, ak_uint8 *p_num_of_elems);

/*! \brief Метод для определения необходимого кол-ва памяти для хранения длины данных. */
ak_uint8 new_asn_get_len_byte_cnt(size_t len);

/*! \brief Метод для определения необходимого кол-ва памяти для хранения идентификатора объекта. */
ak_uint8 new_asn_get_oid_byte_cnt(object_identifier oid);

/*! \brief Метод для определения необходимого кол-ва памяти для хранения времени в общепринятом формате. */
ak_uint8 new_asn_get_gentime_byte_cnt(generalized_time time);

int ak_asn_realloc(ak_pointer* pp_mem, size_t old_size, size_t new_size);

/*! \brief Освобождение памяти. */
void asn_free_int(integer *p_val);

void asn_free_utf8string(utf8_string *p_val);

void asn_free_octetstr(octet_string *p_val);

void asn_free_vsblstr(visible_string *p_val);

void asn_free_objid(object_identifier *p_val);

void asn_free_bitstr(bit_string *p_val);

void asn_free_generalized_time(generalized_time *p_val);

#endif /* __AK_ASN_H__ */
