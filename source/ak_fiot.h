/* ----------------------------------------------------------------------------------------------- */
 #ifndef __FIOT_H__
 #define __FIOT_H__

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_SIGNAL_H
 /* заголовок нужен для определения типа sig_atomic_t */
 #include <signal.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>

/* ----------------------------------------------------------------------------------------------- */
/*  Группа уникальных ошибок протокола sp fiot */
/*! \brief Ошибка выбора роли участника протокола. */
 #define fiot_error_wrong_role                 (-257)
/*! \brief Ошибка выбора типа интрефейса. */
 #define fiot_error_wrong_gate                 (-258)
/*! \brief Передача данных слишком большой длины. */
 #define fiot_error_wrong_send_length          (-259)

/*! \brief Неверное значение, определяющее тип принимаемого фрейма. */
 #define fiot_error_frame_type                 (-258)
/*! \brief Неверное значение, определяющее размер буффера для приема/отправки фреймов. */
 #define fiot_error_frame_size                 (-259)
/*! \brief Неверное значение типа буффера для приема/передачи данных. */
 #define fiot_error_frame_buffer_type          (-261)
/*! \brief Неверный формат фрейма. */
 #define fiot_error_frame_format               (-262)
/*! \brief Неверно установленный криптографический механизм. */
 #define fiot_error_wrong_mechanism            (-263)
/*! \brief Неверно установленные ограничения для криптографических механизмов. */
 #define fiot_error_wrong_restrictions         (-264)
/*! \brief Неверно заданный набор параметров эллиптической кривой. */
 #define fiot_error_unknown_paramset           (-265)
/*! \brief Неверное значение типа предварительно распределенного ключа. */
 #define fiot_error_wrong_psk_type             (-266)
/*! \brief Использование неопределенного/неверного идентификатора предварительно распределенного ключа */
 #define fiot_error_wrong_psk_identifier_using (-267)
/*! \brief Неверное значение типа используемого генератора случайных чисел. */
 #define fiot_error_wrong_random_generator     (-268)
/*! \brief Ошибка генерации случайных данных. */
 #define fiot_error_bad_random_data            (-269)
/*! \brief Неверно заданный тип алгоритма блочного шифрования */
 #define fiot_error_wrong_cipher_type          (-270)
/*! \brief Неверно заданный тип алгоритма вычисления имитовставки */
 #define fiot_error_wrong_integrity_algorithm  (-271)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Допустимые роли участников защищенного взаимодействия. */
 typedef enum {
  /*! \brief Роль не определена. */
   undefined_role,
  /*! \brief Участник выполняет роль клиента. */
   client_role,
  /*! \brief Участник выполняет роль сервера. */
   server_role
} role_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Идентификатор буффера, используемого для приема и отправки фреймов. */
 typedef enum {
  /*! \brief Буффер, используемый для приема сообщений. */
   inframe = 0x0,
  /*! \brief Буффер, используемый для отправки сообщений. */
   oframe = 0x1
} frame_buffer_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип фрейма.
    \details Константа определяет значение второго (начиная с младших) бита,
    см. раздел 7 спецификации протокола.                                                           */
/* ----------------------------------------------------------------------------------------------- */
 typedef enum {
  /*! \brief Фрейм передается в незашифрованном виде. */
   plain_frame = 0x00,
  /*! \brief Фрейм передается в зашифрованном виде. */
   encrypted_frame = 0x02
} frame_type_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип данных, информирующий о том, представлены ли данные, или нет. */
 typedef enum {
    not_present = 0xB0,
    is_present = 0xB1
} present_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип данных, информирующий о наличии или отсутствии запроса. */
 typedef enum {
    not_requested = 0xB0,
    is_requested = 0xB1
} request_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип используемых сертификатов открытых ключей. */
 typedef enum {
    plain = 0x10,
    x509 = 0x19,
    cvc = 0x20
 } certificate_format_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Способ выбора запрашиваемого к использованию сертификата. */
 typedef enum {
    any = 0x00,
    number = 0x10,
    issuer = 0x20
} certificate_processed_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип передаваемого сообщения. */
 typedef enum {
    client_hello = 0x11,
    server_hello = 0x12,
    verify_message = 0x13,
    application_data = 0x14,
    alert = 0x15,
    generate_psk = 0x16,
    extension_request_certificate = 0x21,
    extension_certificate = 0x22,
    extension_set_ertificate = 0x23,
    extension_inform_certificate = 0x24,
    extension_request_identifer = 0x25,
    extension_key_echanism = 0x26
} message_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип, определяющий текущий набор используемых криптографических механизмов. */
 typedef enum {
    not_set_mechanism = 0x0000,
    streebog256 = 0x0013,
    streebog512 = 0x0023,
    magmaGOST3413ePSK = 0x2051,
    kuznechikGOST3413ePSK = 0x2052,
    magmaGOST3413iPSK = 0x3101,
    kuznechikGOST3413iPSK = 0x3102,
    hmac256ePSK = 0x2033,
    hmac512ePSK = 0x2043,
    hmac256iPSK = 0x3033,
    hmac512iPSK = 0x3043,
    magmaCTRplusHMAC256 = 0x1131,
    magmaCTRplusGOST3413 = 0x1151,
    kuznechikCTRplusHMAC256 = 0x1132,
    kuznechikCTRplusGOST3413 = 0x1152,
    magmaAEAD = 0x1201,
    kuznechikAEAD = 0x1202,
} crypto_mechanism_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Допустимые алгоритмы блочного шифрования, прил. Б.2.8 */
 typedef enum {
    undefined_cipher = 0x00,
    magma_cipher = 0x01,
    kuznechik_cipher = 0x02,
    null_cipher = 0x03
} block_cipher_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Допустимые алгоритмы вычисления кода целостности, прил. Б.2.8 */
 typedef enum {
  undefined_function = 0x00,
  streebog256_function = 0x01,
  streebog512_function = 0x02,
  hmacStreebog256_function = 0x03,
  hmacStreebog512_function = 0x04,
  imgost3413_function = 0x05,
} integrity_function_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Допустимые варианты используемых ключей, прил. Б.2.8 */
 typedef enum {
   undefined_key = 0x00,
   derivative_Key = 0x01,
   ePSK_key = 0x02,
   iPSK_key = 0x03
} key_type_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Используемые наборы параметров эллиптических кривых. */
 typedef enum {
    unknown_paramset = 0x00,
    tc26_gost3410_2012_256_paramsetA = 0x01,
    tc26_gost3410_2012_512_paramsetA = 0x02,
    tc26_gost3410_2012_512_paramsetB = 0x03,
    tc26_gost3410_2012_512_paramsetC = 0x04,
    rfc4357_gost3410_2001_paramsetA = 0x05,
    rfc4357_gost3410_2001_paramsetB = 0x06,
    rfc4357_gost3410_2001_paramsetC = 0x07
} elliptic_curve_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Различные типы длин передаваемых фреймов. */
 typedef enum {
   small_frame = 0x00,
   long_frame = 0x01
} crypto_frame_length_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Допустимые классы средств СКЗИ. */
 typedef enum {
   base_class  = 0x05,
   KC_class = 0x06,
   KA_class = 0x07
} crypto_class_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Режимы использования криптографических механизмов (определяют технические характеристики
    протокола sp fiot).
    \details Указанные значения зависят от максимальной длины передаваемых фреймов, используемого
    блочного шифра, а также класса средства защиты. Значения определяются следующим образом:
    - нулевой (младший) бит (0 - сообщения не превосходят 1500 октетов, 1 - иначе ),
    - первый бит - всегда ноль (резерв),
    - третий/четвертый биты: класс средства (01 - не классифицируемое средство, 10 - класс КС3 и ниже,
      11 - классы КВ и КА)
    - пятый/шестой биты: используемый блочный шифр (01 - Магма, 10 - Кузнечик).                    */
/* ----------------------------------------------------------------------------------------------- */
 typedef enum {
   undefinedKeyMechanism = 0x00,
   baseKeyMechanismMagma = ( small_frame | base_class | ( magma_cipher << 4 )),
   baseKeyMechanismKuznechik = ( small_frame | base_class | ( kuznechik_cipher << 4 )),
   shortKCMechanismMagma = ( small_frame | KC_class | ( magma_cipher << 4 )),
   shortKCMechanismKuznechik = ( small_frame | KC_class | ( kuznechik_cipher << 4 )),
   longKCMechanismMagma = ( long_frame | KC_class | ( magma_cipher << 4 )),
   longKCMechanismKuznechik = ( long_frame | KC_class | ( kuznechik_cipher << 4 )),
   shortKAMechanismMagma = ( small_frame | KA_class | ( magma_cipher << 4 )),
   shortKAMechanismKuznechik = ( small_frame | KA_class | ( kuznechik_cipher << 4 )),
   longKAMechanismMagma =( long_frame | KA_class | ( magma_cipher << 4 )),
   longKAMechanismKuznechik = ( long_frame | KA_class | ( kuznechik_cipher << 4 ))
} key_mechanism_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Набор ограничений (параметров) для защищенного взаимодействия, см. прил. Г. */
 typedef struct {
  /*! \brief Максимальная длина сериализованного представления структуры Frame. */
   unsigned int maxFrameLength;
  /*! \brief Максимальное количество фреймов, зашифровываемых на одном ключе. */
   unsigned int maxFrameCount;
  /*! \brief Максимальное количество пар производных ключей шифрования и имитовставки. */
   unsigned int maxFrameKeysCount;
  /*! \brief Максимальное количество преобразований ключевой информации в рамках одного сеанса связи. */
   unsigned int maxApplicationSecretCount;
} crypto_restriction_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип ошибки, возвращаемой в ходе выполнения протокола sp fiot. */
 typedef enum {
    unknownError = 0x1000,
    unsupportedCryptoMechanism = 0x1001,
    wrongExternalPreSharedKey = 0x1002,
    wrongInternalPreSharedKey = 0x1003,
    wrongIntegrityCode = 0x1004,
    lostIntegrityCode = 0x1005,
    wrongCertificateProcessed = 0x100a,
    wrongCertificateNumber = 0x100b,
    expiredCertificate = 0x100c,
    unsupportedCertificateNumber = 0x100d,
    notValidCertificateNumber = 0x100e,
    wrongCertificateApplication = 0x100f,
    wrongCertificateIssuer = 0x1010,
    unsupportedCertificateIssuer = 0x1011,
    unsupportedCertificateFormat = 0x1012,
    wrongCertificateIntegrityCode = 0x1013,
    usupportedKeyMechanism = 0x1020,
    unsupportedEllipticCurveID = 0x1031,
    wrongEllipticCurvePoint = 0x1032,
    wrongInternalPSKIdentifier = 0x1040
} alert_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Возможные состояния контекста защищенного взаимодействия для клиента и сервера
    в ходе выполнения протокола выработки общих ключей.

    \details Константы `rts` (ready to send) описывают состояние готовности к отправке
    сообщения. Константы `wait` описывают состояние готовности к приему сообщения.
    В каждом состоянии клиент и сервер могут выполнить только одно действие по приему
    или передаче сообщений.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 typedef enum {
 /*! \brief Неопределенное состояние, устанавливается при создании контекста. */
   undefined_state,
 /* последовательность состояний клиента */
 /*! \brief Клиент готов отправить сообщение ClientHello */
   rts_client_hello,
 /*! \brief Клиент готов отправить расширение ClientExtension в ходе первого шага протокола */
   rts_client_extension,
 /*! \brief Клиент готов к приему от сервера сообщения ServerHello */
   wait_server_hello,
 /*! \brief Клиент готов к приему от сервера расширений ServerExtension */
   wait_server_extension,
 /*! \brief Клиент готов к приему от сервера сообщения ServerVerify */
   wait_server_verify,
 /*! \brief Клиент готов отправить расширение ClientExtension в ходе первого шага протокола */
   rts_client_extension2,
 /*! \brief Клиент готов отправить сообщение ClientVerify */
   rts_client_verify,
 /*! \brief Клиент готов к приему от сервера прикладных данных */
   wait_server_application_data,
 /* последовательность состояний сервера */
 /*! \brief Сервер готов к приему от клиента сообщения ClientHello */
   wait_client_hello,
 /*! \brief Сервер готов к приему от клиента расширений ClientExtensions */
   wait_client_extension,
 /*! \brief Сервер готов к отправке сообщения ServerHello */
   rts_server_hello,
 /*! \brief Сервер готов к отправке расширений ServerExtension */
   rts_server_extension,
 /*! \brief Сервер готов к отправке сообщения ServerVerify */
   rts_server_verify,
 /*! \brief Сервер готов к приему от клиента расширений ClientExtension */
   wait_client_extension02,
 /*! \brief Сервер готов к приему от клиента сообщения ClientVerify */
   wait_client_verify,
 /*! \brief Сервер готов к приему от клиента прикладных данных */
   wait_client_application_data

} context_state_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, определяющая разбиение длин идентификаторов клиента/сервера,
    помещаемых в исходный идентификатор ключа epsk.                                                */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct fiot_psk_id_sizes {
  unsigned char serverID, serverIDsp, clientID, clientIDcp;
} fiot_psk_id_sizes_t;

/* ----------------------------------------------------------------------------------------------- */
 typedef enum {
   undefined_gate = -1,
   encryption_gate = 0,
   plain_gate = 1
 } gate_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Минимальный уровень аудита сетевых приложений */
 #define fiot_log_minimal                         ( ak_log_maximum + 1 )
/*! \brief Стандартный уровень аудита сетевых приложений */
 #define fiot_log_standard                        ( ak_log_maximum + 2 )
/*! \brief Параноидальный уровень аудита сетевых приложений */
 #define fiot_log_maximum                         ( ak_log_maximum + 3 )

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Минимальный размер фрейма. */
 #define fiot_min_frame_size        (256)
/*! \brief Размер фрейма по-умолчанию. */
 #define fiot_frame_size           (1472)
/*! \brief Максимальный размер фрейма. */
 #define fiot_max_frame_size      (16356)
/*! \brief Смещение зашифровываемых данных от начала фрейма (для базового заголовка). */
 #define fiot_frame_header_offset     (8)
/*! \brief Смещение собственно сообщения от начала фрейма (для базового заголовка). */
 #define fiot_frame_message_offset   (11)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Контекст защищенного соединения протокола sp fiot.
    \details Контекст представляет собой фильтр ...

*/
 typedef struct fiot {
  /*! \brief Буфер, используемый для формирования исходящих фреймов. */
   char *oframe;
  /*! \brief Максимальный размер буффера, содержащего передаваемые в канал связи данные,
      с учетом длины заголовка и тела фрейма.
      \details Размер буффера может изменяться в ходе выполнения защищенного взаимодействия. */
   size_t oframe_size;
  /*! \brief Буфер, используемый для рабора входящих фреймов. */
   char *inframe;
  /*! \brief Максимальный размер буффера, используемого для приема входящих сообщений.
      \details Размер буффера может изменяться в фиксированных пределах,
      определяемых константами \ref FIOT_MIN_FRAME_SIZE и \ref FIOT_MAX_FRAME_SIZE. Изменение
      контролируется размерами входящих сообщений. */
   size_t inframe_size;

  /*! \brief Смещение зашифровываемых данных от начала фрейма (длина расширяемого заголовка).
      \details Для стандартного заголовка равна 8 октетам. Для расширяемого заголовка может принимать
      любое значение от восьми до 64-х. */
   size_t header_offset;
  /*! \brief Роль участника взаимодействия */
   role_t role;
  /*! \brief Текущее состояние контекста. */
   context_state_t state;
  /*! \brief Используемый в текущий момент набор криптографических механизмов. */
   crypto_mechanism_t mechanism;
  /*! \brief Набор параметров, задающих криптографические ограничения согласно спецификации протокола. */
   crypto_restriction_t restriction;
  /*! \brief Значение счетчиков фреймов. */
   ssize_t lcounter, mcounter, ncounter;
  /*! \brief Дескрипторы чтения и записи данных. */
   int enc_gate, plain_gate;

  /*! \brief Идентификатор сервера, должен быть определен всегда. */
   struct buffer server_id;
  /*! \brief Идентификатор клиента.
      \details Перед началом выполнения протокола может быть не определен.
      (значение может быть получено в ходе выполнения протокола). */
   struct buffer client_id;

  /*! \brief Идентификатор используемой эллиптической кривой. */
   elliptic_curve_t curve_id;
  /*! \brief Используемая эллиптическая кривая, на которой происходит выполнение протокола. */
   struct wcurve *curve;

  /*! \brief Генератор для масок, случайного дополнения и т.п. */
   struct random plain_rnd;
  /*! \brief Генератор для генерации криптографически опасной информации. */
   struct random crypto_rnd;

  /* ak_skey secret, cats, sats */

  /*! \brief Ключ шифрования информации, передаваемой от клиента к серверу */
   ak_bckey ecfk;
  /*! \brief Ключ шифрования информации, передаваемой от сервера к клиенту */
   ak_bckey esfk;
  /*! \brief Ключ имитозащиты информации, передаваемой от клиента к серверу */
   ak_mac icfk;
  /*! \brief Ключ имитозащиты информации, передаваемой от сервера к клиенту */
   ak_mac isfk;
  /*! \brief Ключ имитозащиты информации, передаваемой в открытом виде. */
   ak_mac epsk;

} *ak_fiot;

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup fiot_functions Функции создания и настройки параметров контекста защищенного взаимодействия
 *  \detail Данная группа функций позволяет создавать и настраивать контексты защищенного взаимодействия
 *   двух произвольных процессов с помощью протокола [sp fiot](https://tc26.ru/standarts/metodicheskie-rekomendatsii/mr-26-4-003-2018-kriptograficheskie-mekhanizmy-zashchishchennogo-vzaimodeystviya-kontrolnykh-i-izmeritelnykh-ustroystv.html).
 * @{*/
/*! \brief Инициализация контекста протокола sp fiot. */
 int ak_fiot_context_create( ak_fiot );
/*! \brief Уничтожение содержимого контекста протокола sp fiot. */
 int ak_fiot_context_destroy( ak_fiot );
/*! \brief Уничтожение содержимого контекста протокола sp fiot и освобождение памяти. */
 ak_pointer ak_fiot_context_delete( ak_pointer );
/*! \brief Изменение максимально допустимого размера фрейма протокола sp fiot. */
 int ak_fiot_context_set_frame_size( ak_fiot , frame_buffer_t , size_t );
/*! \brief Получение текущего значения размера одного фрейма протокола sp fiot. */
 size_t ak_fiot_context_get_frame_size( ak_fiot , frame_buffer_t );
/*! \brief Установка роли участника защищенного соединения. */
 int ak_fiot_context_set_role( ak_fiot , const role_t );
/*! \brief Получение роли участника защищенного взаимодействия. */
 role_t ak_fiot_context_get_role( ak_fiot );
/*! \brief Получение текущего статуса контекста защищенного взаимодействия. */
 context_state_t ak_fiot_context_get_state( ak_fiot );

/*! \brief Установка идентификатора участника защищенного взаимодействия. */
 int ak_fiot_context_set_user_identifier( ak_fiot , role_t , void *, const size_t );
/*! \brief Получение идентификатора участника защищенного взаимодействия. */
 ssize_t ak_fiot_context_get_user_identifier( ak_fiot , role_t , void *, const size_t );
/*! \brief Установка идентификатора используемой эллиптической кривой. */
 int ak_fiot_context_set_curve( ak_fiot , elliptic_curve_t );
/*! \brief Получение текущего идентификатора эллиптической кривой. */
 elliptic_curve_t ak_fiot_context_get_curve( ak_fiot );

/*! \brief Присвоение заданному интерфейсу контекста открытого сокета. */
 int ak_fiot_context_set_gate_descriptor( ak_fiot , gate_t, int );
/*! \brief Получение дескриптора сокета для заданного интерфейса контекста защищенного взаимодействия. */
 int ak_fiot_context_get_gate_descriptor( ak_fiot , gate_t );
/** @} */

/*! \brief Формирование сообщения транспортного протокола и отправка его в канал связи. */
 int ak_fiot_context_send_frame( ak_fiot , ak_pointer , ak_pointer , size_t ,
                                                                        frame_type_t , message_t );
/*! \brief Вывод содержимого фрейма с использованием системы аудита. */
 void ak_fiot_context_print_frame( char *, ssize_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Флаг прекращения операций сетевого чтения/записи. */
 extern volatile sig_atomic_t __io_canceled;

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                          fiot.h */
/* ----------------------------------------------------------------------------------------------- */
