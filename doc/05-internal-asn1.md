Внутренний интерфейс. Реализация ASN.1 нотации представления данных
-------------------------------------------------------------------


Описание элементарных типов ASN.1
=================================

К базовым типам ASN.1, определенным ГОСТ Р ИСО/МЭК 8824-1-2001, относятся

    BOOLEAN
    INTEGER
    BIT_STRING
    OCTET_STRING
    NULL
    OBJECT_IDENTIFIER
    OBJECT_DESCRIPTOR
    EXTERNAL
    REAL
    ENUMERATED
    UTF8_STRING
    SEQUENCE
    SET
    NUMERIC_STRING
    PRINTABLE_STRING
    T61_STRING
    VIDEOTEX_STRING
    IA5_STRING
    UTCTIME
    GENERALIZED_TIME
    GRAPHIC_STRING
    VISIBLE_STRING
    GENERAL_STRING
    UNIVERSAL_STRING
    CHARACTER_STRING
    BMP_STRING

В библиотеке `libakrypt` реализована поддержка указанных типов в объеме, достаточном
для реализации механизмов экспорта/импорта ключевой информации в соответствии с национальными
стандартами и рекомендациями по стандартизации.
Все остальные используемые библиотекой типы данных строятся из базовых типов.

Также в библиотеке реализовано некоторое множество базовых составных типов, которые неоднократно
используются при экспорте и импорте разных типов ключевых данных.
Большая часть приведенных далее типов определяется согласно RFC 5280.

### Тип Time
Тип `Time`, согласно x509, описывает значение времени.

    Time ::= CHOICE {
      utcTime UTCTime,
      generalTime generalizedTime
    }

### Тип Validity

Тип `Validity` содержит в себе временной интервал действия
ключа и определяется стандартным для x509 образом.

    Validity ::= SEQUENCE {
      notBefore Time,
      notAfter Time
    }

### Тип Resource

Тип `KeyParameters` предназначен для хранения
ресурсов (ограничений) использования ключевой информации и определяется следующим образом.

    KeyParameters ::= SEQUENCE {
       resourceType INTEGER, -- тип ресурса секретного ключа
       resource INTEGER,     -- значение ресурса
       validity Validity     -- временной интервал использования ключа
    }

Тип ресурса секретного ключа должен принимать значения,
определямые константами реализованного в библиотеке перечисления \ref counter_resource_t

### Тип Name

Тип `Name` -- глобальное или обобщенное имя представляет собой
иерархический список типизированных имен, состоящих их пары тип-имя.
Каждая пара может описывать различные характеристики обощенного имени, например, страну, графическое положение,
имя, прозвище, место работы, подразделение и т.п.

    Name ::= CHOICE {
               rdnSequence RDNSequence  -- сейчас поддерживается только один вариант
    }

    RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

    RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue

    AttributeTypeAndValue ::= SEQUENCE {
       type   AttributeType,  -- тип пары, определяющий смысловую нагрузку строки
       value  AttributeValue  -- символьная строка с информацией
    }

    AttributeType ::= OBJECT IDENTIFIER

    AttributeValue ::= ANY DEFINED BY AttributeType

Как правило, строка данных определяется одним из следующих строковых типов

    DirectoryString ::= CHOICE {
       teletexString TeletexString (SIZE (1..MAX)),
       printableString PrintableString (SIZE (1..MAX)),
       universalString UniversalString (SIZE (1..MAX)),
       utf8String UTF8String (SIZE (1..MAX)),
       bmpString BMPString (SIZE (1..MAX))
    }

Пример декодирования обощенного имени, взятый из корневого сертифката тестового УЦ,
выглядит следующим образом.

    ├SEQUENCE┐
             ├SET┐
             │   └SEQUENCE┐
             │            ├OBJECT IDENTIFIER 1.2.643.100.1 (ОГРН)
             │            └NUMERIC STRING 1234567890123
             ├SET┐
             │   └SEQUENCE┐
             │            ├OBJECT IDENTIFIER 1.2.643.3.131.1.1 (ИНН)
             │            └NUMERIC STRING 001234567890
             ├SET┐
             │   └SEQUENCE┐
             │            ├OBJECT IDENTIFIER 2.5.4.9 (Street Address)
             │            └UTF8 STRING ул. Сущёвский вал д. 18
             ├SET┐
             │   └SEQUENCE┐
             │            ├OBJECT IDENTIFIER 2.5.4.6 (Country Name)
             │            └PRINTABLE STRING RU
             ├SET┐
             │   └SEQUENCE┐
             │            ├OBJECT IDENTIFIER 2.5.4.8 (State Or Province Name)
             │            └UTF8 STRING г. Москва
             ├SET┐
             │   └SEQUENCE┐
             │            ├OBJECT IDENTIFIER 2.5.4.7 (Locality Name)
             │            └UTF8 STRING Москва
             ├SET┐
             │   └SEQUENCE┐
             │            ├OBJECT IDENTIFIER 2.5.4.10 (Organization)
             │            └UTF8 STRING ООО "КРИПТО-ПРО"
             └SET┐
                 └SEQUENCE┐
                          ├OBJECT IDENTIFIER 2.5.4.3 (Common Name)
                          └UTF8 STRING Тестовый УЦ ООО "КРИПТО-ПРО"



