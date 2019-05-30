# Аннотация

Библиотека `libakrypt` представляет собой модуль, реализующий криптографические
преобразования в пространстве пользователя. Цель разработки библиотеки заключается в создании СКЗИ
с открытым исходным кодом, удовлетворяющего методическим рекомендациям Р 1323565.1.012-2017
«Информационная технология. Криптографическая защита информации.
Принципы разработки и модернизации шифровальных (криптографических) средств защиты
информации» по классу КС3 (подробности см. [здесь](https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-012-2017-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-printsipy-razrabotki-i-modernizatsii-shifrovalnykh-kriptograficheskikh-sredstv-zashchity-informatsii.html)).

## Возможности

Библиотека `libakrypt` написана на языке C и реализует механизмы генерации, хранения, экспорта и импорта ключей, а также
основные отечественные криптографические механизмы, регламентированные отечественными стандартами
и методическими рекомендациями, включая следующие.

 1. Бесключевые функции хеширования «Стрибог-256» и «Стрибог-512», регламентируемые
   стандартом [ГОСТ Р 34.11-2012](https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-11-2012-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-funktsiya-kheshirovaniya.html).

 2. Алгоритмы блочного шифрования данных «Магма» и «Кузнечик», регламентируемые
   стандартом [ГОСТ Р 34.12-2015](https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-12-2015-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-blochnye-shifry.html).

 3. Механизмы зашифрования/расшифрования данных c помощью алгоритмов блочного шифрования
   в следующих режимах (согласно [ГОСТ Р 34.13-2015](https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-13-2015-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-rezhimy-raboty-blochnykh-shifrov.html)):
    * режим простой замены (ECB, electronic codebook mode);
    * режим гаммирования (CTR, counter mode);
    * режим гаммирования с обратной связью по выходу (OFB, output feedback mode);
    * режим простой замены с зацеплением (CBC, cipher block chaining mode);
    * режим гаммирования с обратной связью по шифртексту (CFB, cipher feedback mode).

 4. Режим работы блочных шифров ACPKM, регламентируемый рекомендациями по стандартизации
[Р 1323565.1.017-2018](https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-017-2018-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-kriptograficheskie-algoritmy-soputstvuyushchie-primeneniyu-algoritmov-blochnogo-shifrovaniya.html)

 5. Режим работы блочных шифров, реализующий аутентифицированное шифрование (режим MGM).

 6. Алгоритмы выработки имитовставки (кода аутентичности сообщения):
    * алгоритм выработки имитовставки HMAC, регламентированный рекомендациями по
    стандартизации [Р 50.1.113-2016](https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-50-1-113-2016-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-kriptograficheskie-algoritmy-soputstvuyushchie-primeneniyu-algoritmov-elektronnoy-tsifrovoy-podpisi-i-funktsii-kheshirovaniya.html) и
    основанный на применении функций хеширования «Стрибог-256» и «Стрибог-512»;
    * алгоритм выработки имитовставки OMAC1 (CMAC), регламентированный стандартом [ГОСТ Р 34.13-2015](https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-13-2015-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-rezhimy-raboty-blochnykh-shifrov.html) и
    использующий алгоритмы блочного шифрования «Магма» или «Кузнечик».

 7. Алгоритм развертки ключа из пароля PBKDF2, регламентированный рекомендациями по стандартизации
   [Р 50.1.111-2016](https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-50-1-111-2016-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-parolnaya-zashchita-klyuchevoy-informatsii.html)
   и использующий функции хеширования «Стрибог-256» и «Стрибог-512».

 8. Программные и биологические генераторы псевдо-случайных чисел:
    * линейный конгруэнтный генератор (используется для генерации уникальных номеров ключей),
    * линейный регистр сдвига длины 32 над полем характеристики два,
      с умножением в кольце вычетов в качестве нелинейной функции выхода (используется для маскирования ключевой информации),
    * генератор-интерфейс, использующий чтение из произвольных файлов, в частности,
       файловых устройств `/dev/random` и `/dev/urandom`;
    * генератор-интерфейс к системному генератору псевдо-случайных значений, реализованному в ОС Windows.
    * семейство генераторов, построенных с использованием функций хеширования
      согласно рекомендациям по стандартизации
      [Р 1323565.1.006-2017](https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-1323565-1-006-2017-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-mekhanizmy-vyrabotki-psevdosluchaynykh-posledovatelnostey.html).

 9. Алгоритмы, реализующие арифметику Монтгомери для эффективных вычислений в конечных простых полях
   фиксированной размерности 256 и 512 бит.

10. Алгоритмы, реализующие операции в группах точек эллиптических кривых,
   удовлетворяющих требованиям стандарта [ГОСТ Р 34.10-2012](https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-10-2012-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-protsessy-formirovaniya-i-proverki-elektronnoy-tsifrovoy-podpisi.html).
   Поддерживаются все отечественные
   эллиптические кривые, регламентированные рекомендациями по стандартизации
   [Р 50.1.114-2016](https://tc26.ru/standarts/rekomendatsii-po-standartizatsii/r-50-1-114-2016-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-parametry-ellipticheskikh-krivykh-dlya-kriptograficheskikh-algoritmov-i-protokolov.html).

11. Процедуры выработки и проверки электронной подписи, регламентированные
   стандартом [ГОСТ Р 34.10-2012](https://tc26.ru/standarts/natsionalnye-standarty/gost-r-34-10-2012-informatsionnaya-tekhnologiya-kriptograficheskaya-zashchita-informatsii-protsessy-formirovaniya-i-proverki-elektronnoy-tsifrovoy-podpisi.html).

## Платформы и компиляторы

Поддерживается работа библиотеки на следующих аппаратных платформах:

   * x86, x64, arm32v7, arm32v7eb, mips32 и mips64.


Поддерживается работа библиотеки в следующих операционных системах:

   * семейство операционных систем `Linux`,

   * `FreeBSD`,

   * семейство Windows (от Windows XP и старше)

   * `MacOS`.

Также были проведены успешные запуски библиотеки под управлением следующих операционных систем:

   * `ReactOS`,

   * `SailfishOS`.

Поддерживается сборка библиотеки при помощи следующих компиляторов:

   * `gcc` (в частности `mingw` под Windows),

   * `clang`,

   * Microsoft Visual Studio (начиная с версии `MSVC10`),

   * TinyCC,

   * Intel C Compiler.

## Внимание

В настоящее время библиотека всё ещё находится в статусе разработки и не рекомендуется для
реальной защиты обрабатываемой пользователем информации.
