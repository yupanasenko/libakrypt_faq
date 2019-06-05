# Инструкция по сборке и установке

## Получение исходных текстов библиотеки

Cтабильная версия библиотеки распространяется в виде архива с исходными текстами


    libakrypt-0.x.y.tar.bz2


в котором `x` обозначает номер версии, а `y` номер релиза. Для разархивирования необходимо
выполнить команду


    tar -xjvf libakrypt-0.x.y.tar.bz2


Эту команду, как и все последующие, необходимо выполнять в консоли от имени обычного пользователя.
После разархивирования должен появиться каталог `libakrypt-0.x.y`, содержащий следующие подкаталоги


    libakrypt-0.x
        - akrypt   /* консольная утилита, использующая функции внешнего интерфейса */
        - cmake    /* система сборки библиотеки */
        - doc      /* документация */
        - examples /* примеры, использующие функции внешнего интерфейса */
        - source   /* исходные тексты библиотеки */
        - tests    /* тестовые примеры, использующие функции внутреннего интерфейса */


После разархивации исходных текстов можно переходить к сборке библиотеки.

Добавим, что последняя, возможно не стабильная, версия исходных текстов библиотеки
может быть получена из репозитория на сайте [github.com](http://github.com/axelkenzo/libakrypt-0.x).
Для клонирования репозитория необходимо выполнить из командной строки следующую команду.


    git clone https://github.com/axelkenzo/libakrypt-0.x


Необходимая документация и описание процедуры установки распределенной
системы управления версиями `git` могут быть найдены [здесь](http://git-scm.com).

## Система сборки

Системой сборки для библиотеки `libakrypt` является [cmake](https://cmake.org").
Система сборки не зависит от используемой операционной системы.
Необходимый набор программ и утилит может быть скачан с официального сайта программы cmake.

Установка `cmake`, как правило, доступна для стандартных средств операционной системы.
Например, в Debian или Ubuntu, установка `cmake` может быть выполнена следующей командой


    apt install cmake


Данная команда должна выполняться с правами суперпользователя.

## Зависимости библиотеки

Библиотека `libakrypt` может реализовывать многопоточное выполнение некоторых криптографических преобразований,
используя для этого базовый набор функций для работы с потоками.
В настоящее время библиотека использует функции, определяемые `POSIX Threads`.

В операционных системах семейства `Linux`, а также в `FreeBSD`,
эта функциональность входит в состав библиотеки `libc`
и не требует дополнительных действий при установке.

В операционной системе `Windows` многопоточность может быть реализована различными способами, при этом
способ реализации определяется используемым для сборки библиотеки компилятором:

- в случае, если для сборки библиотеки используется компилятор `gcc`, входящий в состав
набора библиотек и программ `MinGW`, то доступ к многопоточной функциональности
предоставляется библиотекой `libc` из пакета `MinGW`.

- в случае, если для сборки библиотеки в операционной системе Windows
используется компилятор `Microsoft Visual C` (или любой другой,
поставляемый без библиотек, реализующих многопоточную функциональность),
то необходимо использование разделяемой
библиотеки `pthreads-w32` (POSIX Threads Library for Win32).
Перед сборкой библиотеки `libakrypt` Вам необходимо вручную установить заголовочные и библиотечные файлы
(`pthreadVC.lib` и `pthreadVC.dll`, а также заголовочные файлы `pthread.h`, `semaphore.h` и `sched.h`).
Подробное описание установки `pthreads-w32` может быть найдено
в документации по [pthreads-w32](http://sources.redhat.com/pthreads-win32).

Отметим, что в случае отсутствия библиотеки, реализующей `POSIX Threads`,
соответствующая функциональность будет удалена из библиотеки `libakrypt` при сборке.

## Сборка в Unix

Основной средой разработки библиотеки `libakrypt` является Linux,
поэтому процесс сборки под Unix-like операционными системами является максимально простой процедурой.

### Сборка статической версии библиотеки

После получения исходных кодов и их разархивации,
для сборки библиотеки выполните в консоли следующую последовательность команд.


    mkdir build
    cd build
    cmake ../libakrypt-0.x
    make


В результате сборки, по-умолчанию, будет собрана статическая версия библиотеки --- `libakrypt-static.a`,
а также ряд примеров, использующих функции внешнего (экспортируемого библиотекой) интерфейса.

### Сборка динамической версии библиотеки

Для сборки динамической версии библиотеки --- `libakrypt-shared.so`,
необходимо выполнить команду `cmake` с дополнительным параметром,
указывающим факт сборки динамически исполняемой версии библиотеки.


    cmake -D LIBAKRYPT_SHARED_LIB=ON ../libakrypt-0.x


Таким образом последовательность команд для сборки принимает вид


    mkdir build
    cd build
    cmake -D LIBAKRYPT_SHARED_LIB=ON ../libakrypt-0.x
    make


### Сборка различными компиляторами

Приведенная нами выше последовательность команд использует для сборки библиотеки
найденный `cmake` компилятор по-умолчанию -- в Linux это компилятор `gcc`, во FreeBSD и MacOS это `clang`.
Если Вы хотите использовать другой компилятор, то Вам необходимо использовать
при вызове `cmake` опцию `CMAKE_C_COMPILER`, в явном виде определяющую имя компилятора.

Так, следующий вызов позволит произвести сборку библиотеки с помощью компилятора `clang`.


    cmake -D CMAKE_C_COMPILER=clang ../libakrypt-0.x


Аналогично, следующий вызов позволит произвести сборку библиотеки с помощью компилятора `tcc` (Tiny C Compiler)


    cmake -D CMAKE_C_COMPILER=tcc ../libakrypt-0.x


Отметим, что через опцию `CMAKE_C_COMPILER` можно указывать только те компиляторы,
которые поддерживаются `cmake`.
Перечень поддерживаемых компиляторов можно найти в документации по `cmake`
(см. раздел cmake-compile-features, supported compilers).


## Сборка в Windows

Под управлением операционной системы семейства `Windows`
может быть собрана как статическая, так и динамическая версия библиотеки.
Далее мы описываем способ сборки библиотеки не использующий графические средства разработки.

### Сборка с использованием компилятора Miscrosoft Visual C
На настоящий момент протестирована успешная сборка библиотеки с помощью компилятора MSVC версий 10 и старше.

Для сборки библиотеки и необходимо запустить командную строку `Visual Studio` и
создать каталог для сборки, например, выполнив команду


    mkdir build-msvc

Далее, необходимо перейти в созданный каталог и запустить `cmake` для конфигурации сборки.


    cmake -G "NMake Makefiles" path

где `path` это путь к каталогу, в котором находятся исходные коды библиотеки, например, `../libakrypt-0.x`,
а флаг `-G` определяет имя механизма, используемого далее для сборки исходных текстов.
Сборка библиотеки и тестовых примеров выполняется следующей командой


    nmake

Указанный выше пример позволит создать статическую (.lib) библиотеку и тестовые примеры. Для сборки
динамической (.dll) версии библиотеки необходимо
дополнительно указать соответствующий флаг при вызове `cmake`.


    cmake -G "NMake Makefiles" -D LIBAKRYPT_SHARED_LIB=ON path

Для запуска тестовых примеров
собранных с поддержкой динамической библиотеки
необходимо, чтобы либо в созданном Вами каталоге `build`,
либо в стандартных путях, доступных операционной системе,
находился файл `pthreadVC2.dll`.
В случае, если данный файл не будет найден, операционная система выдаст соответствующее предупреждение.

### Сборка с использованием компилятора GCC
Для сборки компилятором `gcc` Вам необходимо установить набор программ из проекта `MinGW`.
Далее, в командной строке (используйте консоль MinSYS) выполнить следующую последовательность команд.


    mkdir build
    cd build
    cmake -G "MinGW Makefiles" ../libakrypt-0.x
    mingw32-make.exe

Аналогично сказанному выше, для сборки
динамической библиотеки и тестовых примеров, собранных с поддержкой динамических библиотек,
необходимо выполнить следующую последовательность команд.


    mkdir build
    cd build
    cmake -G "MinGW Makefiles" -D LIBAKRYPT_SHARED_LIB=ON ../libakrypt-0.x
    mingw32-make.exe

## Сборка для исполнения под другими платформами

Помимо традиционной сборки, когда библиотека компилируется и выполняется
на одной и той же аппаратной платформе, можно реализовать процесс сборки, при которой эти платформы различаются.

Мы рассмотрим случай в котором платформой сборки (host system)
является Linux, а платформой выполнения (target system) --- любая другая
операционная система, например, Windows или Linux на ARM Cortex.
Для такой сборки наиболее удобным является компилятор `clang`,
или более точно, его сборка из проекта [ellcc](http://ellcc.org).
В данном проекте компилятору `clang` присвоено имя `ecc`.

Обязательным параметром, который должен передаваться компилятору `ecc`
является платформа (target system), на которой будет выполняться компилируемая программа.
Например, для сборки библиотеки под 64-x битную версию Windows (на архитектуре x64),
можно выполнить следующую команду.


    cmake -D CMAKE_C_COMPILER=ecc -D CMAKE_C_FLAGS="-target x86_64-w64-mingw32"
                 -D LIBAKRYPT_EXT=".exe" -D LIBAKRYPT_CONF="C:/" ../../libakrypt-0.x


Прокомментируем приведенные выше параметры команды `cmake`.

* Как и ранее, имя компилятора передается через переменную `CMAKE_C_COMPILER` (в нашем примере это `ecc`);
* Платформа сборки передается в `cmake` через переменную `CMAKE_C_FLAGS` (-target x86_64-w64-mingw32);
* Параметр `LIBAKRYPT_EXT` (.exe) указывает расширение для исполняемых файлов (это актуально только для Windows);
* Параметр `LIBAKRYPT_CONF` - каталог, в котором будет находиться файл с техническими характеристиками
библиотеки `libakrypt`.



## Сборка тестовых примеров

Для проверки корректноcти сборки библиотеки можно
собрать систему тестов, использующих не экспортируемые функции библиотеки (функции внутреннего интерфейса).
По умолчанию, данная возможность выключена. Для ее включения достаточно выполнить


    cmake -D LIBAKRYPT_INTERNAL_TESTS=ON ../libakrypt-0.x

При сборке библиотеки компилятор также соберет тестовые примеры,
используя для этого статическую версию собранной библиотеки.
После этого, для запуска системы тестов достаточно запустить


    make test

После прохождения тестов будет выведена информация об общем числе успешно пройденных тестов,
а также времени их работы.


## Инсталляция библиотеки

В текущей версии библиотеки поддерживается процесс
инсталляции библиотеки только под Unix-like операционными системами.

По умолчанию предполагается, что библиотека будет установлена в каталог `/usr/local`.
Для изменения этого каталога
можно передать в `cmake` путь установки в явном виде. Например, следующий вызов позволяет
установить библиотеку в католог `/usr`.


    cmake -DCMAKE_INSTALL_PREFIX=/usr ../libakrypt-0.x


Для инсталляции библиотеки достаточно выполнить команду


    make install


**Внимание.** Команда инсталляции библиотеки должна выполняться с правами суперпользователя.

## Сборка документации

Часть документации,
не зависящая от исходных текстов библиотеки, располагается в каталоге `doc`.

Для сборки полной документациии необходимо установить
программу [Doxygen](http://www.doxygen.org/index.html).
После этого станет возможным собрать документацию в формате `html` с помощью
последовательности команд


    cmake -DLIBAKRYPT_HTML_DOC=ON ../libakrypt-0.x
    make html

Созданная документация будет находиться в каталоге `doc`,
а также будет упакована в архив `libakrypt-doc-0.x.tar.bz2`,
расположенный в каталоге сборки библиотеки.

Дополнительно,
если у Вас установлена программа qhelpgenerator (входит в стандартную установку библиотеки Qt),
то указанный вызов также создаст документацию в формате `qch`
(в каталоге сборки должен появиться файл `libakrypt-doc-0.x.qch`).

## Перечни флагов для сборки библиотеки

В заключение, приведем перечень флагов, которые могут передаваться в `cmake` для настройки и уточнения значений
параметров сборки библиотеки.
Данные параметры определены только для библиотеки `libakrypt` и дополняют существующие флаги `cmake`.

### LIBAKRYPT_AKRYPT

Опция `LIBAKRYPT_AKRYPT` указывает на необходимость сборки библиотеки вместе с консольной утилитой
`akrypt`, предназначенной для проведения криптографических преобразований с файлами и иллюстрации
возможностей библиотеки. Например, утилита предоставляет возможность вычислять контрольные
суммы файлов, зашифровывать файлы и подписывать их с помощью электронной подписи.

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `OFF`.


### LIBAKRYPT_CONF

Опция `LIBAKRYPT_CONF` устанавливает каталог инсталляции и последующего
поиска конфигурационного файла `libakrypt.conf`, содержащего точные
значения технических и криптографических характеристик библиотеки.

Принимаемые значения: произвольная строка символов.

Значение по умолчанию: в Unix-подобных системах значением является каталог `/etc`,
для Windows-подобных систем значение не определено.

### LIBAKRYPT_CONST_CRYPTO_PARAMS
Опция `LIBAKRYPT_CONST_CRYPTO_PARAMS` указывает, можно ли после сборки библиотеки
контролировать значения технических и критографических характеристик библиотеки.

Если значение опции установлено в `ON`, то библиотека
компилируется без поддержки функций чтения технических характеристик, а файл,
определяемый значением опции `LIBAKRYPT_CONF`, не создается. При вычислениях используются константные
значения, жестко зашитые в исходные тексты библиотеки.

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `OFF`.


### LIBAKRYPT_CRYPTO_FUNCTIONS

Опция `LIBAKRYPT_CRYPTO_FUNCTIONS` указывает необходимость сборки
библиотеки с использованием криптографических преобразований.

В случае, когда опция принимает значение `OFF`, собранная библиотека
содержит только базовые преобразования:
 - реализацию арифметических операций с большими целыми числами,
 - реализацию арифметических операций с элементами полей Галуа \f$ \mathbb F_{2^n} \f$,
 - реализацию операций сложения и удвоения, а также вычисления кратной точки на эллиптической кривой,
 - функции чтения/записи значений технических характеристик библиотеки.

Какие-либо криптографические преобразования не поддерживаются.

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `ON`.


### LIBAKRYPT_EXT

Опция `LIBAKRYPT_EXT` устанавливает расширение для скомпилированных контрольных примеров и программ;
используется, как правило, для установки расширения `.exe` в операционной системе `Windows`.

Принимаемые значения: произвольная строка символов.

Значение по умолчанию: не определено.

### LIBAKRYPT_FIOT

Опция `LIBAKRYPT_FIOT` указывает на необходимость сборки
библиотеки с использованием протокола защищенного взаимодействия sp fiot.

Включенное значение опции автоматически приводит к
включению опций `LIBAKRYPT_CRYPTO_FUNCTIONS` и `LIBAKRYPT_NETWORK`.

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `OFF`.


### LIBAKRYPT_GMP_TESTS

Опция `LIBAKRYPT_GMP_TESTS` добавляет к сборке библиотеки сборку нескольких тестовых примеров,
проводящих вычисления с использованием библиотеки [libgmp](http://gmplib.org).
Данные тестовые примеры сравнивают корректность реализации
арифметических операций с большими целыми числами
для библиотеки `libakrypt` и библиотеки `libgmp`.
После сборки тестовых примеров становится доступной команда, запускающая процесс тестирования.


    make test

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `OFF`.

### LIBAKRYPT_HTML_DOC

Опция `LIBAKRYPT_HTML_DOC` добавляет возможность сборки документации в формате html.
После сборки библиотеки становится доступной команда, запускающая процесс
сборки документации.


    make html

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `OFF`.


### LIBAKRYPT_INTERNAL_TESTS

Опция `LIBAKRYPT_INTERNAL_TESTS` добавляет к сборке библиотеки сборку нескольких тестовых примеров,
напрямую использующих неэкспортируемые функции библиотеки. Данная возможность доступна только при сборке
статической версии библиотеки.
После сборки тестовых примеров становится доступной команда, запускающая процесс тестирования.


    make test

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `OFF`.


### LIBAKRYPT_NETWORK
Опция `LIBAKRYPT_PDF_DOC` добавляет к библиотеке функции для работы с сокетами.
Данные функции предоставляют общий интерфейс, не зависящий от используемой операционной системы.

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `OFF`.


### LIBAKRYPT_PDF_DOC

Опция `LIBAKRYPT_PDF_DOC` добавляет возможность сборки документации в формате pdf.
После сборки тестовых примеров становится доступной команда, запускающая процесс
сборки документации.


    make pdf

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `OFF`.


### LIBAKRYPT_SHARED_LIB

Опция `LIBAKRYPT_SHARED_LIB` устанавливает, нужно ли собирать динамическую версию библиотеки.

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `OFF`.


### LIBAKRYPT_STATIC_LIB

Опция `LIBAKRYPT_STATIC_LIB` устанавливает, нужно ли собирать статическую версию библиотеки.

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `ON`.

### LIBAKRYPT_TLS_13

Опция `LIBAKRYPT_TLS_13` указывает на необходимость сборки
библиотеки с использованием протокола tls версии 1.3.

Включенное значение опции автоматически приводит к
включению опций `LIBAKRYPT_CRYPTO_FUNCTIONS` и `LIBAKRYPT_NETWORK`.

Принимаемые значения: `ON`, `OFF`.

Значение по-умолчанию: `OFF`.