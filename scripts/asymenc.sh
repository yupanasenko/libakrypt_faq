# -------------------------------------------------------------------------------------
# /bin/bash
#
# Пример иллюстрирует процесс создания ключевой системы и последующего шифрования
# данных с использованием асимметричного алгоритма шифрования
# -------------------------------------------------------------------------------------
#
# 1. Создаем ключи центра сертификации
aktool k -nt sign512 --curve ec512b --ca -o ca.key --outpass z12Ajq --op ca.crt --to certificate --id "Root CA" --days 1
#
# 2. Создаем ключевую пару для получателя сообщений
aktool k -nt sign256 -o user.key --outpass 1Qlm21u --op user_request.csr --to pem --id "Local User"
aktool k -v user_request.csr
aktool k -s user.key
#
# 3. Вырабатываем сертификат пользователя 
#    (с добавлением расширения, содержащего номер секретного ключа)
aktool k -c user_request.csr --key-encipherment --secret-key-number `aktool k --show-number user.key` --ca-key ca.key --inpass z12Ajq --ca-cert ca.crt --op user.crt --to pem
aktool k -v user.crt --ca-cert ca.crt --verbose
#
# 4. Вырабатываем данные для тестирования
dd if=/dev/zero of=file bs=1M count=32
aktool i file -o results.streebog
#
# -------------------------------------------------------------------------------------
# Первый эксперимент, используется пароль для шифрования контейнера,
# разбиение на случайные фрагменты,
# алгоритм шифрования Кузнечик в режиме MGM (по-умолчанию)
# -------------------------------------------------------------------------------------
echo; echo "Эксперимент N1. Простое шифрование."
aktool e file --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file01.bin --delete-source
#
# выводим информацию о зашифрованном файле
echo; echo "Значение хешкода для зашифрованного файла"
aktool i file01.bin
ls -la file01.bin
#
# Расшифрование исходных данных
aktool d file01.bin --inpass jQa6 --key user.key --keypass 1Qlm21u --delete-source
aktool i -c results.streebog --dont-show-stat
#
# -------------------------------------------------------------------------------------
# Второй эксперимент, используется предварительное сжатие данных,
# заранее созданный ключ для шифрования контейнера,
# алгоритм шифрования Магма в режиме MGM
# -------------------------------------------------------------------------------------
echo; echo "Создаем ключ для шифрования контейнера"
aktool k -nt hmac-streebog512 -o psk.512 --outpass mag13s
#
echo; echo "Экперимент N2. Шифрование с использованием ключа контейнера и предварительным сжатием"
aktool e file -m mgm-magma --bz2 --ck psk.512 --ckpass mag13s --cert user.crt --ca-cert ca.crt --delete-source -o file02.bin
# выводим информацию о зашифрованном файле
echo; echo "Значение хешкода для зашифрованного файла"
aktool i file02.bin
ls -la file02.bin
#
echo; echo "Расшифрование."
aktool d file02.bin --ck psk.512 --ckpass mag13s --key user.key --keypass 1Qlm21u --delete-source
aktool i -c results.streebog --dont-show-stat
#
# -------------------------------------------------------------------------------------
# Третий эксперимент, тестирующий различные алгоритмы шифрования
# -------------------------------------------------------------------------------------
echo; echo "Эксперимент N3. Многократное шифрование в следующих режимах:"
aktool s --oid aead | grep aead
aktool e file -m ctr-cmac-kuznechik --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file03.bin --delete-source
aktool e file03.bin -m ctr-cmac-magma --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file04.bin --delete-source
aktool e file04.bin -m mgm-magma --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file05.bin --delete-source
aktool e file05.bin -m mgm-kuznechik --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file06.bin --delete-source
aktool e file06.bin -m xtsmac-magma --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file07.bin --delete-source
aktool e file07.bin -m xtsmac-kuznechik --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file08.bin --delete-source
#
echo; echo "Процесс зашифрования завершен."
aktool i file08.bin
ls -la *.bin
#
# Поскольку мы знаем имена файлов, которые будут расшифрованы,
# то указываем их в командной строке, несмотря на то, что они пока еще не существуют
# опция --delete-source удалает файлы сразу после их расшифрования
echo; echo "Расшифрование."
aktool d file08.bin file07.bin file06.bin file05.bin file04.bin file03.bin --inpass jQa6 --key user.key --keypass 1Qlm21u --delete-source
aktool i file
aktool i -c results.streebog --dont-show-stat
#
# -------------------------------------------------------------------------------------
#  В завершение экспериментов, удаляем созданные временные файлы
# -------------------------------------------------------------------------------------
rm -f ca.key ca.crt user_request.csr user.key user.crt psk.512 file results.streebog
