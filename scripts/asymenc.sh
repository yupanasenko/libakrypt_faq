# /bin/bash
#
# Пример иллюстрирует процесс создания ключей и шифрования данных 
# с использованием асимметричного алгоритма шифрования
#
# 1. Создаем ключи центра сертификации
aktool k -nt sign512 --curve ec512b --ca -o ca.key --outpass z12Ajq --op ca.crt --to certificate --id "Root CA"
#
# 2. Создаем ключевую пару для получателя сообщений
aktool k -nt sign256 -o user.key --outpass 1Qlm!21 --op user_request.csr --to pem --id "Local User"
aktool k -v user_request.csr
aktool k -s user.key
#
# 3. Вырабатываем сертификат пользователя 
aktool k -c user_request.csr --key-encipherment --secret-key-number `aktool k --show-number user.key` --ca-key ca.key --inpass z12Ajq --ca-cert ca.crt --op user.crt --to pem
aktool k -v user.crt --ca-cert ca.crt --verbose
#
# 4. Вырабатываем данные для тестирования
dd if=/dev/zero of=file bs=1M count=256
echo "Значение хешкода для исходного тестового файла"
aktool i file
#
# 5. Приступаем к шифрованию
#aktool e file --outpass jQa6 --fr --cert user.crt --ca-cert ca.crt -o file01.bin
## выводим информацию о зашифрованном файле
#echo; echo "Значение хешкода для зашифрованного файла"
#aktool i file01.bin
#ls -la file01.bin
#xxd -g1 -l256 file01.bin
#
# 9. Теперь те же исходные данные, но с предварительным сжатием
echo; echo "Создаем ключ для шифрования контейнера"
aktool k -nt magma -o magma256.key --outpass mag13
#
echo; echo "Зашифровываем данные на открытом ключе получателя"
aktool e file --bz2 --ck magma256.key --ckpass mag13 --cert user.crt --ca-cert ca.crt -o file02.bin
# выводим информацию о зашифрованном файле
echo; echo "Значение хешкода для зашифрованного файла"
aktool i file02.bin
ls -la file02.bin

#
# В завершение теста, удаляем созданные файлы
# rm -f ca.key ca.crt user_request.csr user.key user.crt file file01.bin file02.bin

