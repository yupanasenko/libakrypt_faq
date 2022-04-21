##########################################################################
#!/bin/csh
# проверка способов выработки и проверки контрольных сумм и имитовставок
#
set AKTOOL=./aktool
#
# может использоваться, например, так
# export AKTOOL="qemu-mips64 -L /usr/mips64-linux-gnuabi64/ ./aktool"
##########################################################################
#
#
echo "Тестируем функции хэширования"
${AKTOOL} i * --tag -o result.streebog256 --audit-file /dev/null
echo "Ok (Стрибог256)";
cat result.streebog256
${AKTOOL} i -c result.streebog256 --ignore-errors --audit-file /dev/null
#
${AKTOOL} i -a streebog512 -p "*.s*" . -o result.streebog512 --audit-file /dev/null
echo "Ok (Стрибог512)";
cat result.streebog512
${AKTOOL} i -c result.streebog512 -a streebog512 --ignore-errors --audit-file /dev/null
#
#
echo; echo "Тестируем алгоритмы hmac"
${AKTOOL} k -nt hmac-streebog256 -o hmac256.key --outpass 132a --audit-file /dev/null
echo;
${AKTOOL} i --key hmac256.key --inpass 132a --tag . -o result.hmac-streebog256 --audit-file /dev/null
cat result.hmac-streebog256
${AKTOOL} i -c result.hmac-streebog256 --key hmac256.key --inpass 132a --audit-file dev/null
echo;
#
#
${AKTOOL} k -nt hmac-streebog512 -o hmac512.key --outpass 132a --audit-file /dev/null
echo;
${AKTOOL} i --key hmac512.key --inpass 132a * -o result.hmac-streebog512 --audit-file /dev/null
cat result.hmac-streebog512
${AKTOOL} i -c result.hmac-streebog512 --key hmac512.key --inpass 132a --audit-file /dev/null
echo;
#
#
echo; echo "Тестируем алгоритмы выработки имитовставки с использованием шифра Магма"
${AKTOOL} k -nt magma -o magma.key --outpass 123 --audit-file /dev/null
${AKTOOL} i --key magma.key -m cmac-magma --inpass 123 * -o result.magma --audit-file /dev/null
echo
cat result.magma
${AKTOOL} i -c result.magma --key magma.key -m cmac-magma --inpass 123 --audit-file /dev/null
echo
#
#
echo; echo "Тестируем алгоритмы выработки имитовставки с использованием шифра Кузнечик"
${AKTOOL} k -nt kuznechik -o kuznechik.key --outpass 123 --audit-file /dev/null
${AKTOOL} i --key kuznechik.key -m cmac-kuznechik --inpass 123 --tag * -o result.kuznechik --audit-file /dev/null
echo
cat result.kuznechik
${AKTOOL} i -c result.kuznechik --key kuznechik.key -m cmac-kuznechik --inpass 123 --dont-show-stat --audit-file /dev/null
#
#
rm -f magma.key kuznechik.key hmac256.key hmac512.key
rm -f result.*
echo "Тест пройден"
