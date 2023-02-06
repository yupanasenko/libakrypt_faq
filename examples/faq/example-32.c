#include <stdio.h>
#include <libakrypt.h>
#include <libakrypt-base.h>

void encrypt(char* src, int* pos, char* dst, size_t* mem_pos) {
	// так как массив должен заканчиваться \0 то выделяем на один символ больше(здесь размер in должен быть 3)
	ak_uint8 in[4];
	// копируем 3 входных символа с нужной позиции в наш массив in
	strncpy((char*)in, src + *pos, 3);
	// добавляем в конец \0 чтобы функция ak_base64_encodeblock понимала где конец строки
	in[3] = '\0';
	// увеличиваем текущую позицию во входной строке
	*pos += 3;

	// заводим выходной массив
	ak_uint8 out[4];
	// кодируем
	ak_base64_encodeblock(in, out, 3);

	// ak_uint8 - unsigned char
	// std::string хранит char
	// приводим типы, чтобы записать наш выходной массив в std::string
	memcpy(dst + *mem_pos, (char*)out, 4);
	*mem_pos += 4;
}

void encrypt_size_1(char *src, int *pos, char *dst, size_t *mem_pos) {
	// так как массив должен заканчиваться \0 то выделяем на один символ больше(здесь размер in должен быть 1)
	ak_uint8 in[2];

	// копируем 1 входной символ с нужной позиции в наш массив in
	strncpy((char *)in, src + *pos, 1);
	// добавляем в конец \0 чтобы функция ak_base64_encodeblock понимала где конец строки
	in[1] = '\0';
	// увеличиваем текущую позицию во входной строке
	*pos += 1;

	// заводим выходной массив
	ak_uint8 out[4];
	// кодируем
	ak_base64_encodeblock(in, out, 1);

	// ak_uint8 - unsigned char
	// выходной массив dst хранит char
	// приводим типы, чтобы добавить полученные данные в наш выходной массив
	memcpy(dst + *mem_pos, (char *)out, 4);
	*mem_pos += 2;
}

void encrypt_size_2(char* src, int* pos, char* dst, size_t* mem_pos) {
	// так как массив должен заканчиваться \0 то выделяем на один символ больше(здесь размер in должен быть 2)
	ak_uint8 in[3];

	// копируем 3 входных символа с нужной позиции в наш массив in
	strncpy((char*)in, src + *pos, 2);
	// добавляем в конец \0 чтобы функция ak_base64_encodeblock понимала где конец строки
	in[2] = '\0';
	// увеличиваем текущую позицию во входной строке
	*pos += 2;

	// заводим выходной массив
	ak_uint8 out[4];
	// кодируем
	ak_base64_encodeblock(in, out, 2);

	// ak_uint8 - unsigned char
	// выходной массив dst хранит char
	// приводим типы, чтобы добавить полученные данные в наш выходной массив
	memcpy(dst + *mem_pos, (char*)out, 4);
	*mem_pos += 3;
}

size_t calc_size(size_t size) {
	size_t ret = 0;

	while (size >= 3) {
		ret += 4;
		size -= 3;
	}

	while (size >= 2) {
		ret += 4;
		size -= 2;
	}

	if (1 == size)
		ret += 4;

	return ret;
}

char *encrypt_string(char* str) {
	// текущая позиция в строке
	int pos = 0;
	size_t mem_pos = 0;
	size_t size = strlen(str);
	size_t out_size = calc_size(size);
	char *ret = malloc(out_size + 1ull);
	// делаем цикл пока не дойдем до конца строки
	// после каждого действия добавляем полученный результат в конец выходной строки(std::string ret)
	// pos нужен для хождения по строке, так как размер может быть каким угодно
	while(size - pos) {
		// смотрим размер
		switch(size - pos) {
		// если размер входной строки 0(такого не может быть, но нужно написать для удобства), то выходим
		case 0:
			break;
		// если размер 1, то вызываем функцию кодирования для строки размером 1
		case 1:
			encrypt_size_1(str, &pos, ret, &mem_pos);
			break;
		// если размер 2, то вызываем функцию кодирования для строки размером 2
		case 2:
			encrypt_size_2(str, &pos, ret, &mem_pos);
			break;
		// для всех остальных размеров
		default:
			encrypt(str, &pos, ret, &mem_pos);
			break;
		}
	}

	ret[out_size] = '\0';
	return ret;
}

// для английских букв работает
// для русских и тд не особо понятно как оно должно работать, если надо - сделаем
int main(int argc, char *argv[]) 
{
	if( ak_libakrypt_create( NULL ) != ak_true ) {
		/* инициализация выполнена не успешно, следовательно, выходим из программы */
		ak_libakrypt_destroy();
		return EXIT_FAILURE;
	}

	// если нам не дали входных аргументов то просто выходим и печатаем no input data
	if (argc < 1) {
		printf("No input data");
		return 0;
	}

	// делаем цикл по всем переданным аргументам
	for (int i = 1; i < argc; ++i) {
		printf("Text: %s\n", argv[i]);
		char *ret = encrypt_string(argv[i]);
		printf("\tBase64: %s\n\n", ret);
		// освобождаем ret
		free(ret);
	}
	
 	ak_libakrypt_destroy();
 	return EXIT_SUCCESS;
}
