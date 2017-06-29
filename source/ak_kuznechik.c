/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2008 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_kuznechik.c                                                                                */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_skey.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
 #include <emmintrin.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Нелинейная перестановка алгоритма Кузнечик (ГОСТ Р 34.12-2015) */
 const static ak_uint8 pi[256] = {
   0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
   0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
   0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
   0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
   0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
   0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
   0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
   0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
   0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
   0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
   0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
   0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
   0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
   0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
   0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
   0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
 };

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Обратная нелинейная перестановка алгоритма Кузнечик (ГОСТ Р 34.12-2015) */
 const static ak_uint8 pinv[256] = {
   0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
   0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
   0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4, 0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
   0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9, 0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
   0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B, 0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
   0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F, 0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
   0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
   0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
   0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
   0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
   0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0, 0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
   0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D, 0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
   0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67, 0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
   0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88, 0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
   0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
   0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
 };

/* ---------------------------------------------------------------------------------------------- */
/*! \brief 16-я степень сопровождающей матрицы линейного регистра сдвига, определяемого в
    алгоритме Кузнечик (ГОСТ Р 34.12-2015). */
/* ---------------------------------------------------------------------------------------------- */
 const static ak_uint8 L[16][16] = {
  { 0x01,0x94,0x20,0x85,0x10,0xC2,0xC0,0x01,0xFB,0x01,0xC0,0xC2,0x10,0x85,0x20,0x94 },
  { 0x94,0xA5,0x3C,0x44,0xD1,0x8D,0xB4,0x54,0xDE,0x6F,0x77,0x5D,0x96,0x74,0x2D,0x84 },
  { 0x84,0x64,0x48,0xDF,0xD3,0x31,0xA6,0x30,0xE0,0x5A,0x44,0x97,0xCA,0x75,0x99,0xDD },
  { 0xDD,0x0D,0xF8,0x52,0x91,0x64,0xFF,0x7B,0xAF,0x3D,0x94,0xF3,0xD9,0xD0,0xE9,0x10 },
  { 0x10,0x89,0x48,0x7F,0x91,0xEC,0x39,0xEF,0x10,0xBF,0x60,0xE9,0x30,0x5E,0x95,0xBD },
  { 0xBD,0xA2,0x48,0xC6,0xFE,0xEB,0x2F,0x84,0xC9,0xAD,0x7C,0x1A,0x68,0xBE,0x9F,0x27 },
  { 0x27,0x7F,0xC8,0x98,0xF3,0x0F,0x54,0x08,0xF6,0xEE,0x12,0x8D,0x2F,0xB8,0xD4,0x5D },
  { 0x5D,0x4B,0x8E,0x60,0x01,0x2A,0x6C,0x09,0x49,0xAB,0x8D,0xCB,0x14,0x87,0x49,0xB8 },
  { 0xB8,0x6E,0x2A,0xD4,0xB1,0x37,0xAF,0xD4,0xBE,0xF1,0x2E,0xBB,0x1A,0x4E,0xE6,0x7A },
  { 0x7A,0x16,0xF5,0x52,0x78,0x99,0xEB,0xD5,0xE7,0xC4,0x2D,0x06,0x17,0x62,0xD5,0x48 },
  { 0x48,0xC3,0x02,0x0E,0x58,0x90,0xE1,0xA3,0x6E,0xAF,0xBC,0xC5,0x0C,0xEC,0x76,0x6C },
  { 0x6C,0x4C,0xDD,0x65,0x01,0xC4,0xD4,0x8D,0xA4,0x02,0xEB,0x20,0xCA,0x6B,0xF2,0x72 },
  { 0x72,0xE8,0x14,0x07,0x49,0xF6,0xD7,0xA6,0x6A,0xD6,0x11,0x1C,0x0C,0x10,0x33,0x76 },
  { 0x76,0xE3,0x30,0x9F,0x6B,0x30,0x63,0xA1,0x2B,0x1C,0x43,0x68,0x70,0x87,0xC8,0xA2 },
  { 0xA2,0xD0,0x44,0x86,0x2D,0xB8,0x64,0xC1,0x9C,0x89,0x48,0x90,0xDA,0xC6,0x20,0x6E },
  { 0x6E,0x4D,0x8E,0xEA,0xA9,0xF6,0xBF,0x0A,0xF3,0xF2,0x8E,0x93,0xBF,0x74,0x98,0xCF }
};

/* ---------------------------------------------------------------------------------------------- */
/*! \brief 16-я степень обратной матрицы к сопровождающей матрице линейного регистра сдвига,
     определяемого в алгоритме Кузнечик (ГОСТ Р 34.12-2015). */
/* ---------------------------------------------------------------------------------------------- */
 const static ak_uint8 Linv[16][16]  = {
 { 0xCF, 0x98, 0x74, 0xBF, 0x93, 0x8E, 0xF2, 0xF3, 0x0A, 0xBF, 0xF6, 0xA9, 0xEA, 0x8E, 0x4D, 0x6E },
 { 0x6E, 0x20, 0xC6, 0xDA, 0x90, 0x48, 0x89, 0x9C, 0xC1, 0x64, 0xB8, 0x2D, 0x86, 0x44, 0xD0, 0xA2 },
 { 0xA2, 0xC8, 0x87, 0x70, 0x68, 0x43, 0x1C, 0x2B, 0xA1, 0x63, 0x30, 0x6B, 0x9F, 0x30, 0xE3, 0x76 },
 { 0x76, 0x33, 0x10, 0x0C, 0x1C, 0x11, 0xD6, 0x6A, 0xA6, 0xD7, 0xF6, 0x49, 0x07, 0x14, 0xE8, 0x72 },
 { 0x72, 0xF2, 0x6B, 0xCA, 0x20, 0xEB, 0x02, 0xA4, 0x8D, 0xD4, 0xC4, 0x01, 0x65, 0xDD, 0x4C, 0x6C },
 { 0x6C, 0x76, 0xEC, 0x0C, 0xC5, 0xBC, 0xAF, 0x6E, 0xA3, 0xE1, 0x90, 0x58, 0x0E, 0x02, 0xC3, 0x48 },
 { 0x48, 0xD5, 0x62, 0x17, 0x06, 0x2D, 0xC4, 0xE7, 0xD5, 0xEB, 0x99, 0x78, 0x52, 0xF5, 0x16, 0x7A },
 { 0x7A, 0xE6, 0x4E, 0x1A, 0xBB, 0x2E, 0xF1, 0xBE, 0xD4, 0xAF, 0x37, 0xB1, 0xD4, 0x2A, 0x6E, 0xB8 },
 { 0xB8, 0x49, 0x87, 0x14, 0xCB, 0x8D, 0xAB, 0x49, 0x09, 0x6C, 0x2A, 0x01, 0x60, 0x8E, 0x4B, 0x5D },
 { 0x5D, 0xD4, 0xB8, 0x2F, 0x8D, 0x12, 0xEE, 0xF6, 0x08, 0x54, 0x0F, 0xF3, 0x98, 0xC8, 0x7F, 0x27 },
 { 0x27, 0x9F, 0xBE, 0x68, 0x1A, 0x7C, 0xAD, 0xC9, 0x84, 0x2F, 0xEB, 0xFE, 0xC6, 0x48, 0xA2, 0xBD },
 { 0xBD, 0x95, 0x5E, 0x30, 0xE9, 0x60, 0xBF, 0x10, 0xEF, 0x39, 0xEC, 0x91, 0x7F, 0x48, 0x89, 0x10 },
 { 0x10, 0xE9, 0xD0, 0xD9, 0xF3, 0x94, 0x3D, 0xAF, 0x7B, 0xFF, 0x64, 0x91, 0x52, 0xF8, 0x0D, 0xDD },
 { 0xDD, 0x99, 0x75, 0xCA, 0x97, 0x44, 0x5A, 0xE0, 0x30, 0xA6, 0x31, 0xD3, 0xDF, 0x48, 0x64, 0x84 },
 { 0x84, 0x2D, 0x74, 0x96, 0x5D, 0x77, 0x6F, 0xDE, 0x54, 0xB4, 0x8D, 0xD1, 0x44, 0x3C, 0xA5, 0x94 },
 { 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01 }
};

/* ---------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
 static __m128i kuz_mat_enc128[16][256];
 static __m128i kuz_mat_dec128[16][256];
#else
 static ak_uint128 kuz_mat_enc128[16][256];
 static ak_uint128 kuz_mat_dec128[16][256];
#endif

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает два элемента конечного поля \f$\mathbb F_{2^8}\f$, определенного
     согласно ГОСТ Р 34.12-2015.                                                                  */
/* ---------------------------------------------------------------------------------------------- */
 static ak_uint8 ak_kuznechik_mul_gf256( ak_uint8 x, ak_uint8 y )
{
  ak_uint8 z = 0;
  while (y) {
    if (y & 1) z ^= x;
      x = (x << 1) ^ (x & 0x80 ? 0xC3 : 0x00);
      y >>= 1;
  }
 return z;
}

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует линейное преобразование L согласно ГОСТ Р 34.12-2015
    (шестнадцать тактов работы линейного регистра сдвига).                                        */
/* ---------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_l1( ak_uint128 *w  )
{
  int i = 0, j = 0;
  const ak_uint8 kuz_lvec[16] = {
   0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94
  };

  for( j = 0; j < 16; j++ ) {
     ak_uint8 z = w->b[0];
     for( i = 1; i < 16; i++ ) {
        w->b[i-1] = w->b[i];
        z ^= ak_kuznechik_mul_gf256( w->b[i], kuz_lvec[i] );
     }
     w->b[15] = z;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает вектор w на матрицу D, результат помещается в вектор x.                */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_matrix_mul_vector( const ak_uint8 D[16][16], ak_uint128 *w, ak_uint128* x )
{
  int i = 0, j = 0;
  for( i = 0; i < 16; i++ ) {
    ak_uint8 z = ak_kuznechik_mul_gf256( D[i][0], w->b[0] );
    for( j = 1; j < 16; j++ ) z ^= ak_kuznechik_mul_gf256( D[i][j], w->b[j] );
    x->b[i] = z;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция инициализирует таблицы, необходимые для быстрой работы блочного алгоритма
    шифрования Кузнечик (ГОСТ Р 34.12-2015).                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_kuznechik_init_tables( void )
{
  int i, j, l;

#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
  ak_uint128 x, y;
  for( i = 0; i < 16; i++ ) {
     for( j = 0; j < 256; j++ ) {
        x.q[0] = 0; x.q[1] = 0;
        y.q[0] = 0; y.q[1] = 0;

        for( l = 0; l < 16; l++ ) {
           x.b[l] = ak_kuznechik_mul_gf256( L[l][i], pi[j] );
           y.b[l] = ak_kuznechik_mul_gf256( Linv[l][i], pinv[j] );
        }
      #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
        kuz_mat_enc128[i][j] = _mm_set_epi64x(x.q[1], x.q[0]); // *((__m128i *) &x);
        kuz_mat_dec128[i][j] = _mm_set_epi64x(y.q[1], y.q[0]); // *((__m128i *) &y);
      #else
        kuz_mat_enc128[i][j].m128i_u64[0] = x.q[0]; kuz_mat_enc128[i][j].m128i_u64[1] = x.q[1];
        kuz_mat_dec128[i][j].m128i_u64[0] = y.q[0]; kuz_mat_dec128[i][j].m128i_u64[1] = y.q[1];
      #endif
     }
  }
#else
  for( i = 0; i < 16; i++ ) {
      for( j = 0; j < 256; j++ ) {
         for( l = 0; l < 16; l++ ) {
            kuz_mat_enc128[i][j].b[l] = ak_kuznechik_mul_gf256( L[l][i], pi[j] );
            kuz_mat_dec128[i][j].b[l] = ak_kuznechik_mul_gf256( Linv[l][i], pinv[j] );
         }
      }
  }
#endif
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Раундовые ключи алгоритма Кузнечик. */
 struct kuznechik_expanded_key {
  ak_uint128 k[10];
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура с внутренними данными секретного ключа алгоритма Кузнечик. */
 struct kuznechik_ctx {
  /*! \brief раундовые ключи для алгоритма зашифрования */
  struct kuznechik_expanded_key encryptkey;
  /*! \brief раундовые ключи для алгоритма расшифрования */
  struct kuznechik_expanded_key decryptkey;
  /*! \brief маски для раундовых ключей алгоритма зашифрования */
  struct kuznechik_expanded_key encryptmask;
  /*! \brief маски для раундовых ключей алгоритма расшифрования */
  struct kuznechik_expanded_key decryptmask;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую развернутыми ключами алгоритма Кузнечик. */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_delete_keys( ak_skey key )
{
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if( key == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to secret key" );
  if( key->data == NULL ) return ak_error_message( ak_error_null_pointer,
                                              __func__ , "using a null pointer to internal data" );
 /* теперь очистка и освобождение памяти */
  if(( error = ak_random_ptr( key->generator,
                                    key->data, sizeof( struct kuznechik_ctx ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect wiping an internal data" );
    memset( key->data, 0, sizeof ( struct kuznechik_ctx ));
  }
  if( key->data != NULL ) {
    free( key->data );
    key->data = NULL;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует развертку ключей для алгоритма Кузнечик. */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_schedule_keys( ak_skey skey )
{
  ak_uint128 a0, a1, t, z0, z1;
  struct kuznechik_expanded_key *ekey = NULL, *mkey = NULL;
  struct kuznechik_expanded_key *dkey = NULL, *xkey = NULL;
  int i = 0, j = 0, l = 0, idx = 0, kdx = 1;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( skey->generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                              "using undefined random generator" );
 /* проверяем целостность ключа */
  if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                __func__ , "using key with wrong integrity code" );
 /* готовим память для переменных */
  if(( skey->data = malloc( sizeof( struct kuznechik_ctx ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                                             "wrong allocation of internal data" );
 /* получаем указатели на области памяти */
  ekey = &(( struct kuznechik_ctx * ) skey->data )->encryptkey;
  mkey = &(( struct kuznechik_ctx * ) skey->data )->encryptmask;
  dkey = &(( struct kuznechik_ctx * ) skey->data )->decryptkey;
  xkey = &(( struct kuznechik_ctx * ) skey->data )->decryptmask;

 /* вырабатываем маски */
  ak_random_ptr( skey->generator, mkey, sizeof( struct kuznechik_expanded_key ));
  ak_random_ptr( skey->generator, xkey, sizeof( struct kuznechik_expanded_key ));

 /* только теперь выполняем алгоритм развертки ключа */
  a0.q[0] = (( ak_uint128 *) skey->key.data )[0].q[0] ^ mkey->k[1].q[0];
  ekey->k[1].q[0] = ( a0.q[0] ^= (( ak_uint128 *) skey->mask.data )[0].q[0] );
  a0.q[1] = (( ak_uint128 *) skey->key.data )[0].q[1] ^ mkey->k[1].q[1];
  ekey->k[1].q[1] = ( a0.q[1] ^= (( ak_uint128 *) skey->mask.data )[0].q[1] );

  a1.q[0] = (( ak_uint128 *) skey->key.data )[1].q[0] ^ mkey->k[0].q[0];
  ekey->k[0].q[0] = ( a1.q[0] ^= (( ak_uint128 *) skey->mask.data )[1].q[0] );
  a1.q[1] = (( ak_uint128 *) skey->key.data )[1].q[1] ^ mkey->k[0].q[1];
  ekey->k[0].q[1] = ( a1.q[1] ^= (( ak_uint128 *) skey->mask.data )[1].q[1] );

  dkey->k[0].q[0] = a1.q[0] ^ xkey->k[0].q[0];
  dkey->k[0].q[0] ^= mkey->k[0].q[0];
  dkey->k[0].q[1] = a1.q[1] ^ xkey->k[0].q[1];
  dkey->k[0].q[1] ^= mkey->k[0].q[1];

  ak_kuznechik_matrix_mul_vector( Linv, &a0, &dkey->k[1] );
  ak_kuznechik_matrix_mul_vector( Linv, &mkey->k[1], &t );

  dkey->k[1].q[0] ^= xkey->k[1].q[0]; dkey->k[1].q[1] ^= xkey->k[1].q[1];
  dkey->k[1].q[0] ^= t.q[0]; dkey->k[1].q[1] ^= t.q[1];

 /* к этому моменту величины a0 и a1 содержат замаскированные значения */
  z0.q[0] = mkey->k[1].q[0]; z0.q[1] = mkey->k[1].q[1];
  z1.q[0] = mkey->k[0].q[0]; z1.q[1] = mkey->k[0].q[1];

  for( j = 0; j < 4; j++ ) {
     for( i = 0; i < 8; i++ ) {
        t.q[0] = ++idx; /* вычисляем константу алгоритма согласно ГОСТ Р 34.12-2015 */
        t.q[1] = 0;
        ak_kuznechik_l1( &t );

        t.q[0] ^= a1.q[0]; t.q[0] ^= z1.q[0];
        t.q[1] ^= a1.q[1]; t.q[1] ^= z1.q[1];

        for( l = 0; l < 16; l++ ) t.b[l] = pi[t.b[l]];
        ak_kuznechik_l1( &t );

        t.q[0] ^= a0.q[0]; t.q[0] ^= z0.q[0];
        t.q[1] ^= a0.q[1]; t.q[1] ^= z0.q[1];

        a0.q[0] = a1.q[0]; a0.q[1] = a1.q[1];
        a1.q[0] = t.q[0];  a1.q[1] = t.q[1];

        z0.q[0] = z1.q[0]; z1.q[0] = 0;
        z0.q[1] = z1.q[1]; z1.q[1] = 0;
     }

     kdx++;
     ekey->k[kdx].q[0] = a1.q[0] ^ mkey->k[kdx].q[0];
     ekey->k[kdx].q[1] = a1.q[1] ^ mkey->k[kdx].q[1];
     ak_kuznechik_matrix_mul_vector( Linv, &a1, &dkey->k[kdx] );
     dkey->k[kdx].q[0] ^= xkey->k[kdx].q[0];
     dkey->k[kdx].q[1] ^= xkey->k[kdx].q[1];

     kdx++;
     ekey->k[kdx].q[0] = a0.q[0] ^ mkey->k[kdx].q[0];
     ekey->k[kdx].q[1] = a0.q[1] ^ mkey->k[kdx].q[1];
     ak_kuznechik_matrix_mul_vector( Linv, &a0, &dkey->k[kdx] );
     dkey->k[kdx].q[0] ^= xkey->k[kdx].q[0];
     dkey->k[kdx].q[1] ^= xkey->k[kdx].q[1];
  }
  ak_random_ptr( skey->generator, &a0, 16 );
  ak_random_ptr( skey->generator, &a1, 16 );
  ak_random_ptr( skey->generator, &t, 16 );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция изменяет маску ключа алгоритма блочного шифрования Кузнечик.                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_kuznechik_remask_xor( ak_skey skey )
{
  size_t idx = 0;
  ak_uint64 mask[20], *kptr = NULL, *mptr = NULL;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( skey->key.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                    "using undefined key buffer" );
  if( skey->key.size != 32 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                           "key length is wrong" );
  if( skey->mask.data == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                   "using undefined mask buffer" );
 /* перемаскируем ключ */
  if(( error = ak_random_ptr( skey->generator, mask, skey->key.size )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong generation random key mask");

  for( idx = 0; idx < 4; idx++ ) {
     ((ak_uint64 *) skey->key.data)[idx] ^= mask[idx];
     ((ak_uint64 *) skey->key.data)[idx] ^= ((ak_uint64 *) skey->mask.data)[idx];
     ((ak_uint64 *) skey->mask.data)[idx] = mask[idx];
  }

 /* перемаскируем раундовые ключи зашифрования */
  if(( error = ak_random_ptr( skey->generator, mask, 20*sizeof( ak_uint64 ))) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong generation random key mask");

  kptr = (ak_uint64 *) ( &(( struct kuznechik_ctx *)skey->data)->encryptkey );
  mptr = (ak_uint64 *) ( &(( struct kuznechik_ctx *)skey->data)->encryptmask );
  for( idx = 0; idx < 20; idx++ ) {
     kptr[idx] ^= mask[idx];
     kptr[idx] ^= mptr[idx];
     mptr[idx] = mask[idx];
  }

 /* перемаскируем раундовые ключи расшифрования */
  if(( error = ak_random_ptr( skey->generator, mask, 20*sizeof( ak_uint64 ))) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong generation random key mask");

  kptr = (ak_uint64 *) ( &(( struct kuznechik_ctx *)skey->data)->decryptkey );
  mptr = (ak_uint64 *) ( &(( struct kuznechik_ctx *)skey->data)->decryptmask );
  for( idx = 0; idx < 20; idx++ ) {
     kptr[idx] ^= mask[idx];
     kptr[idx] ^= mptr[idx];
     mptr[idx] = mask[idx];
  }

 /* удаляем старое */
  memset( mask, 0, 20*sizeof( ak_uint64 ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_encrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  struct kuznechik_expanded_key *ekey = &(( struct kuznechik_ctx * ) skey->data )->encryptkey;
  struct kuznechik_expanded_key *mkey = &(( struct kuznechik_ctx * ) skey->data )->encryptmask;

#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
  __m128i z, x = *((__m128i *) in);

  for( i = 0; i < 9; i++ ) {
   #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
     x = _mm_xor_si128( x, _mm_set_epi64x( ekey->k[i].q[1], ekey->k[i].q[0] ));
     x = _mm_xor_si128( x, _mm_set_epi64x( mkey->k[i].q[1], mkey->k[i].q[0] ));
   #else
     z.m128i_u64[0] = ekey->k[i].q[0]; z.m128i_u64[1] = ekey->k[i].q[1]; x = _mm_xor_si128( x, z );
     z.m128i_u64[0] = mkey->k[i].q[0]; z.m128i_u64[1] = mkey->k[i].q[1]; x = _mm_xor_si128( x, z );
   #endif

     z = kuz_mat_enc128[ 0][((ak_uint8 *) &x)[ 0]];
     z = _mm_xor_si128( z, kuz_mat_enc128[ 1][((ak_uint8 *) &x)[ 1]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 2][((ak_uint8 *) &x)[ 2]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 3][((ak_uint8 *) &x)[ 3]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 4][((ak_uint8 *) &x)[ 4]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 5][((ak_uint8 *) &x)[ 5]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 6][((ak_uint8 *) &x)[ 6]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 7][((ak_uint8 *) &x)[ 7]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 8][((ak_uint8 *) &x)[ 8]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 9][((ak_uint8 *) &x)[ 9]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[10][((ak_uint8 *) &x)[10]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[11][((ak_uint8 *) &x)[11]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[12][((ak_uint8 *) &x)[12]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[13][((ak_uint8 *) &x)[13]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[14][((ak_uint8 *) &x)[14]]);
     x = _mm_xor_si128( z, kuz_mat_enc128[15][((ak_uint8 *) &x)[15]]);
  }

 #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
  x = _mm_xor_si128( x, _mm_set_epi64x( ekey->k[9].q[1], ekey->k[9].q[0] ));
  *((__m128i *) out) = _mm_xor_si128( x, _mm_set_epi64x( mkey->k[9].q[1], mkey->k[9].q[0] ));
 #else
  z.m128i_u64[0] = ekey->k[9].q[0]; z.m128i_u64[1] = ekey->k[9].q[1]; x = _mm_xor_si128( x, z );
  z.m128i_u64[0] = mkey->k[9].q[0]; z.m128i_u64[1] = mkey->k[9].q[1];
  *((__m128i *) out) = _mm_xor_si128( x, z );
 #endif

#else
  ak_uint64 t;
  ak_uint128 x;
  x.q[0] = (( ak_uint64 *) in)[0]; x.q[1] = (( ak_uint64 *) in)[1];

  for( i = 0; i < 9; i++ ) {
     x.q[0] ^= ekey->k[i].q[0]; x.q[0] ^= mkey->k[i].q[0];
     x.q[1] ^= ekey->k[i].q[1]; x.q[1] ^= mkey->k[i].q[1];

     t = kuz_mat_enc128[ 0][x.b[ 0]].q[0] ^
         kuz_mat_enc128[ 1][x.b[ 1]].q[0] ^
         kuz_mat_enc128[ 2][x.b[ 2]].q[0] ^
         kuz_mat_enc128[ 3][x.b[ 3]].q[0] ^
         kuz_mat_enc128[ 4][x.b[ 4]].q[0] ^
         kuz_mat_enc128[ 5][x.b[ 5]].q[0] ^
         kuz_mat_enc128[ 6][x.b[ 6]].q[0] ^
         kuz_mat_enc128[ 7][x.b[ 7]].q[0] ^
         kuz_mat_enc128[ 8][x.b[ 8]].q[0] ^
         kuz_mat_enc128[ 9][x.b[ 9]].q[0] ^
         kuz_mat_enc128[10][x.b[10]].q[0] ^
         kuz_mat_enc128[11][x.b[11]].q[0] ^
         kuz_mat_enc128[12][x.b[12]].q[0] ^
         kuz_mat_enc128[13][x.b[13]].q[0] ^
         kuz_mat_enc128[14][x.b[14]].q[0] ^
         kuz_mat_enc128[15][x.b[15]].q[0];

     x.q[1] = kuz_mat_enc128[ 0][x.b[ 0]].q[1] ^
         kuz_mat_enc128[ 1][x.b[ 1]].q[1] ^
         kuz_mat_enc128[ 2][x.b[ 2]].q[1] ^
         kuz_mat_enc128[ 3][x.b[ 3]].q[1] ^
         kuz_mat_enc128[ 4][x.b[ 4]].q[1] ^
         kuz_mat_enc128[ 5][x.b[ 5]].q[1] ^
         kuz_mat_enc128[ 6][x.b[ 6]].q[1] ^
         kuz_mat_enc128[ 7][x.b[ 7]].q[1] ^
         kuz_mat_enc128[ 8][x.b[ 8]].q[1] ^
         kuz_mat_enc128[ 9][x.b[ 9]].q[1] ^
         kuz_mat_enc128[10][x.b[10]].q[1] ^
         kuz_mat_enc128[11][x.b[11]].q[1] ^
         kuz_mat_enc128[12][x.b[12]].q[1] ^
         kuz_mat_enc128[13][x.b[13]].q[1] ^
         kuz_mat_enc128[14][x.b[14]].q[1] ^
         kuz_mat_enc128[15][x.b[15]].q[1];
     x.q[0] = t;
  }
  x.q[0] ^= ekey->k[9].q[0]; x.q[1] ^= ekey->k[9].q[1];
  ((ak_uint64 *)out)[0] = x.q[0] ^ mkey->k[9].q[0];
  ((ak_uint64 *)out)[1] = x.q[1] ^ mkey->k[9].q[1];
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм расшифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015).                                                  */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_kuznechik_decrypt_with_mask( ak_skey skey, ak_pointer in, ak_pointer out )
{
  int i = 0;
  struct kuznechik_expanded_key *dkey = &(( struct kuznechik_ctx * ) skey->data )->decryptkey;
  struct kuznechik_expanded_key *xkey = &(( struct kuznechik_ctx * ) skey->data )->decryptmask;

#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
  __m128i z, x = *((__m128i *) in);

  for( i = 0; i < 16; i++ ) ((ak_uint8 *) &x)[i] = pi[((ak_uint8 *) &x)[i]];
  for( i = 9; i > 0; i-- ) {
     z = kuz_mat_dec128[ 0][((ak_uint8 *) &x)[ 0]];

     z = _mm_xor_si128( z, kuz_mat_dec128[ 1][((ak_uint8 *) &x)[ 1]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 2][((ak_uint8 *) &x)[ 2]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 3][((ak_uint8 *) &x)[ 3]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 4][((ak_uint8 *) &x)[ 4]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 5][((ak_uint8 *) &x)[ 5]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 6][((ak_uint8 *) &x)[ 6]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 7][((ak_uint8 *) &x)[ 7]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 8][((ak_uint8 *) &x)[ 8]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 9][((ak_uint8 *) &x)[ 9]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[10][((ak_uint8 *) &x)[10]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[11][((ak_uint8 *) &x)[11]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[12][((ak_uint8 *) &x)[12]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[13][((ak_uint8 *) &x)[13]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[14][((ak_uint8 *) &x)[14]]);
     x = _mm_xor_si128( z, kuz_mat_dec128[15][((ak_uint8 *) &x)[15]]);
   #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
     x = _mm_xor_si128( x, _mm_set_epi64x( dkey->k[i].q[1], dkey->k[i].q[0] ));
     x = _mm_xor_si128( x, _mm_set_epi64x( xkey->k[i].q[1], xkey->k[i].q[0] ));
   #else
     z.m128i_u64[0] = dkey->k[i].q[0]; z.m128i_u64[1] = dkey->k[i].q[1]; x = _mm_xor_si128( x, z );
     z.m128i_u64[0] = xkey->k[i].q[0]; z.m128i_u64[1] = xkey->k[i].q[1]; x = _mm_xor_si128( x, z );
   #endif
  }
  for( i = 0; i < 16; i++ ) ((ak_uint8 *) &x)[i] = pinv[((ak_uint8 *) &x)[i]];

 #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
  x = _mm_xor_si128( x, _mm_set_epi64x( dkey->k[0].q[1], dkey->k[0].q[0] ));
  *((__m128i *) out) = _mm_xor_si128( x, _mm_set_epi64x( xkey->k[0].q[1], xkey->k[0].q[0] ));
 #else
  z.m128i_u64[0] = dkey->k[0].q[0]; z.m128i_u64[1] = dkey->k[0].q[1]; x = _mm_xor_si128( x, z );
  z.m128i_u64[0] = xkey->k[0].q[0]; z.m128i_u64[1] = xkey->k[0].q[1];
  *((__m128i *) out) = _mm_xor_si128( x, z );
 #endif

#else
  ak_uint64 t;
  ak_uint128 x;

  x.q[0] = (( ak_uint64 *) in)[0]; x.q[1] = (( ak_uint64 *) in)[1];
  for( i = 0; i < 16; i++ ) x.b[i] = pi[x.b[i]];
  for( i = 9; i > 0; i-- ) {
     t = kuz_mat_dec128[ 0][x.b[ 0]].q[0] ^
         kuz_mat_dec128[ 1][x.b[ 1]].q[0] ^
         kuz_mat_dec128[ 2][x.b[ 2]].q[0] ^
         kuz_mat_dec128[ 3][x.b[ 3]].q[0] ^
         kuz_mat_dec128[ 4][x.b[ 4]].q[0] ^
         kuz_mat_dec128[ 5][x.b[ 5]].q[0] ^
         kuz_mat_dec128[ 6][x.b[ 6]].q[0] ^
         kuz_mat_dec128[ 7][x.b[ 7]].q[0] ^
         kuz_mat_dec128[ 8][x.b[ 8]].q[0] ^
         kuz_mat_dec128[ 9][x.b[ 9]].q[0] ^
         kuz_mat_dec128[10][x.b[10]].q[0] ^
         kuz_mat_dec128[11][x.b[11]].q[0] ^
         kuz_mat_dec128[12][x.b[12]].q[0] ^
         kuz_mat_dec128[13][x.b[13]].q[0] ^
         kuz_mat_dec128[14][x.b[14]].q[0] ^
         kuz_mat_dec128[15][x.b[15]].q[0];

     x.q[1] = kuz_mat_dec128[ 0][x.b[ 0]].q[1] ^
         kuz_mat_dec128[ 1][x.b[ 1]].q[1] ^
         kuz_mat_dec128[ 2][x.b[ 2]].q[1] ^
         kuz_mat_dec128[ 3][x.b[ 3]].q[1] ^
         kuz_mat_dec128[ 4][x.b[ 4]].q[1] ^
         kuz_mat_dec128[ 5][x.b[ 5]].q[1] ^
         kuz_mat_dec128[ 6][x.b[ 6]].q[1] ^
         kuz_mat_dec128[ 7][x.b[ 7]].q[1] ^
         kuz_mat_dec128[ 8][x.b[ 8]].q[1] ^
         kuz_mat_dec128[ 9][x.b[ 9]].q[1] ^
         kuz_mat_dec128[10][x.b[10]].q[1] ^
         kuz_mat_dec128[11][x.b[11]].q[1] ^
         kuz_mat_dec128[12][x.b[12]].q[1] ^
         kuz_mat_dec128[13][x.b[13]].q[1] ^
         kuz_mat_dec128[14][x.b[14]].q[1] ^
         kuz_mat_dec128[15][x.b[15]].q[1];

      x.q[0] = t;
      x.q[0] ^= dkey->k[i].q[0]; x.q[1] ^= dkey->k[i].q[1];
      x.q[0] ^= xkey->k[i].q[0]; x.q[1] ^= xkey->k[i].q[1];
  }
  for( i = 0; i < 16; i++ ) x.b[i] = pinv[x.b[i]];

  x.q[0] ^= dkey->k[0].q[0]; x.q[1] ^= dkey->k[0].q[1];
  (( ak_uint64 *) out)[0] = x.q[0] ^ xkey->k[0].q[0];
  (( ak_uint64 *) out)[1] = x.q[1] ^ xkey->k[0].q[1];
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает контекст ключа блочного алгоритма шифрования Кузнечик (ГОСТ Р 34.12-2015).

    После выполнения данной функции создается указатель на контекст ключа и устанавливаются
    обработчики (функции класса). Однако само значение ключу не присваивается -
    поле bkey->key остается равным NULL.

    \b Внимание. Данная функция предназначена для использования другими функциями и не должна
    вызываться напрямую.

    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
    возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 static ak_bckey ak_bckey_kuznechik_new( void )
{
  ak_bckey bkey = NULL;

 /* создаем ключ алгоритма шифрования и определяем его методы */
  if(( bkey = ak_bckey_new( 32, 16 )) == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "incorrect memory allocation" );
    return NULL;
  }
 /* устанавливаем OID алгоритма шифрования */
  if(( bkey->key.oid = ak_oids_find_by_name( "kuznechik" )) == NULL ) {
    int error = ak_error_get_value();
    ak_error_message( error, __func__, "wrong search of predefined kuznechik block cipher OID" );
    return ( bkey = ak_bckey_delete( bkey ));
  };

 /* устанавливаем ресурс использования серетного ключа */
  bkey->key.resource.counter = ak_libakrypt_get_kuznechik_resource();

 /* устанавливаем методы */
  bkey->key.data = NULL;
  bkey->key.set_mask =  ak_skey_set_mask_xor;
  bkey->key.remask = ak_kuznechik_remask_xor;
  bkey->key.set_icode = ak_skey_set_icode_xor;
  bkey->key.check_icode = ak_skey_check_icode_xor;

  bkey->schedule_keys = ak_kuznechik_schedule_keys;
  bkey->delete_keys = ak_kuznechik_delete_keys;
  bkey->encrypt = ak_kuznechik_encrypt_with_mask;
  bkey->decrypt = ak_kuznechik_decrypt_with_mask;

 return bkey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст ключа алгоритма блочного шифрования Кузнечик (ГОСТ 34.12-2015)
    и инициализирует его заданным значением.

    Значение ключа инициализируется значением, содержащемся в области памяти, на которую
    указывает аргумент функции. При инициализации ключевое значение \b копируется в буффер,
    если флаг cflag истиннен. Если флаг ложен, то копирования не происходит.
    Поведение функции при копировании аналогично поведению функции ak_buffer_set_ptr().

    После присвоения ключа производится его развертка,
    маскирование и выработка контрольной суммы.

    Предпалагается, что основное использование функции ak_bckey_kuznechik_new_buffer()
    заключается в тестировании алгоритма шифрования Кузнечик на заданных (тестовых)
    значениях ключей.

    @param keyptr Указатель на область памяти, содержащую значение ключа.
    @param cflag флаг владения данными. Если он истинен, то данные копируются в область памяти,
    которой владеет ключевой контекст.

    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
    возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 ak_bckey ak_bckey_new_kuznechik_ptr( const ak_pointer keyptr, const size_t size, const ak_bool cflag  )
{
  int error = ak_error_ok;
  ak_bckey bkey = NULL;

 /* проверяем входной буффер */
  if( keyptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to key data" );
    return NULL;
  }
  if( size != 32 ) {
    ak_error_message( ak_error_wrong_length, __func__, "using a wrong length of secret key" );
    return NULL;
  }
 /* создаем контекст ключа */
  if(( bkey = ak_bckey_kuznechik_new( )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect creation of kuznechik secret key" );
    return NULL;
  }
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_assign_ptr( &bkey->key, keyptr, size, cflag )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect assigning of key data" );
    return ( bkey = ak_bckey_delete( bkey ));
  }
 /* производим развертку ключа */
  if( bkey->schedule_keys != NULL )
    if(( error = bkey->schedule_keys( &bkey->key )) != ak_error_ok) {
      ak_error_message( error, __func__ , "incorrect scheduling of key value" );
      return ( bkey = ak_bckey_delete( bkey ));
    }

 return bkey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст ключа алгоритма блочного шифрования Кузнечик (ГОСТ 34.12-2015)
    и инициализирует его случайным значением.

    Значение ключа вырабатывается генератором псевдо-случайных чисел.
    После присвоения ключа производится его развертка, маскирование и выработка контрольной суммы.

    @param generator Указатель на генератор псевдо-случайных чисел.

    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
    возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 ak_bckey ak_bckey_new_kuznechik_random( ak_random generator )
{
  int error = ak_error_ok;
  ak_bckey bkey = NULL;

 /* проверяем генератор */
  if( generator == NULL ) { ak_error_message( ak_error_null_pointer, __func__ ,
                                              "using a null pointer to random number generator" );
    return NULL;
  }

 /* создаем контекст ключа */
  if(( bkey = ak_bckey_kuznechik_new( )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect creation of kuznechik secret key" );
    return NULL;
  }

 /* вырабатываем случайные данные */
  if(( error = ak_skey_assign_random( &bkey->key, generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect generation of secret key data" );
    return ( bkey = ak_bckey_delete( bkey ));
  }

 /* производим развертку ключа */
  if( bkey->schedule_keys != NULL )
    if(( error = bkey->schedule_keys( &bkey->key )) != ak_error_ok) {
      ak_error_message( error, __func__ , "incorrect scheduling of key value" );
      return ( bkey = ak_bckey_delete( bkey ));
    }

 return bkey;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bckey ak_bckey_new_kuznechik_password( const ak_pointer pass, const size_t size )
{
  int error = ak_error_ok;
  ak_bckey bkey = NULL;

 /* проверяем входной буффер */
  if( pass == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using a null pointer to password" );
    return NULL;
  }
  if( size == 0 ) {
    ak_error_message( ak_error_zero_length, __func__, "using a password with zero length" );
    return NULL;
  }

 /* создаем контекст ключа */
  if(( bkey = ak_bckey_kuznechik_new( )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "incorrect creation of magma secret key" );
    return NULL;
  }

 /* вырабатываем значение ключа */
  if(( error = ak_skey_assign_password( &bkey->key, pass, size )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect generation of secret key data" );
    return ( bkey = ak_bckey_delete( bkey ));
  }

 /* производим развертку ключа */
  if( bkey->schedule_keys != NULL )
    if(( error = bkey->schedule_keys( &bkey->key )) != ak_error_ok) {
      ak_error_message( error, __func__ , "incorrect scheduling of key value" );
      return ( bkey = ak_bckey_delete( bkey ));
    }

 return bkey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Тестирование производится в соответствии с ГОСТ Р 34.12-2015 и ГОСТ Р 34.13-2015.              */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_bckey_test_kuznechik( void )
{
  char *str = NULL;
  int audit = ak_log_get_level();
  ak_bckey bkey = NULL;

 /* тестовый ключ из ГОСТ Р 34.12-2015, приложение А.1 */
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

 /* открытый текст из ГОСТ Р 34.12-2015, приложение А.1, подлежащий зашифрованию */
  ak_uint8 in[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };

 /* зашифрованный блок из ГОСТ Р 34.12-2015 */
  ak_uint8 out[16] = {
    0xcd, 0xed, 0xd4, 0xb9, 0x42, 0x8d, 0x46, 0x5a, 0x30, 0x24, 0xbc, 0xbe, 0x90, 0x9d, 0x67, 0x7f };

 /* открытый текст из ГОСТ Р 34.13-2015, приложение А.1, подлежащий зашифрованию */
  ak_uint32 inlong[16] = {
    0xbbaa9988, 0xffeeddcc, 0x55667700, 0x11223344, 0xcceeff0a, 0x8899aabb, 0x44556677, 0x00112233,
    0xeeff0a00, 0x99aabbcc, 0x55667788, 0x11223344, 0xff0a0011, 0xaabbccee, 0x66778899, 0x22334455 };

 /* результат зашифрования в режиме простой замены */
  ak_uint32 outecb[16] = {
    0xb9d4edcd, 0x5a468d42, 0xbebc2430, 0x7f679d90, 0x6718d08b, 0x285452d7, 0x6e0032f9, 0xb429912c,
    0x3bd4b157, 0xf3f5a531, 0x9d247cee, 0xf0ca3354, 0xaa8ada98, 0x3a02c4c5, 0xe830b9eb, 0xd0b09ccd };

 /* инициализационный вектор для режима гаммирования (счетчика) */
  ak_uint8 ivctr[8] = { 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12 };

 /* результат зашифрования в режиме гаммирования (счетчика) */
  ak_uint32 outctr[16] = {
    0x40bda1b8, 0xd57b5fa2, 0xc10ed1db, 0xf195d8be, 0x3c45dee4, 0xf33ce4b3, 0xf6a13e5d, 0x85eee733,
    0x3564a3a5, 0xd5e877f1, 0xe6356ed3, 0xa5eae88b, 0x20bdba73, 0xd1c6d158, 0xf20cbab6, 0xcb91fab1 };

  ak_uint8 myout[64];

 /* 1. Создаем контекст ключа алгоритма Кузнечик */
  if(( bkey = ak_bckey_new_kuznechik_ptr( testkey, sizeof( testkey ), ak_false )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong creation of test key" );
    return ak_false;
  }

 /* 2. Тестируем зашифрование/расшифрование одного блока согласно ГОСТ Р34.12-2015 */
  bkey->encrypt( &bkey->key, in, myout );
  if( memcmp( myout, out, 16 ) != 0 ) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                       "the one block encryption test from GOST R 34.12-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 16, ak_true )); free( str );
    bkey = ak_bckey_delete( bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                         "the one block encryption test from GOST R 34.12-2015 is Ok" );

  bkey->decrypt( &bkey->key, out, myout );
  if( memcmp( myout, in, 16 ) != 0 ) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                       "the one block decryption test from GOST R 34.12-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( in, 16, ak_true )); free( str );
    bkey = ak_bckey_delete( bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                         "the one block decryption test from GOST R 34.12-2015 is Ok" );

 /* 3. Тестируем режим простой замены согласно ГОСТ Р34.13-2015 */
  if( ak_bckey_encrypt_ecb( bkey, inlong, myout, 64 ) != ak_error_ok ) {
    ak_error_message_fmt( ak_error_get_value(), __func__ , "wrong checking a secret key" );
    bkey = ak_bckey_delete( bkey );
    return ak_false;
  }
  if( memcmp( myout, outecb, 64 ) != 0 ) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                        "the ecb mode encryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outecb, 64, ak_true )); free( str );
    bkey = ak_bckey_delete( bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the ecb mode encryption test from GOST R 34.13-2015 is Ok" );

  if( ak_bckey_decrypt_ecb( bkey, outecb, myout, 64 ) != ak_error_ok ) {
    ak_error_message_fmt( ak_error_get_value(), __func__ , "wrong checking a secret key" );
    bkey = ak_bckey_delete( bkey );
    return ak_false;
  }
  if( memcmp( myout, inlong, 64 ) != 0 ) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                        "the ecb mode decryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( inlong, 64, ak_true )); free( str );
    bkey = ak_bckey_delete( bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the ecb mode decryption test from GOST R 34.13-2015 is Ok" );

 /* 4. Тестируем режим гаммирования (счетчика) согласно ГОСТ Р34.13-2015 */
  if( ak_bckey_xcrypt( bkey, inlong, myout, 64, ivctr ) != ak_error_ok ) {
    ak_error_message_fmt( ak_error_get_value(), __func__ , "wrong checking a secret key" );
    bkey = ak_bckey_delete( bkey );
    return ak_false;
  }
  if( memcmp( myout, outctr, 64 ) != 0 ) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                        "the ctr mode encryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( outctr, 64, ak_true )); free( str );
    bkey = ak_bckey_delete( bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the ctr mode encryption test from GOST R 34.13-2015 is Ok" );

  if( ak_bckey_xcrypt( bkey, outctr, myout, 64, ivctr ) != ak_error_ok ) {
    ak_error_message_fmt( ak_error_get_value(), __func__ , "wrong checking a secret key" );
    bkey = ak_bckey_delete( bkey );
    return ak_false;
  }
  if( memcmp( myout, inlong, 64 ) != 0 ) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                        "the ctr mode decryption test from GOST R 34.13-2015 is wrong");
    ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( inlong, 64, ak_true )); free( str );
    bkey = ak_bckey_delete( bkey );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                           "the ctr mode decryption test from GOST R 34.13-2015 is Ok" );

  bkey = ak_bckey_delete( bkey );
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  ak_kuznechik.c */
/* ----------------------------------------------------------------------------------------------- */
