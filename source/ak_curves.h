/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_curves.h                                                                               */
/*  - содержит описания функций для работы с эллиптическими кривыми.                               */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_CURVES_H__
#define    __AK_CURVES_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mpzn.h>

/* ----------------------------------------------------------------------------------------------- */
 struct wcurve;
/*! \brief Контекст эллиптической кривой, заданной в короткой форме Вейерштрасса. */
 typedef struct wcurve *ak_wcurve;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий точку эллиптической кривой.

    Класс реализеут точку \f$ P \f$ эллиптической кривой, заданной в короткой форме Вейерштрасса,
    в проективных координатах, т.е. точка представляется в виде вектора \f$ P=(x:y:z) \f$,
    удовлетворяющего сравнению \f$ y^2z \equiv x^3 + axz^2 + bz^3 \pmod{p} \f$.
    В дальнейшем, при проведении вычислений, для координат точки используется
    представление Монтгомери.                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 struct wpoint
{
/*! \brief x-координата точки эллиптической кривой */
 ak_uint64 x[ak_mpzn512_size];
/*! \brief y-координата точки эллиптической кривой */
 ak_uint64 y[ak_mpzn512_size];
/*! \brief z-координата точки эллиптической кривой */
 ak_uint64 z[ak_mpzn512_size];
};
/*! \brief Контекст точки эллиптической кривой в короткой форме Вейерштрасса */
 typedef struct wpoint *ak_wpoint;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация и присвоение контексту значения образующей точки эллиптической кривой. */
 int ak_wpoint_set( ak_wpoint, ak_wcurve );
/*! \brief Инициализация и присвоение контексту значения бесконечно удаленной точки эллиптической кривой. */
 int ak_wpoint_set_as_unit( ak_wpoint , ak_wcurve );
/*! \brief Инициализация и присвоение контексту значения заданной точки эллиптической кривой. */
 int ak_wpoint_set_wpoint( ak_wpoint , ak_wpoint , ak_wcurve );

/*! \brief Проверка принадлежности точки заданной кривой. */
 ak_bool ak_wpoint_is_ok( ak_wpoint , ak_wcurve );
/*! \brief Проверка порядка заданной точки. */
 ak_bool ak_wpoint_check_order( ak_wpoint , ak_wcurve );

/*! \brief Удвоение точки эллиптической кривой, заданной в короткой форме Вейерштрасса. */
 void ak_wpoint_double( ak_wpoint , ak_wcurve );
/*! \brief Прибавление к одной точке эллиптической кривой значения другой точки. */
 void ak_wpoint_add( ak_wpoint , ak_wpoint , ak_wcurve );
/*! \brief Приведение проективной точки к аффинному виду. */
 void ak_wpoint_reduce( ak_wpoint , ak_wcurve );
/*! \brief Вычисление кратной точки эллиптической кривой. */
 void ak_wpoint_pow( ak_wpoint , ak_wpoint , ak_uint64 *, size_t , ak_wcurve );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий эллиптическую кривую, заданную в короткой форме Вейерштрасса

    Класс определяет эллиптическую кривую, заданную сравнением
    \f$ y^2 \equiv x^3 + ax + b \pmod{p} \f$, а также образующую точку \f$P=(x_P, y_P)\f$
    на этой кривой с заданным порядком \f$ q \f$.

    Порядок \f$ m \f$ всей группы точек эллиптической кривой может быть определен
    из равенства \f$ m = dq \f$, где величину \f$ d \f$ называют кофактором.

    Параметры \f$ n, n_q, r_2\f$ вводятся для оптимизации вычислений. Определим \f$ r = 2^{256}\f$
    или \f$ r=2^{512}\f$, тогда \f$ n \equiv n_0 \pmod{2^{64}}\f$,
    где \f$ n_0 \equiv -p^{-1} \pmod{r}\f$.
    Величина \f$ r_2 \f$ удовлетворяет сравнению \f$ r_2 \equiv r^2 \pmod{p}\f$.                   */
/* ----------------------------------------------------------------------------------------------- */
 struct wcurve
{
 /*! \brief Размер параметров эллиптической кривой, исчисляемый количеством 64-х битных блоков. */
  ak_uint32 size;
 /*! \brief Кофактор эллиптической кривой - делитель порядка группы точек. */
  ak_uint32 cofactor;
 /*! \brief Коэффициент \f$ a \f$ эллиптической кривой (в представлении Монтгомери) */
  ak_uint64 a[ak_mpzn512_size];
 /*! \brief Коэффициент \f$ b \f$ эллиптической кривой (в представлении Монтгомери). */
  ak_uint64 b[ak_mpzn512_size];
 /*! \brief Модуль \f$ p \f$ эллиптической кривой. */
  ak_uint64 p[ak_mpzn512_size];
 /*! \brief Величина \f$ r^2\f$, взятая по модулю \f$ p \f$ и используемая в арифметике Монтгомери. */
  ak_uint64 r2[ak_mpzn512_size];
 /*! \brief Порядок \f$ q \f$ подгруппы, порождаемой образующей точкой \f$ P \f$. */
  ak_uint64 q[ak_mpzn512_size];
 /*! \brief Величина \f$ r^2\f$, взятая по модулю \f$ q \f$ и используемая в арифметике Монтгомери. */
  ak_uint64 r2q[ak_mpzn512_size];
 /*! \brief Точка \f$ P \f$ эллиптической кривой, порождающая подгруппу порядка \f$ q \f$. */
  struct wpoint point;
 /*! \brief Константа \f$ n \f$, используемая в арифметике Монтгомери по модулю \f$ p \f$. */
  ak_uint64 n;
 /*! \brief Константа \f$ n_q \f$, используемая в арифметике Монтгомери по модулю \f$ q\f$. */
  ak_uint64 nq;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вычисление дискриминанта эллиптической кривой, заданной в короткой форме Вейерштрасса. */
 void ak_mpzn_set_wcurve_discriminant( ak_uint64 *, ak_wcurve );
/*! \brief Проверка корректности дискриминанта эллиптической кривой, заданной в форме Вейерштрасса. */
 int ak_wcurve_discriminant_is_ok( ak_wcurve );
/*! \brief Проверка корректности параметров, необходимых для вычисления по модулю q. */
 int ak_wcurve_check_order_parameters( ak_wcurve );
/*! \brief Проверка набора параметров эллиптической кривой, заданной в форме Вейерштрасса. */
 int ak_wcurve_is_ok( ak_wcurve );
/*! \brief Функция тестирует все определяемые библиотекой параметры эллиптических кривых, заданных в короткой форме Вейерштрасса. */
 ak_bool ak_wcurve_test( void );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_curves.h  */
/* ----------------------------------------------------------------------------------------------- */