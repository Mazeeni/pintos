#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define BITS_AFTER_DECIMAL (14)
#define CONVERTER (1 << BITS_AFTER_DECIMAL)

/* Converts an integer into its fixed point representation */
#define TO_FIXED_POINT(n) (n * CONVERTER)

/* Converts a fixed-point number to an integer, rounding toward zero */
#define TO_INT_DOWN(x) (x / CONVERTER)

/* Convert a fixed-point number to an integer, round to the nearest integer */
#define TO_INT_NEAREST(x)                                                      \
  (x >= 0 ? ((x + CONVERTER / 2) / CONVERTER)                                  \
          : ((x - CONVERTER / 2) / CONVERTER))

/* Adds two fixed-point numbers */
#define ADD_FIXED(x, y) (x + y)

/* Subtracts y from x, both fixed-point numbers*/
#define SUB_FIXED(x, y) (x - y)

/* Adds an int to a fixed-point number */
#define FIXED_ADD_INT(x, n) (x + TO_FIXED_POINT(n))

/* Subtracts an int from a fixed-point number */
#define FIXED_SUB_INT(x, n) (x - TO_FIXED_POINT(n))

/* Multiplies two fixed-point numbers */
#define MULT_FIXED(x, y) TO_INT_DOWN(((int64_t)x) * y)

/* Multiplies an int with a fixed-point number */
#define FIXED_MULT_INT(x, n) (x * n)

/* Divides a fixed-point number, x, by another fixed-point number, y */
#define DIV_FIXED(x, y) (TO_FIXED_POINT((int64_t)x) / y)

/* Divides a fixed-point number by an integer */
#define FIXED_DIV_INT(x, n) (x / n)

/* Macro for load_avg calculation*/
#define DIV_BY_60(n) (FIXED_DIV_INT(TO_FIXED_POINT(n), 60))

/* Constant multiplied by load_avg for recent_cpu calculation. */
#define LOAD_AVG_COEFF (2)

/* Constant used to multiple load_avg and recent_cpu in
  thread_get_load_avg and thread_get_recent_cpu. */
#define BSD_CALCULATION_MULTIPLE (100)

/* Fixed point constant for 59/60 to avoid recalculation in load_avg
   every second. */
static const int32_t load_avg_weight = DIV_BY_60(59);

#endif /* threads/fixed-point.h */
