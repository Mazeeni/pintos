#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include "threads/synch.h"
#include <round.h>
#include <stdint.h>

/* Number of timer interrupts per second. */
#define TIMER_FREQ 100

struct sleeper_thread {
  int64_t sleep_until;         /* Ticks to reach for thread to awaken */
  struct semaphore sema;       /* Semaphore to control threads put to sleep */
  struct list_elem sleep_elem; /* List element for sleeping threads list */
};

void timer_init(void);
void timer_calibrate(void);

int64_t timer_ticks(void);
int64_t timer_elapsed(int64_t);

/* Sleep and yield the CPU to other threads. */
void timer_sleep(int64_t ticks);
void timer_msleep(int64_t milliseconds);
void timer_usleep(int64_t microseconds);
void timer_nsleep(int64_t nanoseconds);

/* Busy waits. */
void timer_mdelay(int64_t milliseconds);
void timer_udelay(int64_t microseconds);
void timer_ndelay(int64_t nanoseconds);

void timer_print_stats(void);

#endif /* devices/timer.h */
