/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <stdio.h>
#include <string.h>

/* A function used to compare the priority of the thread within
   the semaphore in each of the two semaphore_elem structs. */
static bool sema_less_priority(const struct list_elem *a,
                               const struct list_elem *b, void *aux UNUSED);

/* For priority donation. */
static void update_donation_chain(struct lock *lock);
static void set_holder_donated(struct lock *lock, struct thread *cur);
static void reset_holder_donated(struct lock *lock);

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void sema_init(struct semaphore *sema, unsigned value) {
  ASSERT(sema != NULL);

  sema->value = value;
  list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void sema_down(struct semaphore *sema) {
  enum intr_level old_level;

  ASSERT(sema != NULL);
  ASSERT(!intr_context());

  old_level = intr_disable();
  while (sema->value == 0) {
    list_push_back(&sema->waiters, &thread_current()->elem);
    thread_block();
  }
  sema->value--;
  intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore *sema) {
  enum intr_level old_level;
  bool success;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (sema->value > 0) {
    sema->value--;
    success = true;
  } else
    success = false;
  intr_set_level(old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler.

   The highest priority waiting thread is unblocked.
   Only yield if it has higher priority than current thread.
   */
void sema_up(struct semaphore *sema) {
  enum intr_level old_level;

  ASSERT(sema != NULL);

  struct thread *t = NULL;
  old_level = intr_disable();
  if (!list_empty(&sema->waiters)) {
    /* Unblock the highest priority thread in the waiting list. */
    t = MAX_WAITER(&sema->waiters);
    list_remove(&t->elem);
    thread_unblock(t);
  }
  sema->value++;
  intr_set_level(old_level);

  /* Yields current thread if highest priority. May be called
     from interrupt context.  */
  if (t && t->priority > thread_current()->priority) {
    if (intr_context()) {
      intr_yield_on_return();
    } else {
      thread_yield();
    }
  }
}

static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void) {
  struct semaphore sema[2];
  int i;

  printf("Testing semaphores...");
  sema_init(&sema[0], 0);
  sema_init(&sema[1], 0);
  thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) {
    sema_up(&sema[0]);
    sema_down(&sema[1]);
  }
  printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper(void *sema_) {
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++) {
    sema_down(&sema[0]);
    sema_up(&sema[1]);
  }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock *lock) {
  ASSERT(lock != NULL);

  lock->holder = NULL;
  lock->max_priority = 0;
  sema_init(&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep.

   Donation variables are only set and checked when thread_mlfqs
   is false */

void lock_acquire(struct lock *lock) {
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(!lock_held_by_current_thread(lock));

  if (!thread_mlfqs) {
    update_donation_chain(lock);
  }

  sema_down(&lock->semaphore);
  struct thread *cur = thread_current();
  lock->holder = cur;

  if (!thread_mlfqs) {
    set_holder_donated(lock, cur);
  }
}

void reentrant_lock_init(struct re_lock *re_lock) {
  re_lock->acquires = 0;
  lock_init(&re_lock->lock);
}

void reentrant_lock_acquire(struct re_lock *re_lock) {
  enum intr_level old_level = intr_disable();
  if (lock_held_by_current_thread(&re_lock->lock)) {
    re_lock->acquires++;
  } else{
    re_lock->acquires = 1;
    lock_acquire(&re_lock->lock);
  }
  intr_set_level(old_level);
}

void reentrant_lock_release(struct re_lock *re_lock) {
  enum intr_level old_level = intr_disable();
  if (--re_lock->acquires == 0) {
    lock_release(&re_lock->lock);
  }
  intr_set_level(old_level);
}

/* If the lock has a holder and the current thread's priority is greater
   than the max priority waiting in the lock, it updates the
   max_priority of the current lock.

   If the current thread's priority is greater than the holder's then
   the current thread donates to the holder so changes the holder's
   effective priority. If the current holder is also blocked by a
   lock then this process is repeated recursively to ensure all
   locks and threads in donation chain are up to date. It stops
   recursion once it reaches the top of the chain.

   A semaphore surrounds the recursion so no race conditions occur
   when other threads access a locks max_priority and ensures all
   locks in the donation chain have an up to date max_priority. */
static void update_donation_chain(struct lock *lock) {
  struct thread *cur_holder = lock->holder;
  struct thread *new_thread = thread_current();
  struct lock *cur_lock = lock;

  sema_down(&don_sema);
  while (cur_holder && new_thread->priority > cur_lock->max_priority) {
    cur_lock->max_priority = new_thread->priority;

    if (new_thread->priority > cur_holder->priority) {
      cur_holder->priority = new_thread->priority;
    }

    if (cur_holder->blocked_by) {
      new_thread = cur_holder;
      cur_lock = cur_holder->blocked_by;
      cur_holder = cur_lock->holder;
    } else {
      break;
    }
  }
  sema_up(&don_sema);

  thread_current()->blocked_by = lock;
}

/* Once a thread has been unblocked and left the locks waiting
   list it becomes the holder. So it is no longer blocked by this
   lock and blocked_by is set to NULL. Then the lock's max priority
   is updated to the next highest waiting thread or reset to
   0 (PRI_MIN) if no waiters exist. Finally the lock is inserted
   to the current threads list of held locks. */
static void set_holder_donated(struct lock *lock, struct thread *cur) {
  cur->blocked_by = NULL;

  if (list_empty(&lock->semaphore.waiters)) {
    lock->max_priority = PRI_MIN;
  } else {
    struct thread *max_thread = MAX_WAITER(&lock->semaphore.waiters);
    lock->max_priority = max_thread->priority;
  }

  list_push_back(&cur->acquired_locks, &lock->lock_elem);
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock *lock) {
  bool success;

  ASSERT(lock != NULL);
  ASSERT(!lock_held_by_current_thread(lock));

  success = sema_try_down(&lock->semaphore);
  if (success)
    lock->holder = thread_current();
  return success;
}

bool lock_less_priority(const struct list_elem *a, const struct list_elem *b,
                        void *aux UNUSED) {
  struct lock *l1 = list_entry(a, struct lock, lock_elem);
  struct lock *l2 = list_entry(b, struct lock, lock_elem);
  return l1->max_priority < l2->max_priority;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler.

   Variables for donation are only checked and changed if
   thread_mlfqs is false.  */
void lock_release(struct lock *lock) {
  ASSERT(lock != NULL);
  ASSERT(lock_held_by_current_thread(lock));

  if (!thread_mlfqs) {
    reset_holder_donated(lock);
  }
  lock->holder = NULL;
  sema_up(&lock->semaphore);
}

/* When released the lock is removed from the thread's list of
   locks it holds and the holder becomes NULL. If the effective
   priority of the thread is due to a donation from this lock
   then we check the remaining locks held by the current thread
   for the next highest donating thread and set the effective
   priority of the current thread to this only if it is higher
   than its base priority.

   This check is surrounded by a semaphore to ensure no race
   conditions occur when getting the maximum donated priority.

   Otherwise if no threads are donating a higher priority then its
   base then the current thread will revert to its base priority.
*/
static void reset_holder_donated(struct lock *lock) {
  struct thread *cur = thread_current();
  struct list *cur_lock_list = &cur->acquired_locks;

  list_remove(&lock->lock_elem);

  if (cur->priority == lock->max_priority) {
    /* Recalculate effective priority.  */
    int max_donation;
    sema_down(&don_sema);

    if (!list_empty(cur_lock_list) &&
        (max_donation = MAX_DONATION(cur)) > cur->base_priority) {
      cur->priority = max_donation;
    } else {
      cur->priority = cur->base_priority;
    }

    sema_up(&don_sema);
  }
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock *lock) {
  ASSERT(lock != NULL);

  return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem {
  struct list_elem elem;      /* List element. */
  struct semaphore semaphore; /* This semaphore. */
};

static bool sema_less_priority(const struct list_elem *a,
                               const struct list_elem *b, void *aux UNUSED) {
  struct semaphore s1 = list_entry(a, struct semaphore_elem, elem)->semaphore;
  struct semaphore s2 = list_entry(b, struct semaphore_elem, elem)->semaphore;

  return priority_less_than(list_begin(&s1.waiters), list_begin(&s2.waiters),
                            NULL);
}

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition *cond) {
  ASSERT(cond != NULL);

  list_init(&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait(struct condition *cond, struct lock *lock) {
  struct semaphore_elem waiter;

  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  sema_init(&waiter.semaphore, 0);
  list_push_back(&cond->waiters, &waiter.elem);
  lock_release(lock);
  sema_down(&waiter.semaphore);
  lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler.

   sema_up is called on the semaphore in the condition with the
   highest priority thread.  */
void cond_signal(struct condition *cond, struct lock *lock UNUSED) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  if (!list_empty(&cond->waiters)) {
    struct list_elem *max = list_max(&cond->waiters, &sema_less_priority, NULL);
    list_remove(max);
    sema_up(&list_entry(max, struct semaphore_elem, elem)->semaphore);
  }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition *cond, struct lock *lock) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);

  while (!list_empty(&cond->waiters))
    cond_signal(cond, lock);
}