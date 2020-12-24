#include "threads/thread.h"
#include "devices/timer.h"
#include "threads/fixed-point.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <debug.h>
#include <random.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Current system load average value */
static int32_t load_avg;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame {
  void *eip;             /* Return address. */
  thread_func *function; /* Function to call. */
  void *aux;             /* Auxiliary data for function. */
};

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4          /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-mlfqs". */
bool thread_mlfqs;

struct semaphore don_sema;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *running_thread(void);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static bool is_thread(struct thread *) UNUSED;
static void *alloc_frame(struct thread *, size_t size);
static void schedule(void);
void thread_schedule_tail(struct thread *prev);
static tid_t allocate_tid(void);

/* Used in thread_set_priority and thread_set_nice. */
static void thread_check_yield(int old_priority, int current_priority);

/* Functions for mlfqs calculations. */
static void thread_mlfqs_recalculate(struct thread *cur);
static void calculate_load_avg(void);
static int32_t calculate_recent_cpu_coeff(void);
static void thread_set_recent_cpu(struct thread *t, void *coefficient);
static void calculate_recent_cpu(void);
static void calculate_bsd_priority(struct thread *t, void *aux UNUSED);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void) {
  ASSERT(intr_get_level() == INTR_OFF);

  lock_init(&tid_lock);
  list_init(&ready_list);
  list_init(&all_list);
  sema_init(&don_sema, 1);

#ifdef USERPROG
  initialise_exit_lock();
  initialise_file_lock();
#endif

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread();
  init_thread(initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid();

  initial_thread->nice = 0;
  load_avg = 0;
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void) {
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init(&idle_started, 0);
  thread_create("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down(&idle_started);
}

/* Returns the number of threads currently in the ready list */
size_t threads_ready(void) { return list_size(&ready_list); }

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void) {
  struct thread *t = thread_current();

  /* Update statistics. */
  if (t == idle_thread) {
    idle_ticks++;
  }
#ifdef USERPROG
  else if (t->pagedir != NULL) {
    user_ticks++;
  }
#endif
  else {
    kernel_ticks++;
  }

  if (thread_mlfqs) {
    thread_mlfqs_recalculate(t);
  }

  /* Enforce preemption if current priority is less than or equal to then
     maximum of the ready threads. */
  if (++thread_ticks >= TIME_SLICE && !list_empty(&ready_list) &&
      thread_get_priority() <= MAX_READY_THREAD->priority) {
    intr_yield_on_return();
  }
}

/* If thread_mlfqs is true then it recalculates system load average,
   recent_cpu and priority for all threads every second. Every
   TIME_SLICE it recalculates priority for the current running
   thread if not the idle thread as current thread's recent
   cpu has updated hence priority needs to be updated. */
static void thread_mlfqs_recalculate(struct thread *cur) {
  /* Increments current thread's recent_cpu value if not idle. */
  if (cur != idle_thread) {
    cur->recent_cpu = FIXED_ADD_INT(cur->recent_cpu, 1);
  }

  /* Recalculations every second */
  if (timer_ticks() % TIMER_FREQ == 0) {
    calculate_load_avg();
    calculate_recent_cpu();
    thread_foreach(calculate_bsd_priority, NULL);
  }

  /* Recalculations every TIME_SLICE */
  if (timer_ticks() % TIME_SLICE == 0 && cur != idle_thread) {
    calculate_bsd_priority(cur, NULL);
  }
}

/* Prints thread statistics. */
void thread_print_stats(void) {
  printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
         idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3.

   thread_yield() is called if the newly created thread has
   higher priority and should therefore be scheduled immediately. */
tid_t thread_create(const char *name, int priority, thread_func *function,
                    void *aux) {
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT(function != NULL);

  /* Allocate thread. */
  t = palloc_get_page(PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread(t, name, priority);
  tid = t->tid = allocate_tid();

  if (thread_mlfqs) {
    /* Sets nice and recent_cpu values of new thread to parent
       thread's values. */
    t->nice = thread_get_nice();
    t->recent_cpu = thread_current()->recent_cpu;
    t->priority = thread_get_priority();
  }
  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack'
     member cannot be observed. */
  old_level = intr_disable();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame(t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame(t, sizeof *ef);
  ef->eip = (void (*)(void))kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame(t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level(old_level);

  /* Add to run queue. */
  thread_unblock(t);

  if (t->priority > thread_get_priority()) {
    thread_yield();
  }

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h.

   ADDED CODE:
   If thread_mlfqs then recalculates current thread's priority
   to ensure it is up to date following potential increments to
   its recent cpu which occurs in thread_mlfqs_recalculate
   every tick that current thread is running for.
 */
void thread_block(void) {
  ASSERT(!intr_context());
  ASSERT(intr_get_level() == INTR_OFF);

  if (thread_mlfqs) {
    calculate_bsd_priority(thread_current(), NULL);
  }

  thread_current()->status = THREAD_BLOCKED;

  schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data.  */
void thread_unblock(struct thread *t) {
  enum intr_level old_level;

  ASSERT(is_thread(t));

  old_level = intr_disable();
  ASSERT(t->status == THREAD_BLOCKED);

  list_push_back(&ready_list, &t->elem);

  t->status = THREAD_READY;
  intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *thread_name(void) { return thread_current()->name; }

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *thread_current(void) {
  struct thread *t = running_thread();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT(is_thread(t));
  ASSERT(t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void) { return thread_current()->tid; }

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void) {
  ASSERT(!intr_context());

#ifdef USERPROG
  process_exit();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable();
  list_remove(&thread_current()->allelem);
  thread_current()->status = THREAD_DYING;
  schedule();
  NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim.

   ADDED CODE:
   If thread_mlfqs then recalculates current thread's priority
   to ensure it is up to date following potential increments to
   its recent cpu which occurs in thread_mlfqs_recalculate
   every tick that thread is running for. */
void thread_yield(void) {
  struct thread *cur = thread_current();
  enum intr_level old_level;

  ASSERT(!intr_context());

  old_level = intr_disable();

  if (cur != idle_thread) {
    list_push_back(&ready_list, &cur->elem);
  }

  if (thread_mlfqs) {
    calculate_bsd_priority(thread_current(), NULL);
  }

  cur->status = THREAD_READY;

  schedule();

  intr_set_level(old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void thread_foreach(thread_action_func *func, void *aux) {
  struct list_elem *e;

  ASSERT(intr_get_level() == INTR_OFF);

  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
    struct thread *t = list_entry(e, struct thread, allelem);
    func(t, aux);
  }
}

/* Sets the current thread's priority and base_priority to NEW_PRIORITY.

   If current thread is holding locks and the new priority is less than
   the current effective priority then it will check the maximum donated
   priority the current thread is receiving. If this is greater than the
   new_priority then the effective priority of the thread will be set to
   the maximum donated priority. This check is surrounded by a semaphore
   to ensure no race conditions occur when getting the maximum donated
   priority. If statement short circuits if the new priority is greater
   than or equal to the current effective priority as there is no need
   to check for max donated.

   It calls thread_check_yield to see whether current thread should
   be yielded after a change in priority.
*/
void thread_set_priority(int new_priority) {
  if (thread_mlfqs) {
    return;
  }
  ASSERT(new_priority <= PRI_MAX && new_priority >= PRI_MIN);

  struct thread *cur = thread_current();
  int old_priority = cur->priority;

  cur->base_priority = cur->priority = new_priority;

  sema_down(&don_sema);
  int max_donation;
  if (new_priority < old_priority && !list_empty(&cur->acquired_locks) &&
      (max_donation = MAX_DONATION(cur)) > new_priority) {
    cur->priority = max_donation;
  }
  sema_up(&don_sema);

  thread_check_yield(old_priority, cur->priority);
}

/* Checks whether to call yield following a change in priority to the
   current thread.
   If current thread priority is less than highest priority in ready
   list then it yields. However if new priority for current is greater
   or equal than old then it short circuits i.e. if current thread's
   priority has just increased or stayed the same then there is no point
   in checking the max of the ready list as the current thread will for
   sure have the highest priority.

    max_ready_lock used to ensure no race condtions although there
    shouldn't be as all other read/write to ready_list occurs when
    interrupts are disabled. */
static void thread_check_yield(int old_priority, int new_priority) {
  if (new_priority < old_priority && !list_empty(&ready_list) &&
      new_priority < MAX_READY_THREAD->priority) {
    thread_yield();
  }
}

/* Returns the current thread's priority. */
int thread_get_priority(void) { return thread_current()->priority; }

/* Changes the current thread's nice value to nice then recalculates
   recent_cpu and priority for current thread to ensure these values
   are up to date following a change in nice.

   It calls thread_check_yield to see whether current thread should
   be yielded after a change in priority. */
void thread_set_nice(int nice) {
  struct thread *cur = thread_current();
  int old_priority = cur->priority;
  cur->nice = nice;

  /* Recalculates recent_cpu and priority for current thread. */
  int32_t coefficient = calculate_recent_cpu_coeff();
  thread_set_recent_cpu(cur, &coefficient);
  calculate_bsd_priority(cur, NULL);

  thread_check_yield(old_priority, cur->priority);
}

/* Returns the current thread's nice value. */
int thread_get_nice(void) { return thread_current()->nice; }

/* Calculates the system load average using fixed point arithmetic.
   Function called every second. */
static void calculate_load_avg(void) {
  int ready_threads = threads_ready();
  if (thread_current() != idle_thread) {
    ready_threads++;
  }
  int32_t load_weight = MULT_FIXED(load_avg, load_avg_weight);
  int32_t ready_weight = DIV_BY_60(ready_threads);
  load_avg = ADD_FIXED(load_weight, ready_weight);
}

/* Returns 100 times the current system load average. */
int thread_get_load_avg(void) {
  return TO_INT_NEAREST(FIXED_MULT_INT(load_avg, BSD_CALCULATION_MULTIPLE));
}

/* Returns and calculates the coefficient for recent cpu using fixed point
   arithmetic. Coefficient is the same for all threads, this function
   is used to reduce repeated calculations so coefficient is not
   recalculated by all threads every second. */
static int32_t calculate_recent_cpu_coeff(void) {
  int32_t co_numerator = FIXED_MULT_INT(load_avg, LOAD_AVG_COEFF);
  int32_t co_denominator = FIXED_ADD_INT(co_numerator, 1);
  return DIV_FIXED(co_numerator, co_denominator);
}

/* Updates and calculates the recent cpu value for 1 thread using
   fixed point arithmetic */
static void thread_set_recent_cpu(struct thread *t, void *coefficient) {
  t->recent_cpu = FIXED_ADD_INT(
      MULT_FIXED(*((int32_t *)coefficient), t->recent_cpu), t->nice);
}

/* Recalculates the recent cpu value for all threads.
   Function called every second. */
static void calculate_recent_cpu(void) {
  int32_t coefficient = calculate_recent_cpu_coeff();

  thread_foreach(thread_set_recent_cpu, &coefficient);
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void) {
  return TO_INT_NEAREST(
      FIXED_MULT_INT(thread_current()->recent_cpu, BSD_CALCULATION_MULTIPLE));
}

/* Returns true if thread "a" has a lower priority than
   thread "b". */
bool priority_less_than(const struct list_elem *a, const struct list_elem *b,
                        void *aux UNUSED) {
  return list_entry(a, struct thread, elem)->priority <
         list_entry(b, struct thread, elem)->priority;
}

/* Calculates priority based on BSD Scheduling. If out of bounds
   then priority will equal either PRI_MIN or PRI_MAX */
static void calculate_bsd_priority(struct thread *t, void *aux UNUSED) {
  int32_t weighted_recent = FIXED_DIV_INT(t->recent_cpu, 4);
  int new_priority = TO_INT_DOWN(FIXED_SUB_INT(
      SUB_FIXED(TO_FIXED_POINT(PRI_MAX), weighted_recent), (t->nice * 2)));

  if (new_priority > PRI_MAX) {
    new_priority = PRI_MAX;
  } else if (new_priority < PRI_MIN) {
    new_priority = PRI_MIN;
  }

  t->priority = new_priority;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void idle(void *idle_started_ UNUSED) {
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current();
  sema_up(idle_started);

  for (;;) {
    /* Let someone else run. */
    intr_disable();
    thread_block();

    /* Re-enable interrupts and wait for the next one.

       The `sti' instruction disables interrupts until the
       completion of the next instruction, so these two
       instructions are executed atomically.  This atomicity is
       important; otherwise, an interrupt could be handled
       between re-enabling interrupts and waiting for the next
       one to occur, wasting as much as one clock tick worth of
       time.

       See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
       7.11.1 "HLT Instruction". */
    asm volatile("sti; hlt" : : : "memory");
  }
}

/* Function used as the basis for a kernel thread. */
static void kernel_thread(thread_func *function, void *aux) {
  ASSERT(function != NULL);

  intr_enable(); /* The scheduler runs with interrupts off. */
  function(aux); /* Execute the thread function. */
  thread_exit(); /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *running_thread(void) {
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm("mov %%esp, %0" : "=g"(esp));
  return pg_round_down(esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool is_thread(struct thread *t) {
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void init_thread(struct thread *t, const char *name, int priority) {
  enum intr_level old_level;

  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);

  memset(t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy(t->name, name, sizeof t->name);
  t->stack = (uint8_t *)t + PGSIZE;
  t->priority = priority;
  t->base_priority = priority;
  list_init(&t->acquired_locks);
  t->magic = THREAD_MAGIC;

#ifdef USERPROG
  list_init(&t->child_processes);
#endif

#ifdef VM
  list_init(&t->mm_table);
  t->next_mapping = 0;
#endif

  old_level = intr_disable();
  list_push_back(&all_list, &t->allelem);
  intr_set_level(old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *alloc_frame(struct thread *t, size_t size) {
  /* Stack data is always allocated in word-size units. */
  ASSERT(is_thread(t));
  ASSERT(size % sizeof(uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread.
   Chooses the highest priority thread in the ready_list.  */
static struct thread *next_thread_to_run(void) {

  if (list_empty(&ready_list)) {
    return idle_thread;
  }

  struct thread *next_thread = MAX_READY_THREAD;
  list_remove(&next_thread->elem);

  return next_thread;
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void thread_schedule_tail(struct thread *prev) {
  struct thread *cur = running_thread();

  ASSERT(intr_get_level() == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) {
    ASSERT(prev != cur);
    palloc_free_page(prev);
  }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void schedule(void) {
  struct thread *cur = running_thread();
  struct thread *next = next_thread_to_run();
  struct thread *prev = NULL;

  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(cur->status != THREAD_RUNNING);
  ASSERT(is_thread(next));

  if (cur != next)
    prev = switch_threads(cur, next);
  thread_schedule_tail(prev);
}

/* Returns a tid to use for a new thread. */
static tid_t allocate_tid(void) {
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire(&tid_lock);
  tid = next_tid++;
  lock_release(&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof(struct thread, stack);
