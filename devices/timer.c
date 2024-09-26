#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/*Alarm clock Prototyping 시작*/
struct sleeping_thread {
	struct thread *t;
	int64_t wake_time;
};
static struct list sleep_list;
static bool
wake_time_less (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
void thread_sleep(struct thread *t);
void time_list_chk();
struct thread * search_sleep_list();
void print_sleep_list();
/*Alarm clock Prototyping 끝*/

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);
/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
void
timer_init (void) {
	/*Alarm-clock 구현 sleep_list init*/
	list_init (&sleep_list);
	/* 8254 input frequency divided by TIMER_FREQ, rounded to
	   nearest. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

	outb (0x43, 0x34);    /* CW: counter 0, LSB then MSB, mode 2, binary. */
	outb (0x40, count & 0xff);
	outb (0x40, count >> 8);

	intr_register_ext (0x20, timer_interrupt, "8254 Timer");
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	ASSERT (intr_get_level () == INTR_ON);
	printf ("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. */
	loops_per_tick = 1u << 10;
	while (!too_many_loops (loops_per_tick << 1)) {
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
		if (!too_many_loops (high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable ();
	int64_t t = ticks;
	intr_set_level (old_level);
	barrier ();
	return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t
timer_elapsed (int64_t then) {
	return timer_ticks () - then;
}

/*Alarm-clock 구현 함수 시작*/

/* Suspends execution for approximately TICKS timer ticks. */
void
timer_sleep (int64_t ticks) {
	struct sleeping_thread st;

	int64_t start = timer_ticks ();
	st.t = thread_current();

	ASSERT (intr_get_level () == INTR_ON);
	st.wake_time = ticks + start;

	thread_sleep(st.t); // tick만큼
}
void
thread_sleep(struct thread *t){
	// printf("thread_sleep--1\n");
	enum intr_level old_level;
	// printf("thread_sleep--2\n");
	old_level = intr_disable ();
	// printf("thread_sleep--3\n");
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	// schedule ();
	// printf("thread_sleep--4\n");
	
	list_insert_ordered (&sleep_list, &t->elem, wake_time_less, NULL);
	t->status = THREAD_BLOCKED;
	// printf("thread_sleep--5\n");
	schedule ();
	// printf("thread_sleep--6\n");

	intr_set_level (old_level);
	// printf("thread_sleep--7\n");
}

void time_list_chk(){
// time_interrupt가 발생할때마다
	// printf("time_list_chk\n");
	struct thread *t;
	while(t = search_sleep_list())// tick이 지나면
	{
		thread_unblock(t);
	}
}
struct thread *
search_sleep_list(){
	if(/*sleep_list_empty()*/ list_empty(&sleep_list)){
		return NULL;
	}
	struct sleeping_thread st;
	int64_t now = timer_ticks();
	/*st.t = sleep_list_head();*/ st.t = list_front(&sleep_list); //jwp 수정 부분
	if(st.wake_time <= now){
		/*sleep_list_delete(st.t);*/ list_pop_front (&sleep_list);
		print_sleep_list();
		return st.t;
	}
	return NULL;
}
static bool
wake_time_less (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
  // list_entry 매크로를 사용하여 list_elem에서 thread 구조체로 변환
  	const struct sleeping_thread *thread_a = list_entry(a, struct sleeping_thread, t->elem);
	const struct sleeping_thread *thread_b = list_entry(b, struct sleeping_thread, t->elem);

  // wake_time 기준으로 비교
  return thread_a->wake_time < thread_b->wake_time;
}

void
print_sleep_list() {
    struct list_elem *e;

    // sleep_list 순회
    for (e = list_begin(&sleep_list); e != list_end(&sleep_list); e = list_next(e)) {
        const struct sleeping_thread *st = list_entry(e, struct sleeping_thread, t->elem);

        // wake_time과 tid 출력
        printf("Thread TID: %d, Wake Time: %lld\n", st->t->tid, st->wake_time);
    }
}
/*Alarm-clock 구현 함수 끝*/

/* Suspends execution for approximately MS milliseconds. */
void
timer_msleep (int64_t ms) {
	real_time_sleep (ms, 1000);
}

/* Suspends execution for approximately US microseconds. */
void
timer_usleep (int64_t us) {
	real_time_sleep (us, 1000 * 1000);
}

/* Suspends execution for approximately NS nanoseconds. */
void
timer_nsleep (int64_t ns) {
	real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/* Timer interrupt handler. */
static void
timer_interrupt (struct intr_frame *args UNUSED) {
	ticks++;
	// printf("start\n");
	time_list_chk(); 
	// printf("end\n");
	thread_tick ();
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops (unsigned loops) {
	/* Wait for a timer tick. */
	int64_t start = ticks;
	while (ticks == start)
		barrier ();

	/* Run LOOPS loops. */
	start = ticks;
	busy_wait (loops);

	/* If the tick count changed, we iterated too long. */
	barrier ();
	return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0)
		barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep (int64_t num, int32_t denom) {
	// printf("real_time_sleep");
	/* Convert NUM/DENOM seconds into timer ticks, rounding down.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom;

	ASSERT (intr_get_level () == INTR_ON);
	if (ticks > 0) {
		/* We're waiting for at least one full timer tick.  Use
		   timer_sleep() because it will yield the CPU to other
		   processes. */
		timer_sleep (ticks);
	} else { 
		// /* Otherwise, use a busy-wait loop for more accurate
		//    sub-tick timing.  We scale the numerator and denominator
		//    down by 1000 to avoid the possibility of overflow. */
		ASSERT (denom % 1000 == 0);
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
		// timer_sleep (1);
	}
}

