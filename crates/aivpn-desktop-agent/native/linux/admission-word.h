#pragma once

#define SA_PREPARED 0ULL
#define SA_ADMITTED 1ULL
#define SA_RETIRED 2ULL
#define SA_UPDATING 3ULL
#define SA_ID_LIMIT (~0ULL >> 2)

static __always_inline unsigned long long sa_read(unsigned long long *word) {
    return __sync_fetch_and_add(word, 0);
}

static __always_inline int sa_stable(unsigned long long word) {
    return (word >> 2) && (word & 3) < SA_RETIRED;
}

/* Ни один переход не восстанавливает прежний id после изменения payload. */
static __always_inline int sa_claim(unsigned long long *word, unsigned long long expected) {
    if (!(expected >> 2) || (expected & 3) == SA_UPDATING ||
        (expected & 3) == SA_ADMITTED)
        return 0;
    return __sync_val_compare_and_swap(word, expected, (expected & ~3ULL) | SA_UPDATING) == expected;
}

static __always_inline int sa_publish(unsigned long long *word, unsigned long long previous,
                                      unsigned long long id) {
    if (!id || id > SA_ID_LIMIT || id <= (previous >> 2))
        return 0;
    return __sync_val_compare_and_swap(word, (previous & ~3ULL) | SA_UPDATING,
                                       id << 2) == ((previous & ~3ULL) | SA_UPDATING);
}

static __always_inline int sa_admit(unsigned long long *word, unsigned long long expected) {
    if (!sa_stable(expected)) return 0;
    return __sync_val_compare_and_swap(word, expected, expected | SA_ADMITTED) == expected;
}

static __always_inline int sa_retire(unsigned long long *word, unsigned long long expected) {
    if (!sa_stable(expected)) return 0;
    return __sync_val_compare_and_swap(word, expected, (expected & ~3ULL) | SA_RETIRED) == expected;
}

/* Один счетчик lifetime обслуживает graph и tracing; пропуски ID допустимы. */
static __always_inline unsigned long long sa_next_id(unsigned long long *next) {
    for (unsigned attempt = 0; attempt < 8; attempt++) {
        unsigned long long previous = sa_read(next);
        if (previous >= SA_ID_LIMIT) return 0;
        if (__sync_val_compare_and_swap(next, previous, previous + 1) == previous)
            return previous + 1;
    }
    return 0;
}

/* Только GC может забрать ADMITTED для проверки idle, не для смены маршрута. */
static __always_inline int sa_gc_claim(unsigned long long *word, unsigned long long expected) {
    if (!(expected >> 2) || (expected & 3) == SA_UPDATING) return 0;
    return __sync_val_compare_and_swap(word, expected, (expected & ~3ULL) | SA_UPDATING) == expected;
}

/* id=0/RETIRED окончателен. Rollback разрешен лишь без записи в payload. */
static __always_inline int sa_gc_finish(unsigned long long *word, unsigned long long previous,
                                       int detached) {
    return __sync_val_compare_and_swap(word, (previous & ~3ULL) | SA_UPDATING,
                                       detached ? SA_RETIRED : previous) ==
           ((previous & ~3ULL) | SA_UPDATING);
}
