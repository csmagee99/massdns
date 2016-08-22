#include <stdbool.h>
#include <sys/time.h>

#include "../list.h"
#include "../security.h"

#ifndef RESOLVER_TIME_RING_H
#define RESOLVER_TIME_RING_H

typedef struct timeval timeval_t;

typedef struct
{
    single_list_t *lists;
    size_t max_units;
    timeval_t resolution;
    timeval_t last_update;
    timeval_t next_event;
    size_t offset;
} time_queue_t;

/**
 * Create a new time queue.
 *
 * @param max_units The maximum count of units
 * @param resolution The resolution of the time queue in microseconds.
 * @return
 */
void time_queue_init(time_queue_t *queue, size_t max_units, timeval_t resolution)
{
    queue->max_units = max_units;
    for (size_t i = 0; i < queue->max_units; i++)
    {
        single_list_init(&queue->lists[i]);
    }
    queue->resolution = resolution;
    queue->offset = 0;
    if (gettimeofday(&queue->last_update, NULL) != 0)
    {
        abort();
    }
}

time_queue_t *time_queue_new(size_t max_units, timeval_t resolution)
{
    time_queue_t *queue = safe_malloc(sizeof(*queue));
    queue->lists = safe_malloc(max_units * sizeof(*queue->lists));
    time_queue_init(queue, max_units, resolution);
    return queue;
}

static timeval_t time_queue_elapsed_since(time_queue_t *queue, timeval_t *time)
{
    timeval_t elapsed;
    elapsed.tv_sec = time->tv_sec - queue->last_update.tv_sec;
    if (time->tv_usec >= queue->last_update.tv_usec)
    {
        elapsed.tv_usec = time->tv_usec - queue->last_update.tv_usec;
    }
    else
    {
        elapsed.tv_sec -= 1;
        elapsed.tv_usec = time->tv_usec + 1000000 - queue->last_update.tv_usec;
    }
    return elapsed;
}

static timeval_t time_queue_elapsed(time_queue_t *queue)
{
    timeval_t now;
    if (gettimeofday(&now, NULL) != 0)
    {
        abort();
    }
    return time_queue_elapsed_since(queue, &now);
}

static size_t timeval_to_micros(timeval_t elapsed)
{
    return (size_t) elapsed.tv_sec * 1000000 + elapsed.tv_usec;
}

static size_t time_queue_elapsed_units(time_queue_t *queue)
{
    timeval_t elapsed = time_queue_elapsed(queue);
    return timeval_to_micros(elapsed) / timeval_to_micros(queue->resolution);
}

static size_t time_queue_elapsed_units_since(time_queue_t *queue, timeval_t *time)
{
    timeval_t elapsed = time_queue_elapsed_since(queue, time);
    return timeval_to_micros(elapsed) / timeval_to_micros(queue->resolution);
}

void **time_queue_add(time_queue_t *queue, timeval_t *time, void *element)
{
    size_t elapsed_units = time_queue_elapsed_units_since(queue, time);
    if (elapsed_units > queue->max_units)
    {
        elapsed_units = queue->max_units;
    }
    size_t pos = (queue->offset + elapsed_units) % queue->max_units;
    return single_list_push_back(&queue->lists[pos], element);
}

void time_queue_process_due(time_queue_t *queue, bool (*f)(void *, void *), void *context)
{
    timeval_t now;
    if (gettimeofday(&now, NULL) != 0)
    {
        abort();
    }
    size_t elapsed_units = time_queue_elapsed_units(queue);
    if(elapsed_units == 0) // This is inaccurate
    {
        // TODO: Floor based on resolution
        return;
    }
    queue->last_update = now;
    if (elapsed_units > queue->max_units)
    {
        elapsed_units = queue->max_units;
    }
    for (size_t i = 0; i < elapsed_units; i++)
    {
        size_t pos = (queue->offset + i) % queue->max_units;
        single_list_iterate_free(&queue->lists[pos], f, context);
    }
    queue->offset = (queue->offset + elapsed_units) % queue->max_units;
}

size_t time_queue_next(time_queue_t *queue)
{
    for (size_t i = 0; i < queue->max_units; i++)
    {
        size_t pos = (queue->offset + i) % queue->max_units;
        if(queue->lists[pos].count > 0)
        {
            return pos;
        }
    }
    return SIZE_MAX;
}

void time_queue_iterate_all(time_queue_t *queue, bool (*f)(void *, void *), void *context)
{
    for (size_t i = 0; i < queue->max_units; i++)
    {
        if (!single_list_iterate(&queue->lists[i], f, context))
        {
            return;
        }
    }
}

void time_queue_clear(time_queue_t *queue)
{
    for (size_t i = 0; i < queue->max_units; i++)
    {
        single_list_clear(&queue->lists[i]);
    }
    safe_free(&queue->lists);
}

void time_queue_free(time_queue_t *queue)
{
    time_queue_clear(queue);
    safe_free(&queue);
}

#endif //RESOLVER_TIME_RING_H
