#ifndef MASSDNS_CACHE_H
#define MASSDNS_CACHE_H

#include "../hashmap.h"
#include <ldns/rr.h>
#include <ldns/host2str.h>
#include <time.h>

typedef Hashmap *cache_t;

typedef struct
{
    char *owner;
    ldns_rr_type type;
} cache_key_t;

typedef struct
{
    ldns_rr_list *records;
    struct timeval insertion_time;
} cache_value_t;

bool cache_keys_equal(void *entry1, void *entry2)
{
    return strcmp(((cache_key_t *) entry1)->owner, ((cache_key_t *) entry2)->owner) == 0
           && ((cache_key_t *) entry1)->type == ((cache_key_t *) entry2)->type;
}

unsigned long djb2(cache_key_t *entry)
{
    unsigned long hash = 5381;
    int c;
    char *str = entry->owner;
    while ((c = *str++) != 0)
    {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    hash = ((hash << 5) + hash) + (unsigned long) entry->type;
    return hash;
}

/**
 * Hash cache entry for the use in hash based data structures.
 *
 * @param entry The cache key entry to be hashed.
 * @return A hash value.
 */
int cache_hash_entry(void *entry)
{
    return (int) djb2((cache_key_t *) entry);
}

cache_t cache_new(size_t initial_capacity)
{
    return hashmapCreate(initial_capacity, cache_hash_entry, cache_keys_equal);
}

void cache_free(cache_t cache)
{
    hashmapFree(cache);
}

void cache_put(cache_t cache, cache_key_t *key, cache_value_t *value)
{
#ifdef DEBUG
    ldns_rr *record = ldns_rr_list_rr(value->records, 0);
    ldns_rdf *rdf = ldns_rr_rdf(record, 0);
    char *data = ldns_rdf2str(rdf);
    char *type = ldns_rr_type2str(key->type);
    fprintf(stderr, "[Cache] Set: %s %s = %s\n", type, key->owner, data);
    free(type);
    free(data);
#endif
    hashmapPut(cache, key, value);
}

void cache_remove(cache_t cache, cache_key_t *key)
{
    hashmapRemove(cache, key);
}

cache_value_t *cache_get(cache_t cache, cache_key_t *key)
{
    return hashmapGet(cache, key);
}

cache_key_t cache_key_get(char *owner, ldns_rr_type type)
{
    cache_key_t cache_key;
    cache_key.owner = owner;
    cache_key.type = type;
    return cache_key;
}

cache_value_t *cache_get_from_data(cache_t cache, char *owner, ldns_rr_type type)
{
    cache_key_t cache_key = cache_key_get(owner, type);
    return cache_get(cache, &cache_key);
}

void cache_put_ldns_rr_list(cache_t cache, ldns_rr_list *list)
{
    cache_key_t *key = NULL;
    for(size_t i = 0; i < ldns_rr_list_rr_count(list); i++)
    {
        key = safe_malloc(sizeof(*key));
        ldns_rr *record = ldns_rr_clone(ldns_rr_list_rr(list, i));
        key->owner = ldns_rdf2str(ldns_rr_owner(record));
        key->type = ldns_rr_get_type(record);
        cache_value_t* cache_value = cache_get(cache, key);
        if(!cache_value)
        {
            cache_value = safe_malloc(sizeof(*cache_value));
            cache_value->records = NULL;
            gettimeofday(&cache_value->insertion_time, NULL);
            cache_put(cache, key, cache_value);
        }
        else
        {
            safe_free(&key->owner);
            safe_free(&key);
        }

        if(cache_value->records == NULL)
        {
            cache_value->records = ldns_rr_list_new();
        }

        ldns_rr_list_push_rr(cache_value->records, record);
    }
}

void cache_put_packet(cache_t cache, ldns_pkt *packet)
{
    cache_put_ldns_rr_list(cache, ldns_pkt_authority(packet));
    cache_put_ldns_rr_list(cache, ldns_pkt_additional(packet));
    cache_put_ldns_rr_list(cache, ldns_pkt_answer(packet));
}

#endif //MASSDNS_CACHE_H
