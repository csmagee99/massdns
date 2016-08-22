#ifndef MASSDNS_AGENDA_H
#define MASSDNS_AGENDA_H

#include "cache.h"
#include "resolve.h"
#include "time_queue.h"
#include "../list.h"
#include <stdint.h>

typedef struct
{
    void *component1;
    void *component2;
} tuple_t;

typedef struct
{
    void *component1;
    void *component2;
    void *component3;
} triple_t;

typedef cache_key_t agenda_key_t;
typedef struct
{
    Hashmap *map;
    time_queue_t *queue;
} *agenda_t;
typedef struct timeval timeval_t;

typedef struct sockaddr_in sockaddr_in_t;
typedef struct sockaddr_storage sockaddr_storage_t;

typedef struct
{
    char *owner;
    size_t tries;
    single_list_t *addresses; // List of agenda addresses
} agenda_ns_t;

typedef struct
{
    struct sockaddr_storage address;
    size_t tries;
} agenda_addr_t;

typedef struct agenda_value
{
    bool unmet_requirement; // Agenda entry required to be resolved before this entry can be proceeded with
    timeval_t next_try;
    uint8_t tries;
    single_list_t *nameservers;
    cache_t agenda_cache; /* Contains entries from the additional section of a packet in order to
        prevent cache poisoning but preserve performance */
    single_list_t *recipients; // List with elements of sockaddr_storage_t
    single_list_t *requirement_for;
    uint16_t transaction_id;
    ldns_pkt *reply_packet;
    agenda_key_t *key;

    bool remove;

    struct agenda_value **time_queue_entry;
} agenda_value_t;

void agenda_key_safe_free(agenda_key_t **key);

void agenda_remove(agenda_t agenda, agenda_key_t *key);

typedef struct
{
    sockaddr_storage_t address;
    uint16_t transaction_id;
} recipient_t;

agenda_key_t agenda_key_get(char *owner, ldns_rr_type type)
{
    return cache_key_get(owner, type);
}

agenda_key_t *agenda_key_new(char *owner, ldns_rr_type type)
{
    agenda_key_t *agenda_key = safe_malloc(sizeof(*agenda_key));
    agenda_key->owner = malloc(strlen(owner) + 1);
    strcpy(agenda_key->owner, owner);
    agenda_key->type = type;
    return agenda_key;
}

agenda_t agenda_new(size_t initial_capacity)
{
    agenda_t agenda = malloc(sizeof(*agenda));
    agenda->map = hashmapCreate(initial_capacity, cache_hash_entry, cache_keys_equal);
    timeval_t resolution =
            {
                    .tv_sec = 0, .tv_usec = 1000
            };
    agenda->queue = time_queue_new(3000, resolution);
    return agenda;
}

void agenda_free(agenda_t agenda)
{
    hashmapFree(agenda->map);
    safe_free(&agenda);
}

void agenda_put(agenda_t agenda, agenda_key_t *key, agenda_value_t *value)
{
#ifdef DEBUG
    char *type = ldns_rr_type2str(key->type);
    fprintf(stderr, "[Agenda] Add: %s %s\n", type, key->owner);
    safe_free(&type);
#endif
    hashmapPut(agenda->map, key, value);
    value->key = key;
    value->remove = false;
    value->time_queue_entry = (agenda_value_t **) time_queue_add(agenda->queue, &value->next_try, value);
}

bool agenda_key_clear_dependants_callback(void *element, void *param)
{
    agenda_value_t *requirement_value = element;
    requirement_value->unmet_requirement = false;
    return true;
}

void agenda_key_clear_dependants(agenda_value_t *value)
{
    if (value->requirement_for)
    {
        single_list_iterate(value->requirement_for, agenda_key_clear_dependants_callback, NULL);
    }
}

agenda_value_t *agenda_get(agenda_t agenda, agenda_key_t *key)
{
    return hashmapGet(agenda->map, key);
}

agenda_value_t *agenda_get_from_data(agenda_t agenda, char *owner, ldns_rr_type type)
{
    agenda_key_t agenda_key = agenda_key_get(owner, type);
    return agenda_get(agenda, &agenda_key);
}

void agenda_remove_from_data(agenda_t agenda, char *owner, ldns_rr_type type)
{
    agenda_key_t agenda_key = agenda_key_get(owner, type);
    agenda_remove(agenda, &agenda_key);
}

void agenda_remove_rr_list(ldns_pkt *packet, agenda_t agenda, ldns_rr_list *list, bool (*update)(void*, void *param), void *param)
{
    size_t list_count = ldns_rr_list_rr_count(list);
    for (size_t i = 0; i < list_count; i++)
    {
        ldns_rr *record = ldns_rr_list_rr(list, i);
        ldns_rdf *owner_rdf = ldns_rr_owner(record);
        char *owner = ldns_rdf2str(owner_rdf);
        agenda_value_t *value = agenda_get_from_data(agenda, owner, ldns_rr_get_type(record));
        if (value)
        {
            if (value->recipients == NULL || single_list_count(value->recipients) == 0)
            {
                single_list_iterate(value->requirement_for, update, param);
                agenda_key_clear_dependants(value);
                agenda_remove_from_data(agenda, owner, ldns_rr_get_type(record));
            }
            else
            {
                value->reply_packet = ldns_pkt_clone(packet);
            }
        }
        safe_free(&owner);
    }
}

void address_list_safe_free(single_list_t **list)
{
    if (*list != NULL)
    {
        single_list_free_with_elements(*list);
    }
    *list = NULL;
}

bool free_ns_callback(void *element, void *param)
{
    agenda_ns_t *agenda_ns = element;
    address_list_safe_free(&agenda_ns->addresses);
    safe_free(&agenda_ns->owner);
    safe_free(&agenda_ns);
    return true;
}

void ns_list_safe_free(single_list_t **list)
{
    if (*list != NULL)
    {
        single_list_iterate_free(*list, free_ns_callback, NULL);
    }
    safe_free(list);
}

void agenda_value_safe_free(agenda_value_t **value)
{
    ns_list_safe_free(&(*value)->nameservers);
    single_list_free_with_elements((*value)->recipients);
    (*value)->recipients = NULL;
    single_list_free((*value)->requirement_for);
    (*value)->requirement_for = NULL;
    safe_free(value);
}

void agenda_key_safe_free(agenda_key_t **key)
{
    safe_free(&(*key)->owner);
    safe_free(key);
}

void time_queue_remove_agenda_value(agenda_value_t *value)
{
    if (value->time_queue_entry != NULL)
    {
        *value->time_queue_entry = NULL;
        value->time_queue_entry = NULL;
    }
}

void agenda_removal_list_add(single_list_t *list, agenda_value_t *value)
{
    if(value->remove)
    {
        return;
    }
    value->remove = true;
    single_list_push_back(list, value);
}

void agenda_remove(agenda_t agenda, agenda_key_t *key)
{
    agenda_value_t *value = hashmapRemove(agenda->map, key);
    time_queue_remove_agenda_value(value);
    agenda_key_safe_free(&value->key);
    agenda_value_safe_free(&value);
}

bool due_wrapper(void *v, void *c)
{
    if (v == NULL)
    {
        return true;
    }
    /*if(((agenda_value_t *) v)->key == NULL)
    {
        // TODO: Check reason for condition fulfillment.
        return true;
    }*/
    bool (*callback)(agenda_key_t *, agenda_value_t *, void *) = ((tuple_t *) c)->component1;
    //agenda_value_t *value = agenda_get((agenda_t) (((triple_t *) c)->component3), (agenda_key_t *) k);
    ((agenda_value_t *)v)->time_queue_entry = NULL;
    return callback(((agenda_value_t *) v)->key, ((agenda_value_t *) v), ((tuple_t *) c)->component2);
}

void agenda_iterate_due(agenda_t agenda, bool (*callback)(agenda_key_t *, agenda_value_t *, void *), void *param)
{
    tuple_t tuple;
    tuple.component1 = callback;
    tuple.component2 = param;
    time_queue_process_due(agenda->queue, due_wrapper, &tuple);
}

/*void agenda_iterate_due(agenda_t agenda, bool (*callback)(void*, void *), void *param)
{
    time_queue_process_due(agenda->queue, callback, param);
}*/

bool agenda_value_has_requirement(agenda_value_t *value)
{
    return value->unmet_requirement;
}

bool agenda_value_is_due(agenda_value_t *value)
{
    timeval_t now;
    gettimeofday(&now, NULL);
    return now.tv_sec > value->next_try.tv_sec
           || now.tv_sec == value->next_try.tv_sec && now.tv_usec >= value->next_try.tv_usec;
}

void agenda_value_update_time(agenda_t agenda, agenda_value_t *value, time_t millis)
{
    fprintf(stderr, "Update time: %s to %zu ms\n", value->key->owner, millis);
    time_queue_remove_agenda_value(value);
    gettimeofday(&value->next_try, NULL);
    value->next_try.tv_usec += millis * 1000;
    value->next_try.tv_sec += value->next_try.tv_usec / 1000000;
    value->next_try.tv_usec %= 1000000;
    value->time_queue_entry = (agenda_value_t **) time_queue_add(agenda->queue, &value->next_try, value);
}

void agenda_value_add_recipient(agenda_value_t *value, uint16_t transaction_id, sockaddr_storage_t addr)
{
    if (value->recipients == NULL)
    {
        value->recipients = single_list_new();
    }
    recipient_t *recipient = malloc(sizeof(*recipient));
    recipient->address = addr;
    recipient->transaction_id = transaction_id;
    single_list_push_back(value->recipients, recipient);
}

void agenda_remove_packet(agenda_t agenda, ldns_pkt *packet, bool (*update)(void*, void *param), void *param)
{
    agenda_remove_rr_list(packet, agenda, ldns_pkt_authority(packet), update, param);
    agenda_remove_rr_list(packet, agenda, ldns_pkt_additional(packet), update, param);
    agenda_remove_rr_list(packet, agenda, ldns_pkt_answer(packet), update, param);
}

#endif //MASSDNS_AGENDA_H
