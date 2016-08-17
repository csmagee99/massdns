#ifndef MASSDNS_AGENDA_H
#define MASSDNS_AGENDA_H

#include "cache.h"
#include "resolve.h"
#include <stdint.h>

typedef cache_key_t agenda_key_t;
typedef Hashmap *agenda_t;
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

typedef struct
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
} agenda_value_t;

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
    agenda_key->owner = owner;
    agenda_key->type = type;
    return agenda_key;
}

agenda_t agenda_new(size_t initial_capacity)
{
    return hashmapCreate(initial_capacity, cache_hash_entry, cache_keys_equal);
}

void agenda_free(agenda_t agenda)
{
    hashmapFree(agenda);
}

void agenda_put(agenda_t agenda, agenda_key_t *key, agenda_value_t *value)
{
#ifdef DEBUG
    char *type = ldns_rr_type2str(key->type);
    fprintf(stderr, "[Agenda] Add: %s %s\n", type, key->owner);
    free(type);
#endif
    hashmapPut(agenda, key, value);
}

void agenda_remove(agenda_t agenda, agenda_key_t *key)
{
    hashmapRemove(agenda, key);
}

void agenda_remove_from_data(agenda_t agenda, char *owner, ldns_rr_type type)
{
    agenda_key_t agenda_key = agenda_key_get(owner, type);
    agenda_remove(agenda, &agenda_key);
}

void *agenda_get(agenda_t agenda, agenda_key_t *key)
{
    return hashmapGet(agenda, key);
}

agenda_value_t *agenda_get_from_data(agenda_t agenda, char *owner, ldns_rr_type type)
{
    agenda_key_t agenda_key = agenda_key_get(owner, type);
    return agenda_get(agenda, &agenda_key);
}

void agenda_iterate(agenda_t agenda, bool (*callback)(void *, void *, void *), void *param)
{
    hashmapForEach(agenda, callback, param);
}

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

void agenda_value_update_time(agenda_value_t *value, time_t millis)
{
    gettimeofday(&value->next_try, NULL);
    value->next_try.tv_sec += millis / 1000;
    value->next_try.tv_usec += (millis % 1000) * 1000;
    value->next_try.tv_sec += value->next_try.tv_usec / 1000000;
    value->next_try.tv_usec %= 1000000;
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

void agenda_key_clear_dependants_callback(single_list_element_t *element, size_t i, void *param)
{
    agenda_value_t *requirement_value = element->data;
    requirement_value->unmet_requirement = false;
}

void agenda_key_clear_dependants(agenda_value_t *value)
{
    if (value->requirement_for)
    {
        single_list_iterate(value->requirement_for, agenda_key_clear_dependants_callback, NULL);
    }
}

void agenda_remove_rr_list(ldns_pkt* packet, agenda_t agenda, ldns_rr_list *list)
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

void agenda_key_safe_free(agenda_key_t **key)
{
    safe_free(&(*key)->owner);
    safe_free(key);
}

void address_list_safe_free(single_list_t **list)
{
    single_list_free_with_elements(*list);
    *list = NULL;
}

void free_ns_callback(single_list_element_t *element, size_t i, void *param)
{
    agenda_ns_t *agenda_ns = element->data;
    address_list_safe_free(&agenda_ns->addresses);
    safe_free(&agenda_ns->owner);
    safe_free(&agenda_ns);
    safe_free(&element);
}

void ns_list_safe_free(single_list_t **list)
{
    single_list_iterate(*list, free_ns_callback, NULL);
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

void agenda_remove_packet(agenda_t agenda, ldns_pkt *packet)
{
    agenda_remove_rr_list(packet, agenda, ldns_pkt_authority(packet));
    agenda_remove_rr_list(packet, agenda, ldns_pkt_additional(packet));
    agenda_remove_rr_list(packet, agenda, ldns_pkt_answer(packet));
}

#endif //MASSDNS_AGENDA_H
