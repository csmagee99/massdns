#ifndef MASSDNS_RESOLVE_H
#define MASSDNS_RESOLVE_H

#include "../list.h"
#include "cache.h"
#include "agenda.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

const char MASSDNS_ROOT_LABEL[] = ".";

typedef enum
{
    MASSDNS_IPV4 = 0x01,
    MASSDNS_IPV6 = 0x02
} massdns_ip_support_t;

typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_in sockaddr_in_t;
typedef struct sockaddr_in6 sockaddr_in6_t;

typedef struct
{
    void *component1;
    void *component2;
} tuple_t;

typedef struct
{
    char *owner;
    ldns_rr_type type;
    sockaddr_storage_t address;
} resolve_todo_t;

tuple_t *tuple_new(void *component1, void *component2)
{
    tuple_t *tuple = safe_malloc(sizeof(*tuple));
    tuple->component1 = component1;
    tuple->component2 = component2;
    return tuple;
}

/**
 * Count how often a particular character appear within a string.
 *
 * @param haystack The string to search in.
 * @param needle The character to be counted.
 * @return The character count.
 */
size_t string_char_occurrences(char *haystack, char needle)
{
    char c;
    size_t num = 0;
    while ((c = *haystack++) != 0)
    {
        if (c == needle)
        {
            num++;
        }
    }
    return num;
}

/**
 * Split a domain name into its labels, ordered from the highest to the lowest label (left to right).
 *
 * @param haystack The uncompressed domain name terminated by a dot.
 * @return A buffer containing the number of labels and the labels as an array of strings. The buffer data has to be
 * freed.
 */
buffer_t dname_split(char *haystack)
{
    char *haystack_copy = safe_malloc(strlen(haystack) + 1);
    strcpy(haystack_copy, haystack);
    buffer_t buf;
    buf.len = string_char_occurrences(haystack_copy, '.');
    buf.data = safe_malloc(sizeof(char *) * buf.len);
    size_t index = 0;
    char c;
    if (buf.len == 0)
    {
        return buf;
    }
    ((char **) buf.data)[index++] = haystack_copy;
    while ((c = *haystack_copy) != 0)
    {
        if (c == '.')
        {
            if (index < buf.len)
            {
                ((char **) buf.data)[index++] = haystack_copy + 1;
            }
            *haystack_copy = 0;
        }
        haystack_copy++;
    }
    return buf;
}

char *dname_join(char **source, size_t count)
{
    // TODO: Improve efficiency
    size_t total_len = 0;
    for (size_t i = 0; i < count; i++)
    {
        total_len += strlen(source[i]) + 1;
    }
    char *result = malloc(total_len + 1);
    result[total_len] = 0;
    size_t index = 0;
    for (size_t i = 0; i < count; i++)
    {
        size_t len = strlen(source[i]);
        strcpy(result + index, source[i]);
        index += len;
        result[index++] = '.';
    }
    return result;
}

/**
 * Create a dependency chain which has to be resolved from the front.
 *
 * e.g. A query for "example.org." will result in "example.org." -> "org." -> "."
 *
 * @return A list with string elements. The list and its elements should be freed.
 */
double_list_t *dependency_chain_new(char *owner)
{
    double_list_t *list = safe_calloc(sizeof(*list));

    buffer_t labels = dname_split(owner);
    for (size_t i = 0; i < labels.len; i++)
    {
        char *subname = dname_join((char **) labels.data + i, labels.len - i);
        double_list_push_back(list, subname);
    }
    char *root_label = malloc(sizeof(MASSDNS_ROOT_LABEL));
    strcpy(root_label, MASSDNS_ROOT_LABEL);
    double_list_push_back(list, root_label);
    return list;
}

/**
 * Minimize a dependency chain by considering the first cached entry only.
 *
 * @param list The full, unminimized dependency chain.
 * @param cache The cache.
 */
void dependency_chain_minimize(double_list_t *list, cache_t cache)
{
    double_list_element_t *current;
    size_t new_list_count = 0;
    double_list_element_t *new_last = NULL;
    for (current = list->first; current != NULL; current = current->next)
    {
        new_list_count++;
        if (cache_get_from_data(cache, (char *) current->data, LDNS_RR_TYPE_NS))
        {
            new_last = current;
            current = current->next;
            break;
        }
    }
    list->count = new_list_count;
    list->last = new_last;

    // Free the rest of the list
    while (current != NULL)
    {
        double_list_element_t *next = current->next;
        free(current->data);
        free(current);
        current = next;
    }
}

char *dependency_chain_next_nameserver(double_list_t *list)
{
    return list->last->data;
}

char *dependency_chain_query(double_list_t *list)
{
    return list->first->data;
}

void dependency_chain_free(double_list_t *list)
{
    for (double_list_element_t *elm = list->first; elm != NULL;)
    {
        double_list_element_t *next_element = elm->next;
        free(elm->data);
        free(elm);
        elm = next_element;
    }
}

bool sockaddr_storage_from_record(ldns_rr *record, sockaddr_storage_t *addr)
{
    if (ldns_rr_get_type(record) == LDNS_RR_TYPE_A)
    {
        sockaddr_in_t *ipv4addr = (sockaddr_in_t *) addr;
        ipv4addr->sin_port = htons(53);
        ipv4addr->sin_family = AF_INET;
        ldns_rdf *rdf = ldns_rr_rdf(record, 0);
        memcpy(&ipv4addr->sin_addr, ldns_rdf_data(rdf), ldns_rdf_size(rdf));
        return true;
    }
    else if (ldns_rr_get_type(record) == LDNS_RR_TYPE_AAAA)
    {
        sockaddr_in6_t *ipv6addr = (sockaddr_in6_t *) addr;
        ipv6addr->sin6_port = htons(53);
        ipv6addr->sin6_family = AF_INET;
        ldns_rdf *rdf = ldns_rr_rdf(record, 0);
        memcpy(&ipv6addr->sin6_addr, ldns_rdf_data(rdf), ldns_rdf_size(rdf));
        return true;
    }
    return false;
}

char *ldns_rr_ns_value(ldns_rr *record)
{
    ldns_rdf *rdf = ldns_rr_rdf(record, 0);
    return ldns_rdf2str(rdf);
}

void agenda_value_set_next_nameservers(agenda_t agenda, cache_t cache, agenda_key_t *key, agenda_value_t *value,
                                       massdns_ip_support_t ip_support)
{
    buffer_t labels = dname_split(key->owner);
    char *subname = NULL;
    cache_value_t *cached_ns = NULL;
    for (size_t i = 0; i < labels.len; i++)
    {
        subname = dname_join((char **) labels.data + i, labels.len - i);
        cached_ns = cache_get_from_data(cache, subname, LDNS_RR_TYPE_NS);
        if (cached_ns)
        {
            break;
        }
        safe_free(&subname);
    }
    free(((char **) labels.data)[0]);
    safe_free(&labels.data);

    if (subname == NULL)
    {
        subname = safe_malloc(sizeof(MASSDNS_ROOT_LABEL));
        strcpy(subname, MASSDNS_ROOT_LABEL);
        cached_ns = cache_get_from_data(cache, subname, LDNS_RR_TYPE_NS);
    }
    safe_free(&subname);

    ns_list_safe_free(&value->nameservers);
    value->nameservers = NULL;

    value->nameservers = single_list_new();

    assert(cached_ns != NULL);
    for (size_t i = 0; i < ldns_rr_list_rr_count(cached_ns->records); i++)
    {
        ldns_rr *record = ldns_rr_list_rr(cached_ns->records, i);
        char *ns_name = ldns_rr_ns_value(record);

        if ((ip_support & MASSDNS_IPV4) != 0)
        {
            cache_value_t *ipv4_cache = cache_get_from_data(cache, ns_name, LDNS_RR_TYPE_A);
            agenda_ns_t *agenda_ns = safe_calloc(sizeof(*agenda_ns));
            agenda_ns->owner = ns_name;
            if (ipv4_cache && ipv4_cache->records)
            {
                single_list_push_front(value->nameservers,
                                       agenda_ns); // Push cached entries to the front to be processed first
                agenda_ns->addresses = single_list_new();
                for (size_t j = 0; j < ldns_rr_list_rr_count(ipv4_cache->records); j++)
                {
                    agenda_addr_t *addr = safe_calloc(sizeof(*addr));
                    sockaddr_storage_from_record(ldns_rr_list_rr(ipv4_cache->records, j), &addr->address);
                    single_list_push_front(agenda_ns->addresses, addr);
                }
            }
            else
            {
                single_list_push_back(value->nameservers, agenda_ns);
            }
        }
    }
}

agenda_ns_t *agenda_value_get_next_nameserver(agenda_value_t *value)
{
    if (value == NULL || single_list_count(value->nameservers) == 0)
    {
        return NULL;
    }
    return value->nameservers->first->data;
}

resolve_todo_t agenda_todo(agenda_t agenda, cache_t cache, agenda_key_t *key, agenda_value_t *value,
                           single_list_t *agenda_addition, massdns_ip_support_t ip_support)
{
    resolve_todo_t resolve_todo;
    resolve_todo.owner = key->owner;
    resolve_todo.type = key->type;
    agenda_ns_t *nameserver = agenda_value_get_next_nameserver(value);

    if (nameserver->addresses == NULL || single_list_count(nameserver->addresses) == 0) // NS has to be resolved first
    {
        fprintf(stderr, "Requirement: %s\n", nameserver->owner);
        agenda_key_t *new_key = safe_malloc(sizeof(*new_key));
        new_key->owner = nameserver->owner;
        new_key->type = LDNS_RR_TYPE_A;
        agenda_value_t *existing_value = agenda_get(agenda, new_key);
        if(!existing_value)
        {
            agenda_value_t *new_value = safe_calloc(sizeof(*new_value));
            new_value->requirement_for = single_list_new();
            single_list_push_back(new_value->requirement_for, value);
            agenda_value_update_time(new_value, 0);
            tuple_t *tuple = tuple_new(new_key, new_value);
            single_list_push_back(agenda_addition, tuple);

            value->unmet_requirement = true;
            agenda_value_set_next_nameservers(agenda, cache, new_key, new_value, ip_support);
        }
        else
        {
            safe_free(&new_key);
            if(!existing_value->requirement_for)
            {
                existing_value->requirement_for = single_list_new();
            }
            single_list_push_back(existing_value->requirement_for, value);
            value->unmet_requirement = true;
        }
    }
    else
    {
        resolve_todo.address = *((sockaddr_storage_t *) nameserver->addresses->first->data);
    }
    return resolve_todo;
}

ldns_pkt *query_from_todo(resolve_todo_t *todo)
{
    ldns_pkt *packet;
    if (LDNS_STATUS_OK ==
        ldns_pkt_query_new_frm_str(&packet, todo->owner, todo->type, LDNS_RR_CLASS_IN, LDNS_RD | LDNS_AD))
    {
        ldns_pkt_set_id(packet, 7432);
        return packet;
    }
    return NULL;
}

#endif //MASSDNS_RESOLVE_H
