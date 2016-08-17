#ifndef MASSDNS_ROOT_H
#define MASSDNS_ROOT_H

#include <ldns/packet.h>
#include <ldns/rbtree.h>
#include <ldns/keys.h>
#include <ldns/wire2host.h>
#include <ldns/host2str.h>
#include <ldns/host2wire.h>

#include "cache.h"
#include "../security.h"

/**
 * Check whether a line within the root hint file is empty or a comment
 *
 * @param line The line string.
 * @return A boolean which is true if the line is empty or a comment.
 */
bool hint_emtpy_or_comment(char *line)
{
    char c;
    while ((c = *line++) != 0)
    {
        if (c == ';')
        {
            return true;
        }
        if (c != ' ')
        {
            return false;
        }
    }
    return true;
}

/**
 * Add root hints to a given cache.
 *
 * @param cache The cache which the hints are supposed to be added to.
 * @param filename The filename of the root hints file in the format provided by InterNIC.
 */
void root_hints_from_file(cache_t cache, char *filename)
{
    FILE *f = fopen(filename, "r");
    if(!f)
    {
        perror("Reading root hints failed");
        abort();
    }
    size_t line_len = 4096;
    char *line = safe_malloc(line_len);
    char ownerbuf[256];
    char rnamebuf[256];
    char rdfvalbuf[256];
    size_t line_num = 0;
    while (!feof(f))
    {
        ssize_t read = getline(&line, &line_len, f);
        strtolower(line);
        if (read < 0 && !feof(f))
        {
            perror("Reading root hints failed");
            abort();
        }
        line_num++;
        if (!hint_emtpy_or_comment(line))
        {
            ldns_rr* record;
            if(LDNS_STATUS_OK == ldns_rr_new_frm_str(&record, line, 86400, NULL, NULL))
            {
                cache_key_t* cache_key = safe_calloc(sizeof(*cache_key));
                ldns_rdf* rdf = ldns_rr_owner(record);
                cache_key->owner = ldns_rdf2str(rdf);
                cache_key->type = ldns_rr_get_type(record);
                cache_value_t* cache_value = cache_get(cache, cache_key);
                if(!cache_value)
                {
                    cache_value = safe_calloc(sizeof(*cache_value));
                    cache_value->records = ldns_rr_list_new();
                    if (gettimeofday(&cache_value->insertion_time, NULL) != 0)
                    {
                        fprintf(stderr, "FATAL: Failed to obtain current time.\n");
                        abort();
                    }
                    cache_put(cache, cache_key, cache_value);
                }
                else
                {
                    free(cache_key->owner);
                    free(cache_key);
                }
                ldns_rr_list_push_rr(cache_value->records, record);
            }
            else
            {
                fprintf(stderr, "[FATAL] The root hints file \"%s\" contains an invalid line:\n%s\n", filename, line);
                abort();
            }
        }
    }
    free(line);
}

#endif //MASSDNS_ROOT_H
