#define DEBUG

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include <sys/resource.h>

#include <ldns/packet.h>
#include <ldns/rbtree.h>
#include <ldns/keys.h>
#include <ldns/wire2host.h>
#include <ldns/host2str.h>
#include <ldns/host2wire.h>

#include "../buffers.h"
#include "../security.h"
#include "../list.h"
#include "../string.h"

#include "cache.h"
#include "root.h"
#include "resolve.h"
#include "agenda.h"

typedef enum
{
    MASSDNS_SOCKET_QUERY = 0x01,
    MASSDNS_SOCKET_CLIENT = 0x02
} massdns_socket_t;

typedef struct
{
    int query_socket; //! Socket descripter providing the server interface
    buffer_t client_sockets; //! Socket descriptors providing
    agenda_t agenda; //! Contains records that are about to be resolved
    cache_t cache; //! Contains records that have been successfully resolved
    size_t tries; //! Number of tries to resolve before giving up
    size_t agenda_size;
    size_t cache_size;
    massdns_ip_support_t ip_support;

    single_list_t *agenda_removal;
    single_list_t *agenda_addition;

    time_t retry_after_ms;
} context_t;

typedef struct
{
    massdns_socket_t type;
    int descriptor;
} socket_info_t;

void double_list_print(double_list_element_t *element, size_t index, void *param)
{
    fprintf(stderr, "%s\n", (char *) element->data);
}

bool agenda_handle(agenda_key_t* key, agenda_value_t *value, void *p);

void resolver_handle_query(context_t *context, socket_info_t *socket, sockaddr_storage_t addr, ldns_pkt *packet)
{
    ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(packet), 0);
    ldns_rdf *rdf = ldns_rr_owner(question);
    char *owner = ldns_rdf2str(rdf);
    ldns_rr_type qtype = ldns_rr_get_type(question);
    uint16_t transaction_id = ldns_pkt_id(packet);
    char *typestr = ldns_rr_type2str(qtype);
    fprintf(stderr, "[Packet] Incoming request: %s %s\n", typestr, owner);
    safe_free(&typestr);
    agenda_key_t *agenda_key = agenda_key_new(owner, qtype);
    agenda_value_t *agenda_value = agenda_get(context->agenda, agenda_key);

    if (agenda_value) // The request is already on our agenda, just add a recipient
    {
        // TODO: Only add if recipient is new
        agenda_value_add_recipient(agenda_value, transaction_id, addr);
        safe_free(&owner);
        agenda_key_safe_free(&agenda_key);
        return;
    }
    agenda_value = safe_calloc(sizeof(*agenda_value));
    agenda_put(context->agenda, agenda_key, agenda_value);
    agenda_value_add_recipient(agenda_value, transaction_id, addr);
    agenda_value_update_time(context->agenda, agenda_value, 0);
    agenda_value_set_next_nameservers(context->agenda, context->cache, agenda_key, agenda_value, context->ip_support);

    //agenda_handle(agenda_key, agenda_value, context);
    safe_free(&owner);
}

bool handle_helper(void *v, void *param)
{
    //agenda_handle(((agenda_value_t*)v)->key, (agenda_value_t*)v, param);
    return true;
}

void resolver_handle_response(context_t *context, socket_info_t *socket, sockaddr_storage_t addr, ldns_pkt *packet)
{
    fprintf(stderr, "RESPONSE\n");
    ldns_rr_list *questions = ldns_pkt_question(packet);
    if (ldns_rr_list_rr_count(questions) == 1) // We don't support queries with more or less than one question
    {
        ldns_rr *question = ldns_rr_list_rr(questions, 0);
        ldns_rdf *owner_rdf = ldns_rr_owner(question);
        char *owner = ldns_rdf2str(owner_rdf);

        ldns_rr_type type = ldns_rr_get_type(question);
        char *typestr = ldns_rr_type2str(ldns_rr_get_type(question));
        fprintf(stderr, "[Packet] Incoming response: %s %s\n", owner, typestr);
        safe_free(&typestr);
        cache_put_packet(context->cache, packet);

        // If we have received an update for an agenda value, directly continue resolving
        agenda_value_t *value = agenda_get_from_data(context->agenda, owner, type);
        if (value)
        {
            agenda_value_update_time(context->agenda, value, 0);
            if(ldns_pkt_get_rcode(packet) != LDNS_RCODE_NOERROR)
            {
                value->reply_packet = ldns_pkt_clone(packet);
            }
            //agenda_handle(value->key, value, context);
        }
        agenda_remove_packet(context->agenda, packet, handle_helper, context);



        safe_free(&owner);
    }
}

bool resolver_receive(context_t *context, socket_info_t *socket)
{
    uint8_t buf[0xFFFF];
    struct sockaddr_storage recvaddr;
    socklen_t fromlen = sizeof(recvaddr);
    ssize_t num_received = recvfrom(socket->descriptor, buf, sizeof(buf), 0, (struct sockaddr *) &recvaddr, &fromlen);
    if (num_received > 0)
    {
        ldns_pkt *packet = NULL;
        if (LDNS_STATUS_OK == ldns_wire2pkt(&packet, buf, (size_t) num_received)) // cast to size_t is safe because > 0
        {
            if (!ldns_pkt_qr(packet) && (socket->type & MASSDNS_SOCKET_QUERY) != 0) // Packet received on a query socket
            {
                resolver_handle_query(context, socket, recvaddr, packet);
            }
            else if (ldns_pkt_qr(packet)) // Reply to query received
            {
                resolver_handle_response(context, socket, recvaddr, packet);
            }
            ldns_pkt_free(packet);
        }
        return true;
    }
    return false;
}

bool agenda_reply(void *element, void *param)
{
    tuple_t *tuple = param;
    context_t *context = tuple->component1;
    agenda_value_t *value = tuple->component2;
    ldns_pkt *packet = value->reply_packet;
    recipient_t *recipient = element;

    uint8_t *buffer;
    size_t buffer_size;
    ldns_pkt_set_id(packet, recipient->transaction_id);
    if (LDNS_STATUS_OK != ldns_pkt2wire(&buffer, packet, &buffer_size))
    {
        abort();
    }

    int fd = context->query_socket;
    ssize_t sent;
    do
    {
        sent = sendto(fd, buffer, buffer_size, 0, (sockaddr_t *) &recipient->address, sizeof(sockaddr_in_t));
    }
    while(sent == 0);
    safe_free(&buffer);
    return true;
}

bool agenda_handle(agenda_key_t* key, agenda_value_t *value, void *p)
{
    context_t *context = p;
    if (agenda_value_has_requirement(value)) // This agenda entry depends on another one
    {
        return true;
    }
    if (value->tries++ >= context->tries)
    {
        fprintf(stderr, "[Agenda] Remove: %s\n", key->owner);
        agenda_removal_list_add(context->agenda_removal, value);
        return true;
    }
    agenda_value_update_time(context->agenda, value, context->retry_after_ms);

    if (!value->reply_packet)
    {
        fprintf(stderr, "[Agenda] Resolve: %s\n", key->owner);
        agenda_value_set_next_nameservers(context->agenda, context->cache, key, value, context->ip_support);

        resolve_todo_t resolve_todo;
        if(!agenda_todo(context->agenda, context->cache, key, value,
                                                  context->agenda_addition, context->ip_support, &resolve_todo))
        {
            return true;
        }
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((struct sockaddr_in *)&resolve_todo.address)->sin_addr, buf, INET_ADDRSTRLEN);
        fprintf(stderr, "IP: %s\n", buf);
        ldns_pkt *packet = query_from_todo(&resolve_todo);
        if (packet == NULL)
        {
            abort();
        }


        // TODO: Correctly select socket
        uint8_t *buffer;
        size_t buffer_size;
        if (LDNS_STATUS_OK != ldns_pkt2wire(&buffer, packet, &buffer_size))
        {
            abort();
        }
        int fd = context->query_socket;
        ssize_t sent;
        do
        {
            sent = sendto(fd, buffer, buffer_size, 0, (sockaddr_t *) &resolve_todo.address, sizeof(sockaddr_in_t));
        }
        while(sent == 0);
        ldns_pkt_free(packet);
        safe_free(&buffer);
    }
    else
    {
        fprintf(stderr, "[Agenda] Reply: %s\n", key->owner);
        tuple_t tuple;
        tuple.component1 = context;
        tuple.component2 = value;
        single_list_iterate(value->recipients, agenda_reply, &tuple);
        ldns_pkt_free(value->reply_packet);
        value->reply_packet = NULL;
        fprintf(stderr, "[Agenda] Remove: %s\n", key->owner);
        agenda_removal_list_add(context->agenda_removal, value);
        return true;
    }
    return true;
}

bool agenda_removal_handler(void *data, void *param)
{
    //fprintf(stderr, "P: %p\n", data);
    agenda_remove(((context_t*)param)->agenda, ((agenda_value_t*)data)->key);
    return true;
}

bool agenda_addition_handler(void *data, void *param)
{
    agenda_put(((context_t*)param)->agenda, ((agenda_value_t *)data)->key, (agenda_value_t *)data);
    return true;
}
void resolver_send(context_t *context, socket_info_t *socket)
{
    agenda_iterate_due(context->agenda, &agenda_handle, context);
    //fprintf(stderr, "C: %zu\n", context->agenda_removal->count);
    single_list_iterate_free(context->agenda_removal, &agenda_removal_handler, context);
    single_list_iterate_free(context->agenda_addition, &agenda_addition_handler, context);
}

bool process(void *data, void *ctx)
{
    fprintf(stderr, "Process: %s\n", (char*)data);
    return true;
}

int main(int argc, char **argv)
{
    /*char *data = "abcdefg";
    timeval_t res;
    res.tv_sec = 0;
    res.tv_usec = 1000;
    time_queue_t *tqueue = time_queue_new(10000, res);
    timeval_t time;
    gettimeofday(&time, NULL);
    time.tv_sec += 5;
    time_queue_add(tqueue, &time, data);
    while(true)
    {
        fprintf(stderr, "Process...\n");
        time_queue_process_due(tqueue, process, NULL);
        sleep(1);
    }*/

    struct rlimit core_limits;
    core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &core_limits);
    context_t *context = malloc(sizeof(*context));
    memset(context, 0, sizeof(context));
    context->cache = cache_new(100000);
    context->agenda = agenda_new(100000);
    context->tries = 10;
    context->retry_after_ms = 1000;
    context->ip_support = MASSDNS_IPV4;

    context->agenda_removal = single_list_new();
    context->agenda_addition = single_list_new();

    root_hints_from_file(context->cache, "named.root");

    context->query_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in_t server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(1054);

    int socketbuf = 1024 * 1024 * 100;
    if (setsockopt(context->query_socket, SOL_SOCKET, SO_SNDBUF, &socketbuf, sizeof(socketbuf)) != 0)
    {
        perror("Failed to adjust socket send buffer size.");
    }
    if (setsockopt(context->query_socket, SOL_SOCKET, SO_RCVBUF, &socketbuf, sizeof(socketbuf)) != 0)
    {
        perror("Failed to adjust socket receive buffer size.");
    }

    if (bind(context->query_socket, (sockaddr_t *) &server_addr, sizeof(server_addr)) != 0)
    {
        perror("Could not bind socket");
        abort();
    }

    fcntl(context->query_socket, F_SETFL, fcntl(context->query_socket, F_GETFL, 0) | O_NONBLOCK);

    int epollfd = epoll_create(1);
    struct epoll_event ev = {0};
    socket_info_t *query_socket_info = safe_calloc(sizeof(*query_socket_info));
    query_socket_info->descriptor = context->query_socket;
    query_socket_info->type = MASSDNS_SOCKET_QUERY | MASSDNS_SOCKET_CLIENT;
    ev.data.ptr = query_socket_info;
    ev.events = EPOLLIN | EPOLLOUT;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, context->query_socket, &ev) != 0)
    {
        perror("Error adding epoll event");
        abort();
    }
    struct epoll_event pevents[10000];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
    while (true)
    {
        size_t timeout = time_queue_next(context->agenda->queue);
        int timeout_ms = -1;
        if(timeout != SIZE_MAX)
        {
            timeout_ms = (int)timeout;
        }
        int ready = epoll_wait(epollfd, pevents, 10000, timeout_ms);
        if (ready < 0)
        {
            fprintf(stderr, "to\n");
            // TODO: Add error handling
        }
        else if (ready == 0)
        {
            // Timeout
            fprintf(stderr, "to\n");
            resolver_send(context, query_socket_info);
            // TODO: Add error handling
        }
        else
        {

            for (int i = 0; i < ready; i++)
            {
                if (pevents[i].events & EPOLLIN) // Data can be received
                {
                    resolver_receive(context, pevents[i].data.ptr);
                }
                if (pevents[i].events & EPOLLOUT) // Data can be sent
                {
                    resolver_send(context, pevents[i].data.ptr);
                }
            }
        }
    }
#pragma clang diagnostic pop
}