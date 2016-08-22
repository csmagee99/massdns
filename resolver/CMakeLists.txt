cmake_minimum_required(VERSION 3.2)
project(resolver)

link_directories(/usr/lib)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c11")

set(SOURCE_FILES main.c
        agenda.h
        ../buffers.h
        cache.h
        ../hashmap.h
        ../list.h
        resolve.h
        root.h
        ../security.h
        ../string.h time_queue.h)

link_libraries(libldns.so)

set(LDNS_DIR /usr/include/ldns)

set(LDNS_FILES
        ${LDNS_DIR}/host2str.h
        ${LDNS_DIR}/host2wire.h
        ${LDNS_DIR}/wire2host.h
        ${LDNS_DIR}/dnssec.h)

add_executable(resolver ${SOURCE_FILES} ${LDNS_FILES})