# An application with its own u_bstream and u_sstream, which this tree then links instead of compiling vendor/ (D-290).
# Its copy is the vendored files moved out of the tree, so test/parent_streams.py can tell the two builds apart.
cmake_minimum_required (VERSION 3.11)
project (parent_streams C)

set(ZB_TREE "" CACHE PATH "The phoscon_zbstack tree under test")
set(PARENT_HEADER_SOURCE "" CACHE PATH "Where the application's u_bstream.h comes from: empty is the tree's own")

set(ULIB ${CMAKE_BINARY_DIR}/ulib)
file(COPY ${ZB_TREE}/vendor/u_bstream/u_bstream.c ${ZB_TREE}/vendor/u_sstream/u_sstream.c
          ${ZB_TREE}/vendor/u_sstream/u_sstream.h DESTINATION ${ULIB})
if (PARENT_HEADER_SOURCE)
    file(COPY ${PARENT_HEADER_SOURCE}/u_bstream.h DESTINATION ${ULIB})
else ()
    file(COPY ${ZB_TREE}/vendor/u_bstream/u_bstream.h DESTINATION ${ULIB})
endif ()

add_library(parent_ulib STATIC ${ULIB}/u_bstream.c ${ULIB}/u_sstream.c)
target_include_directories(parent_ulib PUBLIC ${ULIB})

set(ZB_U_STREAMS_LIBRARY parent_ulib CACHE STRING "" FORCE)
set(ZB_U_STREAMS_INCLUDE_DIR ${ULIB} CACHE PATH "" FORCE)
add_subdirectory(${ZB_TREE} zbstack)

add_executable(parent_app main.c)
target_link_libraries(parent_app PRIVATE zb_stack)
