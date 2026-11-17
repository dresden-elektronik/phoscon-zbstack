cmake_minimum_required (VERSION 3.11)

# The version is src/zb/zb_version.h's, read here so the two cannot disagree.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/src/zb/zb_version.h" ZB_VERSION_LINES REGEX "^#define ZB_VERSION_(MAJOR|MINOR|PATCH) ")
string(REGEX REPLACE ".*ZB_VERSION_MAJOR ([0-9]+).*" "\\1" ZB_VERSION_MAJOR "${ZB_VERSION_LINES}")
string(REGEX REPLACE ".*ZB_VERSION_MINOR ([0-9]+).*" "\\1" ZB_VERSION_MINOR "${ZB_VERSION_LINES}")
string(REGEX REPLACE ".*ZB_VERSION_PATCH ([0-9]+).*" "\\1" ZB_VERSION_PATCH "${ZB_VERSION_LINES}")

project (phoscon_zbstack VERSION ${ZB_VERSION_MAJOR}.${ZB_VERSION_MINOR}.${ZB_VERSION_PATCH} LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if (NOT MSVC)
    add_compile_options(-Wall -Wextra -pedantic)
else ()
    # The tools and suites read files and numbers with C99's own fopen and sscanf, which MSVC deprecates in favour of
    # its _s calls; those are not C99.
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif ()

# A project that adds this directory gets the libraries alone; the tools, the examples and the suites are this tree's.
if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(ZB_TOP_LEVEL ON)
else ()
    set(ZB_TOP_LEVEL OFF)
endif ()
option(ZB_BUILD_TREE "Build the tools, examples and suites beside the libraries" ${ZB_TOP_LEVEL})

option(ZB_SANITIZE "Build Debug with AddressSanitizer and UndefinedBehaviorSanitizer" ${ZB_TOP_LEVEL})

if (ZB_SANITIZE AND CMAKE_C_COMPILER_ID MATCHES "Clang|GNU" AND CMAKE_BUILD_TYPE MATCHES "Debug")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif ()

# Band C: portable rings plus one device-ops implementation per target. A target is
# chosen by which files are linked (docs/internals/coding-rules.md §1, docs/porting.md §3).
set(ZB_PORT_SRCS
        src/port/port.c
        src/port/port_null.c
        src/port/log_names.c
        src/port/port_locate.c
)
if (UNIX)
    list(APPEND ZB_PORT_SRCS src/port/port_posix.c src/port/port_log_posix.c src/port/port_file_posix.c
            src/port/port_locate_sysfs.c)

    if (APPLE)
        list(APPEND ZB_PORT_SRCS src/port/port_locate_darwin.c)
    else ()
        list(APPEND ZB_PORT_SRCS src/port/port_locate_linux.c)
    endif ()
elseif (WIN32)
    list(APPEND ZB_PORT_SRCS src/port/port_win32.c src/port/port_log_win32.c src/port/port_file_win32.c
            src/port/port_locate_win32.c)
endif ()

# Substrate below the bands: our own byte and text primitives, so that no file under src/
# needs a hosted header (docs/internals/coding-rules.md §1, §4.6), and what this stack adds to the
# vendored U_BStream (docs/internals/refs.md §6).
add_library(zb_utils STATIC src/utils/zb_utils.c src/utils/zb_time.c src/utils/zb_bstream.c)
target_include_directories(zb_utils PUBLIC src/utils)
target_link_libraries(zb_utils PUBLIC u_bstream)

# Substrate below the bands: the log pool. Integer records only: the human line is built
# host-side, by a platform sink in src/port or by a suite or a tool (docs/internals/coding-rules.md §5,
# docs/internals/coding-rules.md §5).
add_library(zb_log STATIC src/log/log.c)
target_include_directories(zb_log PUBLIC src/log src/seam)

# Vendored third-party code: verbatim at a pinned revision, recorded in vendor/MANIFEST
# and re-hashed by the `vendor` suite (docs/internals/refs.md §6). An application that links its own copy at the same
# pins names it instead, and vendor/ is not compiled; its headers must hash as vendor/MANIFEST says (D-290).
set(ZB_U_STREAMS_LIBRARY "" CACHE STRING "The application's library holding u_bstream and u_sstream; empty builds vendor/")
set(ZB_U_STREAMS_INCLUDE_DIR "" CACHE PATH "The directory holding that library's u_bstream.h and u_sstream.h")
if (NOT ZB_U_STREAMS_LIBRARY)
    add_library(u_bstream STATIC vendor/u_bstream/u_bstream.c)
    target_include_directories(u_bstream PUBLIC vendor/u_bstream)

    add_library(u_sstream STATIC vendor/u_sstream/u_sstream.c)
    target_include_directories(u_sstream PUBLIC vendor/u_sstream)
else ()
    foreach (header u_bstream.h u_sstream.h)
        file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/vendor/MANIFEST pinned REGEX "^${header}=")
        string(REPLACE "${header}=" "" pinned "${pinned}")
        if (NOT EXISTS ${ZB_U_STREAMS_INCLUDE_DIR}/${header})
            message(FATAL_ERROR "ZB_U_STREAMS_INCLUDE_DIR holds no ${header}")
        endif ()
        file(SHA256 ${ZB_U_STREAMS_INCLUDE_DIR}/${header} found)
        if (NOT found STREQUAL pinned)
            message(FATAL_ERROR "${ZB_U_STREAMS_INCLUDE_DIR}/${header} is not the revision vendor/MANIFEST pins")
        endif ()
        configure_file(${ZB_U_STREAMS_INCLUDE_DIR}/${header} ${CMAKE_CURRENT_BINARY_DIR}/u_streams/${header} COPYONLY)
    endforeach ()

    # The two checked headers alone go on the tree's path, and the library is linked without its own include
    # directories, so another header of the application's (an aps.h, a zcl.h) never stands in for one of ours.
    add_library(u_bstream INTERFACE)
    target_include_directories(u_bstream INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/u_streams)
    target_link_libraries(u_bstream INTERFACE $<LINK_ONLY:${ZB_U_STREAMS_LIBRARY}>)

    add_library(u_sstream INTERFACE)
    target_include_directories(u_sstream INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/u_streams)
    target_link_libraries(u_sstream INTERFACE $<LINK_ONLY:${ZB_U_STREAMS_LIBRARY}>)
endif ()

# Band B: the Spinel side over band C. One dialect driver for now: both ConBee IIs answer
# identically (docs/internals/hardware.md §3).
# Band B's backend needs band C: a stick is reached through a port, and nothing else in band B may
# know one exists.
add_library(zb_rcp
    STATIC
    src/rcp/hdlc.c
    src/rcp/spinel.c
    src/rcp/spinel_session.c
    src/rcp/props.c
    src/rcp/rcp_radio.c
)
target_include_directories(zb_rcp PUBLIC src/rcp src/seam)
target_link_libraries(zb_rcp PUBLIC zb_utils u_bstream zb_port)

# Band A: the library. The MAC layer of it knows no device, no port, no dialect and no clock
# (docs/internals/architecture.md §1), which is why it links against the two substrates and nothing else.
# `security` is the one part of band A that does have a band below it: the CCM* seam of src/crypto is
# what 4.3.1.1 step 3 and 4.3.1.2 step 4 run on, and the
# log pool is where its refusals are recorded (docs/internals/coding-rules.md §5).
# `aps`, `aps_ack`, `aps_dup`, `aps_frame`, `aps_group`, `aps_rx` and `aps_tx` are chapter 2 of the same
# band, split into topic modules of one directory: the service reaches the radio only through `nwk`,
# which is why it adds no library and no include of its own below that layer.
add_library(zb_mac STATIC src/zb/af/af.c src/zb/zcl/zcl.c src/zb/zdo/zdo.c src/zb/mac_frame.c src/zb/aps/aps.c src/zb/aps/aps_admit.c src/zb/aps/aps_tclink.c src/zb/mac/mac.c src/zb/mac/mac_assoc.c src/zb/mac/mac_beacon.c src/zb/mac/mac_indirect.c src/zb/mac/mac_rx.c src/zb/mac/mac_scan.c src/zb/mac/mac_tx.c src/zb/nwk/nwk.c src/zb/nwk/nwk_addr.c src/zb/nwk/nwk_beacon.c src/zb/nwk/nwk_btt.c src/zb/nwk/nwk_command.c src/zb/nwk/nwk_commissioning.c src/zb/nwk/nwk_cost.c src/zb/nwk/nwk_discovery.c src/zb/nwk/nwk_frame.c src/zb/nwk/nwk_indirect.c src/zb/nwk/nwk_join.c src/zb/nwk/nwk_leave.c src/zb/nwk/nwk_get.c src/zb/nwk/nwk_linkstatus.c src/zb/nwk/nwk_neighbor.c src/zb/nwk/nwk_parents.c src/zb/nwk/nwk_permit.c src/zb/nwk/nwk_poll.c src/zb/nwk/nwk_relay.c src/zb/nwk/nwk_route.c src/zb/nwk/nwk_rrep.c src/zb/nwk/nwk_rreprx.c src/zb/nwk/nwk_rreq.c src/zb/nwk/nwk_rreqrelay.c src/zb/nwk/nwk_rreqrx.c src/zb/nwk/nwk_rreqtx.c src/zb/nwk/nwk_rx.c src/zb/nwk/nwk_sourceroute.c src/zb/nwk/nwk_status.c src/zb/nwk/nwk_timeout.c src/zb/nwk/nwk_tlv.c src/zb/nwk/nwk_tx.c src/zb/aps/aps_ack.c src/zb/aps/aps_bind.c src/zb/aps/aps_dup.c src/zb/aps/aps_frag.c src/zb/aps/aps_frame.c src/zb/aps/aps_group.c src/zb/aps/aps_keydoor.c src/zb/aps/aps_rx.c src/zb/aps/aps_transportkey.c src/zb/aps/aps_tx.c src/zb/security.c src/zb/zb_state.c src/zb/zb_layers.c src/zb/zb_core.c)
target_include_directories(zb_mac PUBLIC src/zb src/zb/af src/zb/zcl src/zb/zdo src/zb/mac src/zb/nwk src/zb/aps src/seam)
target_link_libraries(zb_mac PUBLIC zb_utils u_bstream zb_log zb_crypto)

# The pool sizes of src/zb/zb_limits.h, which holds each default and its bounds (docs/configuration.md).
# An option left empty keeps the header's default; one that is set reaches every target linking zb_mac,
# since the sizes shape structs those targets share.
set(ZB_LIMITS
    APS_TX NWK_TX MAC_TX_TRACK MAC_TRANSACTION MAC_INDICATION NWK_INDICATION CORE_INDICATION NWK_NEIGHBOR NWK_ROUTE
    NWK_DISCOVERY NWK_SOURCE_ROUTE NWK_BTT AF_ENDPOINT AF_CLUSTER APS_BIND APS_GROUP APS_DUP
    SECURITY_KEYPAIR CORE_JOINER NWK_ADDR_MAP SECURITY_INCOMING)
set(ZB_LIMITS_SET "")
foreach (limit ${ZB_LIMITS})
    set(ZB_LIMIT_${limit} "" CACHE STRING "Pool size ZB_LIMIT_${limit}; empty keeps src/zb/zb_limits.h's default")
    if (NOT ZB_LIMIT_${limit} STREQUAL "")
        if (NOT ZB_LIMIT_${limit} MATCHES "^[0-9]+$")
            message(FATAL_ERROR "ZB_LIMIT_${limit} is a count, not '${ZB_LIMIT_${limit}}'")
        endif ()
        target_compile_definitions(zb_mac PUBLIC ZB_LIMIT_${limit}=${ZB_LIMIT_${limit}} ZB_LIMITS_CHANGED=1)
        list(APPEND ZB_LIMITS_SET "${limit}=${ZB_LIMIT_${limit}}")
    endif ()
endforeach ()
option(ZB_APS_FRAGMENTATION "Build APS fragmentation; OFF indicates a fragmented frame as DEFRAG_UNSUPPORTED" ON)
if (NOT ZB_APS_FRAGMENTATION)
    target_compile_definitions(zb_mac PUBLIC ZB_APS_FRAGMENTATION=0)
    list(APPEND ZB_LIMITS_SET "APS_FRAGMENTATION=OFF")
endif ()
option(ZB_ZDO_CLIENT "Build the device object's client half: ZDP requests an application asks, and Zb_StackZdoRequest" OFF)
if (ZB_ZDO_CLIENT)
    target_sources(zb_mac PRIVATE src/zb/zdo/zdo_client.c)
    target_compile_definitions(zb_mac PUBLIC ZB_ZDO_CLIENT=1)
endif ()
if (ZB_LIMITS_SET)
    string(REPLACE ";" ", " ZB_LIMITS_SET "${ZB_LIMITS_SET}")
    message(STATUS "Changed from the defaults: ${ZB_LIMITS_SET}; ctest in this build checks them (docs/configuration.md §7)")
endif ()

# Band B's hardware-free backend: the same seam, answered by a script. It links no port and no codec,
# which is the point: a target with no radio can still run band A against it (docs/internals/architecture.md §1).
add_library(zb_loopback
    STATIC
    src/loopback/loopback_radio.c
)
target_include_directories(zb_loopback PUBLIC src/loopback src/seam)
target_link_libraries(zb_loopback PUBLIC zb_utils)

# The AES band: FIPS-197 block and the 802.15.4 modes, our own from the specification rather than
# vendored (docs/internals/refs.md §6). The block cipher is a seam: Aes_KeySchedule and
# Aes_EncryptBlock are each defined by exactly one file, and ZB_AES_IMPLEMENTATION links exactly
# one: a second definition would fail the link (src/crypto/aes.h).
set(ZB_AES_IMPLEMENTATION scalar CACHE STRING "AES block implementation (scalar | table)")
add_library(zb_crypto
    STATIC
    src/crypto/aes_hash.c
    src/crypto/aes_modes.c
    src/crypto/aes_${ZB_AES_IMPLEMENTATION}.c
)
target_include_directories(zb_crypto PUBLIC src/crypto src/seam)

add_library(zb_port STATIC ${ZB_PORT_SRCS})
target_include_directories(zb_port PUBLIC src/port src/seam)
target_link_libraries(zb_port PUBLIC zb_utils zb_log)

if (APPLE)
    target_link_libraries(zb_port PUBLIC "-framework IOKit" "-framework CoreFoundation")
elseif (WIN32)
    target_link_libraries(zb_port PUBLIC bcrypt setupapi cfgmgr32)
endif ()

# The stack an application meets (D-251): the library over the Spinel backend and the port, reporting events.
add_library(zb_stack STATIC src/stack/zb_stack.c)
target_include_directories(zb_stack PUBLIC src/stack)
target_link_libraries(zb_stack PUBLIC zb_mac zb_rcp zb_port)

# The bench's deafness over any radio (D-260): no application links it, and it stands on the seam the stack stands on.
add_library(zb_hearing STATIC src/stack/hearing.c)
target_include_directories(zb_hearing PUBLIC src/stack)
target_link_libraries(zb_hearing PUBLIC zb_mac)

if (ZB_BUILD_TREE)
    add_executable(port_probe tools/port_probe.c)
    target_link_libraries(port_probe PRIVATE zb_port)

    add_executable(port_find tools/port_find.c)
    target_link_libraries(port_find PRIVATE zb_port)

    add_executable(rcp_probe tools/rcp_probe.c)
    target_link_libraries(rcp_probe PRIVATE zb_rcp zb_mac)

    add_executable(log_probe tools/log_probe.c)
    target_link_libraries(log_probe PRIVATE zb_port)

    # The live passive observer: band C port, band B backend, the tool's own deny-tx shim and band A
    # above it. It links no transmit path of its own and takes no --tx.
    add_executable(interop_sniff tools/interop_sniff.c)
    target_link_libraries(interop_sniff PRIVATE zb_rcp zb_mac)

    # The composed-frame witness: the façade over one backend behind a tee that records the octets band A
    # handed tx. --model runs it over the hardware-free backend and opens no port; --path runs it over a
    # stick and transmits only when --tx and --allow-tx are both named. Glue, not a suite: ctest does not
    # run it, and no suite's source set or ledger changes with it.
    add_executable(rcp_send tools/rcp_send.c)
    target_link_libraries(rcp_send PRIVATE zb_rcp zb_mac zb_loopback)

    # The join on two sticks: --parent runs the coordinator's beacon answer and association door, --join scans,
    # adds the parent it heard and calls NLME-JOIN.request, then proves the join with one APS unicast. Glue, not a
    # suite: ctest does not run it, and no suite's source set or ledger changes with it.
    add_executable(zb_join tools/zb_join.c)
    target_link_libraries(zb_join PRIVATE zb_rcp zb_mac)

    # One node of a mesh on the bench: the stack over the hearing shim, so sticks that all hear each other can stand for
    # a mesh that has to route, with counted traffic. Glue, not a suite: ctest runs the shim's suite and not this.
    add_executable(zb_mesh tools/zb_mesh.c)
    target_link_libraries(zb_mesh PRIVATE zb_stack zb_hearing)

    # The examples, each in a directory of its own (examples/CMakeLists.txt).
    add_subdirectory(examples)
endif ()

if (ZB_BUILD_TREE)
    enable_testing()
    add_subdirectory(test)
endif ()
