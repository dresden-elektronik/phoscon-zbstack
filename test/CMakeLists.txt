# The shared assertion family: one harness for every suite that asserts,
# linked as an interface target so the support source is built into each of them without the suite ledger (which
# sums the assertions of the suite's own sources) ever counting the harness's own definitions.
add_library(zb_test_support INTERFACE)
target_sources(zb_test_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/support/test_harness.c)
target_include_directories(zb_test_support INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/support ${CMAKE_SOURCE_DIR}/src/seam)
target_link_libraries(zb_test_support INTERFACE zb_utils)

# The rig constructor: a band-A device (the hardware-free backend, a MAC on its seam and the
# network layer on that MAC) built where every band-A suite can reach it. An interface target for the same
# reason the harness is one: no suite's source set grows, so the ledger keeps counting the suite's own
# assertions and the rig's call sites stay out of it. It links band A and the hardware-free backend, so a suite
# that takes it is linked against the library under test without naming it twice.
add_library(zb_test_rig_band_a INTERFACE)
target_sources(zb_test_rig_band_a INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/support/rig_band_a.c)
target_include_directories(zb_test_rig_band_a INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/support ${CMAKE_SOURCE_DIR}/src/seam)
target_link_libraries(zb_test_rig_band_a INTERFACE zb_mac zb_loopback zb_utils)

# The fixture loader: the annotated captures of test/fixtures/ read as PSDUs, on top of the plain
# hex reader the fixture suites already carry (`test_fixture.c`).
add_library(zb_test_fixtures INTERFACE)
target_sources(zb_test_fixtures INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/support/fixtures_frames.c
        ${CMAKE_CURRENT_SOURCE_DIR}/test_fixture.c)
target_include_directories(zb_test_fixtures INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/support ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(zb_test_fixtures INTERFACE zb_utils)

add_executable(port_contract test_port.c)
target_link_libraries(port_contract PRIVATE zb_port zb_test_support)
add_test(NAME port_contract COMMAND port_contract)

add_executable(port_conformance test_port_conformance.c test_fixture.c)
target_include_directories(port_conformance PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(port_conformance PRIVATE
        ZB_SAMPLES_DIR="${CMAKE_SOURCE_DIR}/test/fixtures")
target_link_libraries(port_conformance PRIVATE zb_port zb_test_support)
add_test(NAME port_conformance COMMAND port_conformance)

if (WIN32)
    add_executable(port_win32 test_port_win32.c port_file_cases.c)
    target_compile_definitions(port_win32 PRIVATE ZB_SCRATCH_DIR="${CMAKE_CURRENT_BINARY_DIR}")
    target_link_libraries(port_win32 PRIVATE zb_port zb_test_support)
    add_test(NAME port_win32 COMMAND port_win32)
endif ()

if (UNIX)
    add_executable(port_posix test_port_posix.c port_file_cases.c)
    target_compile_definitions(port_posix PRIVATE ZB_SCRATCH_DIR="${CMAKE_CURRENT_BINARY_DIR}")
    target_link_libraries(port_posix PRIVATE zb_port zb_test_support)
    add_test(NAME port_posix COMMAND port_posix)

    # A stick found by its USB serial number, on a sysfs-shaped tree made here at configure time (D-282).
    include(${CMAKE_CURRENT_SOURCE_DIR}/port_locate_fixture.cmake)
    port_locate_fixture(${CMAKE_CURRENT_BINARY_DIR}/locate_fixture)
    add_executable(port_locate test_port_locate.c)
    target_link_libraries(port_locate PRIVATE zb_port zb_test_support)
    add_test(NAME port_locate COMMAND port_locate WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/locate_fixture)
endif ()

# The examples' saved network, on a scratch file and on the samples in examples/config/.
add_executable(ex_config_contract test_ex_config.c)
target_compile_definitions(ex_config_contract PRIVATE ZB_SCRATCH_DIR="${CMAKE_CURRENT_BINARY_DIR}"
                           EX_CONFIG_SAMPLES="${CMAKE_SOURCE_DIR}/examples/config")
target_link_libraries(ex_config_contract PRIVATE example_config zb_test_support)
add_test(NAME ex_config COMMAND ex_config_contract)

add_executable(hdlc_contract test_hdlc.c test_fixture.c)
target_include_directories(hdlc_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(hdlc_contract PRIVATE
        ZB_SAMPLES_DIR="${CMAKE_SOURCE_DIR}/test/fixtures")
target_link_libraries(hdlc_contract PRIVATE zb_rcp zb_test_support)
add_test(NAME hdlc COMMAND hdlc_contract)

add_executable(spinel_codec_contract test_spinel.c test_fixture.c)
target_include_directories(spinel_codec_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(spinel_codec_contract PRIVATE
        ZB_SAMPLES_DIR="${CMAKE_SOURCE_DIR}/test/fixtures")
target_link_libraries(spinel_codec_contract PRIVATE zb_rcp zb_test_support)
add_test(NAME spinel_codec COMMAND spinel_codec_contract)

# The split of the MAC suite: `mac` is a name and a ledger, not a file, so its cases live in eight
# topic case files beside the machinery they share (the adoption and composition of a frame, the confirmations
# the backend answers with, the indications a neighbor's frame is delivered as, the coordinator's indirect queue
# and its association doors, the child's half of that same association, the backend that went away and the frames
# the two-stick rig put on channel 26) and
# the entry point keeps the run order the ledger records. The last of those reads its known answers out of `test/fixtures/`, so the samples
# directory is named for it the way the `interop` suite names it.
add_executable(mac_contract
        mac/mac_main.c mac/mac_helpers.c mac/cases_build.c mac/cases_confirm.c
        mac/cases_delivery.c mac/cases_beacon.c mac/cases_scan.c mac/cases_indirect.c mac/cases_association.c
        mac/cases_child.c mac/cases_poll.c mac/cases_reapply.c mac/cases_onair.c)
target_include_directories(mac_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/mac)
target_compile_definitions(mac_contract PRIVATE
        ZB_SAMPLES_DIR="${CMAKE_SOURCE_DIR}/test/fixtures")
target_link_libraries(mac_contract PRIVATE zb_test_rig_band_a zb_test_fixtures zb_test_support)
add_test(NAME mac COMMAND mac_contract)

add_executable(loopback_radio test_loopback_radio.c)
target_link_libraries(loopback_radio PRIVATE zb_loopback zb_test_support)
add_test(NAME loopback_radio COMMAND loopback_radio)

add_executable(mac_frame_contract mac/mac_frame_suite.c)
target_link_libraries(mac_frame_contract PRIVATE zb_mac zb_test_support)
add_test(NAME mac_frame COMMAND mac_frame_contract)

add_executable(nwk_frame_contract nwk/nwk_frame_suite.c)
target_link_libraries(nwk_frame_contract PRIVATE zb_mac zb_test_support)
add_test(NAME nwk_frame COMMAND nwk_frame_contract)

add_executable(aps_frame_contract aps/aps_frame_suite.c)
target_link_libraries(aps_frame_contract PRIVATE zb_mac zb_test_support)
add_test(NAME aps_frame COMMAND aps_frame_contract)

# The first split suite: `nwk` is a name and a ledger, not a file, so its 62 cases live in six
# topic case files beside the machinery they share, and the entry point keeps the run order the ledger records.
add_executable(nwk_contract
        nwk/nwk_main.c nwk/nwk_helpers.c nwk/cases_config.c nwk/cases_beacon.c nwk/cases_delivery.c
        nwk/cases_broadcast.c nwk/cases_rx.c nwk/cases_security.c nwk/cases_join.c nwk/cases_linkstatus.c nwk/cases_sourceroute.c nwk/cases_commissioning.c nwk/cases_permit.c nwk/cases_leave.c nwk/cases_poll.c)
target_link_libraries(nwk_contract PRIVATE zb_test_rig_band_a zb_test_support)
add_test(NAME nwk COMMAND nwk_contract)

# The three table modules the layer directory holds, driven directly: plain pools and the three
# headers, with no Nwk_Nwk, no MAC and no radio anywhere in the file.
add_executable(nwk_tables_contract nwk/nwk_tables_suite.c)
target_link_libraries(nwk_tables_contract PRIVATE zb_mac zb_test_support)
add_test(NAME nwk_tables COMMAND nwk_tables_contract)

# The other half: the topic modules' own operations, driven directly over plain pools and one
# seeded Security, with no façade, no MAC and no backend in the file.
add_executable(nwk_modules_contract nwk/nwk_modules_suite.c)
target_link_libraries(nwk_modules_contract PRIVATE zb_mac zb_test_support)
add_test(NAME nwk_modules COMMAND nwk_modules_contract)

# Route discovery's two codecs and its table: the Route Request payload of Figure 3-9 with Annex K/I's
# TLV tail, and Table 3-79's pool: four sources in the directory's shape, no Nwk_Nwk and no radio.
add_executable(nwk_routedisc_contract
        nwk/nwk_routedisc_main.c nwk/nwk_routedisc_helpers.c nwk/cases_rreq.c nwk/cases_discovery.c)
target_link_libraries(nwk_routedisc_contract PRIVATE zb_mac zb_test_support)
add_test(NAME nwk_routedisc COMMAND nwk_routedisc_contract)

# Route discovery's reception half: 3.6.4.5.1's gate and forward cost, 3.6.4.5.1.4's jitter and relay count,
# the Route Reply payload of Figure 3-11, 3.6.4.5.2's two halves, and the dispatch a received request meets in
# the façade: five sources, plain pools on each case's own stack, one caller seed and the shared band-A rig.
add_executable(nwk_routeflow_contract
        nwk/nwk_routeflow_main.c nwk/nwk_routeflow_helpers.c nwk/nwk_helpers.c
        nwk/cases_rrep.c nwk/cases_routeflow.c nwk/cases_rreqrelay.c nwk/cases_rreqtx.c
        nwk/cases_rreqflow.c nwk/cases_rrepflow.c nwk/cases_maintenance.c nwk/cases_mesh.c support/mesh_air.c)
target_link_libraries(nwk_routeflow_contract PRIVATE zb_test_rig_band_a zb_test_support)
add_test(NAME nwk_routeflow COMMAND nwk_routeflow_contract)

# The second split suite: `aps` is a name and a ledger, not a file, so its 33 cases live in seven
# topic case files beside the machinery they share (the door, the NLDE confirmations, the acknowledgement
# machine, the transmit half's broadcasts and ring, the group sends, the reception sequence and the security
# crossing) and the entry point keeps the run order the ledger records.
add_executable(aps_contract
        aps/aps_main.c aps/aps_helpers.c aps/cases_door.c aps/cases_confirm.c aps/cases_ack.c
        aps/cases_tx.c aps/cases_group.c aps/cases_keydoor.c aps/cases_admit.c aps/cases_rx.c aps/cases_security.c)
target_include_directories(aps_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/aps)
target_link_libraries(aps_contract PRIVATE zb_test_rig_band_a zb_test_support)
add_test(NAME aps COMMAND aps_contract)

# Direct coverage of this directory's pool modules (`aps_group`, `aps_dup`, `aps_tx` and
# `aps_ack`) driven over plain pools and hand-built structs, with one seeded `Security` where an operation
# crosses into it and one minimal `Nwk_Nwk` over `loopback_radio` where an owed acknowledgement has an air to be
# asserted empty. `aps_frame` is a codec and has its own suite; `aps_rx`'s stage is the façade's delivery record
# and is asserted through the `aps` suite's crossing cases.
# The application framework: the endpoint table and the ASDU path, on a band-A rig with an APS service.
add_executable(af_contract af/af_main.c af/af_helpers.c af/cases_descriptor.c af/cases_data.c)
target_include_directories(af_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/af)
target_link_libraries(af_contract PRIVATE zb_test_rig_band_a zb_test_support)
add_test(NAME af COMMAND af_contract)

# The device object: 2.4.4.2's server half on the framework.
add_executable(core_contract core/core_main.c core/cases_surface.c core/cases_pair.c core/cases_trust.c core/cases_parent.c core/core_helpers.c)
target_include_directories(core_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/core)
target_link_libraries(core_contract PRIVATE zb_test_rig_band_a zb_test_support)
add_test(NAME core COMMAND core_contract)

add_executable(zdo_contract zdo/zdo_main.c zdo/zdo_helpers.c zdo/cases_server.c zdo/cases_management.c af/af_helpers.c)
target_include_directories(zdo_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/af ${CMAKE_CURRENT_SOURCE_DIR}/zdo)
target_link_libraries(zdo_contract PRIVATE zb_test_rig_band_a zb_test_support)
add_test(NAME zdo COMMAND zdo_contract)

if (ZB_ZDO_CLIENT)
    add_executable(zdo_client_contract zdo/zdo_client_main.c zdo/zdo_helpers.c zdo/cases_client.c af/af_helpers.c)
    target_include_directories(zdo_client_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/af ${CMAKE_CURRENT_SOURCE_DIR}/zdo)
    target_link_libraries(zdo_client_contract PRIVATE zb_test_rig_band_a zb_test_support)
    add_test(NAME zdo_client COMMAND zdo_client_contract)
endif ()

# The cluster library's foundation over one cluster, on the framework.
add_executable(zcl_contract zcl/zcl_main.c zcl/cases_frame.c af/af_helpers.c)
target_include_directories(zcl_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/af ${CMAKE_CURRENT_SOURCE_DIR}/zcl)
target_link_libraries(zcl_contract PRIVATE zb_test_rig_band_a zb_test_support)
add_test(NAME zcl COMMAND zcl_contract)

add_executable(aps_modules_contract aps/aps_modules_suite.c)
target_link_libraries(aps_modules_contract PRIVATE zb_mac zb_loopback zb_test_support)
add_test(NAME aps_modules COMMAND aps_modules_contract)

# The interop gate and the split of it: `interop` is a name and a ledger, not a file, so the
# fixtures' replay lives in four phase files beside the machinery they share (the one loader, the one device this
# suite assembles for itself, the three drives and the ledger) and the entry point keeps the run order the ledger
# records. The samples directory is named for the suite the way the fixture suites have it named.
add_executable(interop_contract
        interop/interop_main.c interop/interop_helpers.c
        interop/phase_a.c interop/phase_b.c interop/phase_c.c interop/phase_d.c)
target_include_directories(interop_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/interop)
target_compile_definitions(interop_contract PRIVATE
        ZB_SAMPLES_DIR="${CMAKE_SOURCE_DIR}/test/fixtures")
target_link_libraries(interop_contract PRIVATE zb_test_rig_band_a zb_test_fixtures zb_test_support)
add_test(NAME interop COMMAND interop_contract)

# The split of the security suite: `security` is a name and a ledger, not a file, so its 33 cases live
# in the two case files the chapters themselves name (the NWK crossing of 4.3.1.1/4.3.1.2 and the APS crossing of
# 4.4.1.1/4.4.1.2) beside the fixtures and the vectors they share.
add_executable(security_contract
        security/security_main.c security/security_helpers.c
        security/cases_nwk.c security/cases_aps.c)
target_include_directories(security_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/security)
target_link_libraries(security_contract PRIVATE zb_mac zb_log zb_test_support)
add_test(NAME security COMMAND security_contract)

# The persistence boundary: `zb_state` over the four layers it captures and restores, and the one
# operation `security` needed in order to be restorable at all. A suite is a name and a ledger, so its 15
# cases live in three topic case files beside the device they share: what the object carries and what its
# counts mean, the rules a restore is held to, and Security_Restore's own door. No radio is needed beyond the
# one frame a counter has to move with.
add_executable(state_contract
        state/state_main.c state/state_helpers.c
        state/cases_capture.c state/cases_restore.c state/cases_security.c)
target_include_directories(state_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/state)
target_link_libraries(state_contract PRIVATE zb_test_rig_band_a zb_test_support)
add_test(NAME state COMMAND state_contract)

# The façade over the four modules: `Zb_Layers`'s config, its validate-then-apply init, the one step that advances
# the three layers, the two drains, the state pair and its request (the one edge an application sends through)
# driven through the public operations only. A suite is a name and a ledger, so its cases live in the topic case
# files beside the device they share. The last of those reads its known answers out of the frames two RCPs put on
# channel 26, so the samples directory is named for it the way the `mac` and `interop` suites name it.
add_executable(layers_contract
        layers/layers_main.c layers/layers_helpers.c layers/cases_init.c layers/cases_shape.c layers/cases_turn.c
        layers/cases_state.c layers/cases_send.c layers/cases_onair.c)
target_include_directories(layers_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/layers)
target_compile_definitions(layers_contract PRIVATE
        ZB_SAMPLES_DIR="${CMAKE_SOURCE_DIR}/test/fixtures")
target_link_libraries(layers_contract PRIVATE zb_test_rig_band_a zb_test_fixtures zb_test_support)
add_test(NAME layers COMMAND layers_contract)

# The object an application meets (D-251): Zb_Stack over loopback models, read only through its events.
add_executable(stack_contract stack/stack_main.c stack/cases_events.c stack/cases_rcp.c)
if (UNIX)
    target_compile_definitions(stack_contract PRIVATE STACK_RCP_CASES=1)    # the RCP on a pseudo-terminal
endif ()
target_link_libraries(stack_contract PRIVATE zb_stack zb_test_rig_band_a zb_test_support)
add_test(NAME stack COMMAND stack_contract)

add_executable(rcp_radio test_rcp_radio.c test_fixture.c)
target_include_directories(rcp_radio PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(rcp_radio PRIVATE
        ZB_SAMPLES_DIR="${CMAKE_SOURCE_DIR}/test/fixtures")
target_link_libraries(rcp_radio PRIVATE zb_rcp zb_test_support)
add_test(NAME rcp_radio COMMAND rcp_radio)

add_executable(spinel_session test_spinel_session.c)
target_link_libraries(spinel_session PRIVATE zb_rcp)
add_test(NAME spinel_session COMMAND spinel_session)

add_executable(props_contract test_props.c)
target_link_libraries(props_contract PRIVATE zb_rcp)
add_test(NAME props COMMAND props_contract)

add_executable(log_contract test_log.c)
target_link_libraries(log_contract PRIVATE zb_port zb_test_support)
add_test(NAME log COMMAND log_contract)

add_executable(hearing_contract test_hearing.c)
target_link_libraries(hearing_contract PRIVATE zb_hearing zb_test_support)
add_test(NAME hearing COMMAND hearing_contract)

add_executable(seam_contract test_seam.c)
target_include_directories(seam_contract PRIVATE ${CMAKE_SOURCE_DIR}/src/seam)
add_test(NAME seam COMMAND seam_contract)

add_executable(crypto_aes test_crypto_aes.c)
target_link_libraries(crypto_aes PRIVATE zb_crypto zb_test_support)
add_test(NAME crypto_aes COMMAND crypto_aes)

# The two hash constructions R23.1 Annex B instantiates over AES-128, against the vectors Annex C
# prints for them: B.4's Matyas-Meyer-Oseas hash (C.5.1 to C.5.6) and B.1.4's HMAC over it (C.6.1,
# C.6.2), which 4.5.3's key-transport and key-load keys are built from.
add_executable(crypto_hash test_crypto_hash.c)
target_link_libraries(crypto_hash PRIVATE zb_crypto zb_test_support)
add_test(NAME crypto_hash COMMAND crypto_hash)

add_executable(utils_contract test_utils.c)
target_link_libraries(utils_contract PRIVATE zb_utils zb_log)
add_test(NAME utils_contract COMMAND utils_contract)

add_executable(u_bstream_contract test_u_bstream.c)
target_link_libraries(u_bstream_contract PRIVATE u_bstream)
add_test(NAME u_bstream COMMAND u_bstream_contract)

# The upstream test suite of a vendored library is vendored with it and run as-is.
file(GLOB U_SSTREAM_TEST_SRCS ${CMAKE_SOURCE_DIR}/vendor/u_sstream/tests/*.c)
foreach(testSrc ${U_SSTREAM_TEST_SRCS})
    get_filename_component(testName ${testSrc} NAME_WE)
    add_executable(vendor_${testName} ${testSrc})
    target_link_libraries(vendor_${testName} PRIVATE u_sstream)
    if (MSVC)
        target_compile_options(vendor_${testName} PRIVATE /wd4267)    # upstream's size_t into an unsigned, verbatim
    endif ()
    add_test(NAME u_sstream/${testName} COMMAND vendor_${testName})
endforeach()

find_program(ZB_PYTHON NAMES python3 python)
if (ZB_PYTHON)
    add_test(NAME bands
             COMMAND ${ZB_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/bands_audit.py ${CMAKE_SOURCE_DIR})
    add_test(NAME vendor
             COMMAND ${ZB_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/vendor_audit.py ${CMAKE_SOURCE_DIR})
    add_test(NAME freestanding
             COMMAND ${ZB_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/freestanding_audit.py ${CMAKE_SOURCE_DIR})
    # The compiled size of band A for the ConBee II's silicon, over the source set CMakeLists.txt names. It skips
    # itself where no arm-none-eabi- toolchain is on PATH, and it fails when a source the build links is missing
    # from its own set, which is how the figure stopped being one (docs/memory.md).
    add_test(NAME band_a_size
             COMMAND ${ZB_PYTHON} ${CMAKE_SOURCE_DIR}/tools/band_a_size.py ${CMAKE_SOURCE_DIR})
    # The RAM docs/memory.md cites, member by member on the M0+ and on this host: it fails when a struct gains a
    # declaration its reader cannot measure, so the figures cannot quietly stop being the tree's. Its reader drives a
    # gcc or clang command line, which MSVC's is not.
    if (NOT MSVC)
        add_test(NAME mem_size
                 COMMAND ${ZB_PYTHON} ${CMAKE_SOURCE_DIR}/tools/mem_size.py ${CMAKE_SOURCE_DIR})
    endif ()
    # §6's two comment rules, checked over the areas that are migrated and counted over the
    # rest: a gate that fails everywhere on day one is a gate that gets switched off.
    add_test(NAME comment_audit
             COMMAND ${ZB_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/comment_audit.py ${CMAKE_SOURCE_DIR})
    # The oracle: every file under test/fixtures/ re-dissected by the harness's own decoder, which has
    # never read this tree's code (docs/internals/testing.md §7). Its working directory is the tree because
    # the script names test/fixtures relative to it.
    add_test(NAME samples
             COMMAND ${ZB_PYTHON} ${CMAKE_SOURCE_DIR}/harness/check_samples.py
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    # The documentation's own gate: every add_test name has an entry in docs/internals/testing.md §2, every entry's
    # state marker agrees with the build, and every fixture in test/fixtures/ is named in docs/internals/testing.md §4.
    add_test(NAME docs_audit
             COMMAND ${ZB_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/docs_audit.py ${CMAKE_SOURCE_DIR})
    # The map's own gate: every clause a row names is marked in the file that answers it, and no mark
    # names a clause no row gives it (test/conformance_audit.py, decision 150).
    add_test(NAME conformance_audit
             COMMAND ${ZB_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/conformance_audit.py ${CMAKE_SOURCE_DIR})
    # An application's own u_bstream and u_sstream at this tree's pins replace vendor/, and another revision is
    # refused at configure (D-290): a parent project is configured and built under the build tree.
    add_test(NAME parent_streams
             COMMAND ${ZB_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/parent_streams.py ${CMAKE_COMMAND} ${CMAKE_SOURCE_DIR}
                     ${CMAKE_CURRENT_BINARY_DIR}/parent_streams ${CMAKE_GENERATOR})
    # U_ belongs to the u_* libraries: no library of the tree's own defines a U_ symbol, so an application that links
    # its own u_* copies meets no second definition (docs/internals/coding-rules.md §2).
    if (CMAKE_NM)
        set(ZB_OWN_ARCHIVES "")
        foreach (library zb_utils zb_log zb_rcp zb_mac zb_loopback zb_crypto zb_port zb_stack zb_hearing)
            list(APPEND ZB_OWN_ARCHIVES $<TARGET_FILE:${library}>)
        endforeach ()
        add_test(NAME namespace_audit
                 COMMAND ${ZB_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/namespace_audit.py ${CMAKE_NM} ${ZB_OWN_ARCHIVES})
    endif ()
endif ()

