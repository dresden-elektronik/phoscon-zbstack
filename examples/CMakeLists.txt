# The examples are applications, not instruments: each is built from the public surface only, from a directory of
# its own, so one can grow past a file without touching another. The binaries land beside the stack's own tools
# (build/host/example_*), where the README and the getting-started guide run them.
# Linking zb_stack is enough: it carries zb_port and zb_utils publicly, and naming them again makes the linker warn of
# duplicate libraries.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_subdirectory(common)
add_subdirectory(coordinator)
add_subdirectory(router)
if (ZB_ZDO_CLIENT)
    add_subdirectory(interview)
else ()
    message(STATUS "example_interview is not built: it asks its ZDP requests through ZB_ZDO_CLIENT, which is OFF")
endif ()
