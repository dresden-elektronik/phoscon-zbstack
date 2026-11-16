# What more than one example pulls in: the saved network of ex_config, a text file through U_SStream and the port's
# files. An example links example_config; zb_stack comes with it.
add_library(example_config STATIC ex_config.c)
target_include_directories(example_config PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(example_config PUBLIC zb_stack u_sstream)
