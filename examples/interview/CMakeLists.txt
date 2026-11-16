# A coordinator that interviews every device that joins: its descriptors through the device object's client half,
# then the Basic cluster's manufacturer name and model; built only where ZB_ZDO_CLIENT builds that half.
add_executable(example_interview interview_coordinator.c interview.c)
target_include_directories(example_interview PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(example_interview PRIVATE zb_stack)
