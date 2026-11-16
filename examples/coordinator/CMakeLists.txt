# A coordinator that opens a network, hands a joining device the network key and prints what it receives; with
# --config it keeps that network in a file, so example_config comes with zb_stack.
add_executable(example_coordinator coordinator.c)
target_link_libraries(example_coordinator PRIVATE example_config)
