# A router that discovers a network on the channels it is given, joins it, waits for the key and lets other devices
# join through it; with --config it keeps that network in a file, so example_config comes with zb_stack.
add_executable(example_router router.c)
target_link_libraries(example_router PRIVATE example_config)
