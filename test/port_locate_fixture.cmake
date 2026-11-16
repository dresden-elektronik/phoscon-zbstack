# A tree shaped like Linux's sysfs and /dev, made at configure time for the port_locate suite (D-282). The shapes are
# the layouts read on two Linux hosts (ttyACM0 under the USB device 1-1, and ttyUSB0 one level deeper, under 1-2):
# a CDC stick, an FTDI stick, an FTDI stick whose node a container did not map, two clones sharing a serial, a header
# UART with no USB device above it, a link to nothing, and a virtual terminal with no device at all.

function(locate_usb root dir vendor product serial name)
    file(MAKE_DIRECTORY "${root}/sys/devices/${dir}")
    file(WRITE "${root}/sys/devices/${dir}/idVendor" "${vendor}\n")
    file(WRITE "${root}/sys/devices/${dir}/idProduct" "${product}\n")
    file(WRITE "${root}/sys/devices/${dir}/serial" "${serial}\n")
    file(WRITE "${root}/sys/devices/${dir}/product" "${name}\n")
endfunction()

function(locate_tty root tty target)
    file(MAKE_DIRECTORY "${root}/sys/class/tty/${tty}")

    if (NOT "${target}" STREQUAL "")
        execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink "../../../devices/${target}"
                "${root}/sys/class/tty/${tty}/device")
    endif ()
endfunction()

function(port_locate_fixture root)
    file(REMOVE_RECURSE "${root}")
    file(MAKE_DIRECTORY "${root}/dev")

    locate_usb("${root}" "pci0000:00/usb1" "1d6b" "0002" "0000:00:14.0" "xHCI Host Controller")
    locate_usb("${root}" "pci0000:00/usb1/1-1" "1cf1" "0030" "DE1000000" "ConBee II")
    locate_usb("${root}" "pci0000:00/usb1/1-2" "0403" "6015" "DEDEADAFFE" "ConBee III")
    locate_usb("${root}" "pci0000:00/usb1/1-3" "0403" "6015" "DM00F7D1" "FT230X Basic UART")
    locate_usb("${root}" "pci0000:00/usb1/1-4" "10c4" "ea60" "0001" "CP2102 USB to UART Bridge Controller")
    locate_usb("${root}" "pci0000:00/usb1/1-5" "10c4" "ea60" "0001" "CP2102 USB to UART Bridge Controller")
    file(MAKE_DIRECTORY "${root}/sys/devices/pci0000:00/usb1/1-1/1-1:1.0")
    file(MAKE_DIRECTORY "${root}/sys/devices/pci0000:00/usb1/1-2/1-2:1.0/ttyUSB0")
    file(MAKE_DIRECTORY "${root}/sys/devices/pci0000:00/usb1/1-3/1-3:1.0/ttyUSB1")
    file(MAKE_DIRECTORY "${root}/sys/devices/pci0000:00/usb1/1-4/1-4:1.0/ttyUSB2")
    file(MAKE_DIRECTORY "${root}/sys/devices/pci0000:00/usb1/1-5/1-5:1.0/ttyUSB3")
    file(MAKE_DIRECTORY "${root}/sys/devices/platform/serial0/serial0:0")

    locate_tty("${root}" "ttyACM0" "pci0000:00/usb1/1-1/1-1:1.0")
    locate_tty("${root}" "ttyUSB0" "pci0000:00/usb1/1-2/1-2:1.0/ttyUSB0")
    locate_tty("${root}" "ttyUSB1" "pci0000:00/usb1/1-3/1-3:1.0/ttyUSB1")
    locate_tty("${root}" "ttyUSB2" "pci0000:00/usb1/1-4/1-4:1.0/ttyUSB2")
    locate_tty("${root}" "ttyUSB3" "pci0000:00/usb1/1-5/1-5:1.0/ttyUSB3")
    locate_tty("${root}" "ttyAMA0" "platform/serial0/serial0:0")
    locate_tty("${root}" "ttyS0" "platform/gone")
    locate_tty("${root}" "tty0" "")

    foreach (node ttyACM0 ttyUSB0 ttyUSB2 ttyUSB3 ttyAMA0 ttyS0 tty0)
        file(WRITE "${root}/dev/${node}" "")
    endforeach ()
endfunction()
