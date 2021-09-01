cmake_minimum_required(VERSION 3.13.1)

# Automated versioning
file(READ VERSION ver)

string(REGEX MATCH "VERSION_MAJOR = ([0-9]*)" _ ${ver})
set(SDK_VERSION_MAJOR ${CMAKE_MATCH_1})

string(REGEX MATCH "VERSION_MINOR = ([0-9]*)" _ ${ver})
set(SDK_VERSION_MINOR ${CMAKE_MATCH_1})

string(REGEX MATCH "PATCHLEVEL = ([0-9]*)" _ ${ver})
set(SDK_VERSION_PATCH ${CMAKE_MATCH_1})
set(SDK_VERSION_STRING "\"v${SDK_VERSION_MAJOR}.${SDK_VERSION_MINOR}.${SDK_VERSION_PATCH}\"")
set_property(GLOBAL PROPERTY BLE_DAP_SDK_VERSION ${SDK_VERSION_STRING})
math(EXPR SDK_VERSION_NUMBER_INT "(${SDK_VERSION_MAJOR} << 16) +\
				  (${SDK_VERSION_MINOR} << 8)  +\
				  (${SDK_VERSION_PATCH})")
to_hex(${SDK_VERSION_NUMBER_INT} SDK_VERSION_NUMBER)

message(STATUS "Bluetooth LE DAP SDK library version ${SDK_VERSION_STRING} - ${SDK_VERSION_NUMBER}")

configure_file(version.h.in version.h)

add_library(bledap STATIC)
add_dependencies(bledap kernel subsys__bluetooth__host skgcorelib_project skgcorelib tinymt32lib)
target_sources(bledap PRIVATE
	wio_uuid.c
	skg_scan.c
	skg_adv.c
	skg_char.c
	skg_fsm.c
	bluetooth_dap.c
	./services/skg_service.c
	./services/relay_service.c
)
target_include_directories(bledap PUBLIC ${SKGBLESDK_INCLUDE_DIR})
target_include_directories(bledap PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_definitions(bledap PRIVATE DAP_ZEPHYR_IMPLEMENTATION
				  PRIVATE DAP_OOB_COMPATIBLE)

# I don't know of another way to make this build - dependencies
# on the kernel and the way this is build makes the whole thing
# fail
target_link_libraries(bledap INTERFACE zephyr_interface
				PRIVATE skgcorelib tinymt32lib kernel)
