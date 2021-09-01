# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)

project(skg-ble-sdk-test)

# The external static library that we are linking with does not know
# how to build for this platform so we export all the flags used in
# this zephyr build to the external build system.
#
# Other external build systems may be self-contained enough that they
# do not need any build information from zephyr. Or they may be
# incompatible with certain zephyr options and need them to be
# filtered out.
zephyr_get_include_directories_for_lang_as_string(         C includes)
zephyr_get_system_include_directories_for_lang_as_string(  C system_includes)
zephyr_get_compile_definitions_for_lang_as_string(         C definitions)
zephyr_get_compile_options_for_lang_as_string(             C options)

set(external_project_cflags
	"${includes} ${definitions} ${options} ${system_includes}"
)

include(../src/CMakeLists.txt)

target_sources(app PRIVATE
	tests_state_machine.c
	main.c

	../src/services/skg_service.c
	../src/services/recon_service.c
	../src/services/relay_service.c
)

target_link_libraries(app PUBLIC skgblesdk kernel)
