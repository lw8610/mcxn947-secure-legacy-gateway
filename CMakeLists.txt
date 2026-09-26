# SPDX-FileCopyrightText: 2026 Secure Legacy Gateway contributors
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(mcx_http_test)

target_sources(app PRIVATE
    src/main.c
    src/html_stream.c
    src/proxy_request.c
)

target_sources_ifdef(CONFIG_MCUX_PSA_CRYPTO_DRIVER_ELS_PKC app PRIVATE
    src/els_psa_selftest.c
)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

generate_inc_file_for_target(
    app
    src/globalsign_r1.der
    ${gen_dir}/globalsign_r1.der.inc
)

generate_inc_file_for_target(
    app
    src/aaa_certificate_services.der
    ${gen_dir}/aaa_certificate_services.der.inc
)

generate_inc_file_for_target(
    app
    src/isrg_root_x1.der
    ${gen_dir}/isrg_root_x1.der.inc
)

generate_inc_file_for_target(
    app
    src/globalsign_root_r3.der
    ${gen_dir}/globalsign_root_r3.der.inc
)
