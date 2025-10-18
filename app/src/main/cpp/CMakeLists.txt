cmake_minimum_required(VERSION 3.22.1)

project("yaraengine")

add_library(jansson STATIC
        jansson/src/dtoa.c
        jansson/src/dump.c
        jansson/src/error.c
        jansson/src/hashtable.c
        jansson/src/hashtable.h
        jansson/src/hashtable_seed.c
        jansson/src/jansson.h
        jansson/src/jansson_config.h
        jansson/src/jansson_private.h
        jansson/src/load.c
        jansson/src/lookup3.h
        jansson/src/memory.c
        jansson/src/pack_unpack.c
        jansson/src/strbuffer.c
        jansson/src/strbuffer.h
        jansson/src/strconv.c
        jansson/src/utf.c
        jansson/src/utf.h
        jansson/src/value.c
        jansson/src/version.c)

add_library(yara SHARED
        libyara/ahocorasick.c
        libyara/arena.c
        libyara/atoms.c
        libyara/base64.c
        libyara/bitmask.c
        libyara/compiler.c
        libyara/crypto.h
        libyara/endian.c
        libyara/exception.h
        libyara/exec.c
        libyara/exefiles.c
        libyara/filemap.c
        libyara/grammar.c
        libyara/grammar.h
        libyara/hash.c
        libyara/hex_grammar.c
        libyara/hex_grammar.h
        libyara/hex_lexer.c
        libyara/include/authenticode-parser/authenticode.h
        libyara/include/tlshc/tlsh.h
        libyara/include/yara/ahocorasick.h
        libyara/include/yara/arena.h
        libyara/include/yara/atoms.h
        libyara/include/yara/base64.h
        libyara/include/yara/bitmask.h
        libyara/include/yara/compiler.h
        libyara/include/yara/dex.h
        libyara/include/yara/dotnet.h
        libyara/include/yara/elf.h
        libyara/include/yara/elf_utils.h
        libyara/include/yara/endian.h
        libyara/include/yara/error.h
        libyara/include/yara/exec.h
        libyara/include/yara/exefiles.h
        libyara/include/yara/filemap.h
        libyara/include/yara/globals.h
        libyara/include/yara/hash.h
        libyara/include/yara/hex_lexer.h
        libyara/include/yara/integers.h
        libyara/include/yara/lexer.h
        libyara/include/yara/libyara.h
        libyara/include/yara/limits.h
        libyara/include/yara/macho.h
        libyara/include/yara/mem.h
        libyara/include/yara/modules.h
        libyara/include/yara/notebook.h
        libyara/include/yara/object.h
        libyara/include/yara/parser.h
        libyara/include/yara/pe.h
        libyara/include/yara/pe_utils.h
        libyara/include/yara/proc.h
        libyara/include/yara/re.h
        libyara/include/yara/re_lexer.h
        libyara/include/yara/rules.h
        libyara/include/yara/scan.h
        libyara/include/yara/scanner.h
        libyara/include/yara/simple_str.h
        libyara/include/yara/sizedstr.h
        libyara/include/yara/stack.h
        libyara/include/yara/stopwatch.h
        libyara/include/yara/stream.h
        libyara/include/yara/strutils.h
        libyara/include/yara/threading.h
        libyara/include/yara/types.h
        libyara/include/yara/unaligned.h
        libyara/include/yara/utils.h
        libyara/include/yara.h
        libyara/lexer.c
        libyara/libyara.c
        libyara/mem.c
        libyara/modules/console/console.c
        libyara/modules/cuckoo/cuckoo.c
        libyara/modules/demo/demo.c
        libyara/modules/dex/dex.c
        libyara/modules/dotnet/dotnet.c
        libyara/modules/elf/elf.c
        libyara/modules/hash/hash.c
        libyara/modules/macho/macho.c
        libyara/modules/math/math.c
        libyara/modules/module_list
        libyara/modules/pb_tests/pb_tests.c
        libyara/modules/pb_tests/pb_tests.pb-c.c
        libyara/modules/pb_tests/pb_tests.pb-c.h
        libyara/modules/pb_tests/pb_tests.proto
        libyara/modules/pb_tests/yara.pb-c.h
        libyara/modules/pb_tests/protobuf-c/protobuf-c.c
        libyara/modules/pb_tests/protobuf-c/protobuf-c.h
        libyara/modules/pb_tests/pb_tests.c
        libyara/modules/pb_tests/pb_tests.pb-c.c
        libyara/modules/pb_tests/pb_tests.pb-c.h
        libyara/modules/pb_tests/protobuf-c/protobuf-c.c
        libyara/modules/pb_tests/protobuf-c/protobuf-c.h
        libyara/modules/pb_tests/protoc-c/c_bytes_field.h
        libyara/modules/pb_tests/protoc-c/c_enum.h
        libyara/modules/pb_tests/protoc-c/c_enum_field.h
        libyara/modules/pb_tests/protoc-c/c_extension.h
        libyara/modules/pb_tests/protoc-c/c_field.h
        libyara/modules/pb_tests/protoc-c/c_file.h
        libyara/modules/pb_tests/protoc-c/c_generator.h
        libyara/modules/pb_tests/protoc-c/c_helpers.h
        libyara/modules/pb_tests/protoc-c/c_message.h
        libyara/modules/pb_tests/protoc-c/c_message_field.h
        libyara/modules/pb_tests/protoc-c/c_primitive_field.h
        libyara/modules/pb_tests/protoc-c/c_service.h
        libyara/modules/pb_tests/protoc-c/c_string_field.h
        libyara/modules/pb_tests/yara.pb-c.h
        libyara/modules/pe/authenticode-parser/authenticode.c
        libyara/modules/pe/authenticode-parser/certificate.c
        libyara/modules/pe/authenticode-parser/certificate.h
        libyara/modules/pe/authenticode-parser/countersignature.c
        libyara/modules/pe/authenticode-parser/countersignature.h
        libyara/modules/pe/authenticode-parser/helper.c
        libyara/modules/pe/authenticode-parser/helper.h
        libyara/modules/pe/authenticode-parser/structs.c
        libyara/modules/pe/authenticode-parser/structs.h
        libyara/modules/pe/pe.c
        libyara/modules/pe/pe_utils.c
        libyara/modules/string/string.c
        libyara/modules/tests/tests.c
        libyara/modules/time/time.c
        libyara/modules.c
        libyara/notebook.c
        libyara/object.c
        libyara/parser.c
        libyara/pb/yara.proto
        libyara/proc/freebsd.c
        libyara/proc/linux.c
        libyara/proc/mach.c
        libyara/proc/none.c
        libyara/proc/openbsd.c
        libyara/proc/windows.c
        libyara/proc.c
        libyara/re.c
        libyara/re_grammar.c
        libyara/re_grammar.h
        libyara/re_lexer.c
        libyara/rules.c
        libyara/scan.c
        libyara/scanner.c
        libyara/simple_str.c
        libyara/sizedstr.c
        libyara/stack.c
        libyara/stopwatch.c
        libyara/stream.c
        libyara/strutils.c
        libyara/threading.c
        libyara/tlshc/tlsh.c
        libyara/tlshc/tlsh_impl.c
        libyara/tlshc/tlsh_impl.h
        libyara/tlshc/tlsh_util.c
        libyara/tlshc/tlsh_util.h
        cli/args.c
        cli/args.h
        cli/common.c
        cli/common.h
        cli/threading.c
        cli/threading.h
        cli/unicode.h
        cli/yara.c
)

set(MY_LINUX_PROC_MACRO 1)
add_definitions(-DBUCKETS_256 -DCHECKSUM_3B -DUSE_LINUX_PROC=${MY_LINUX_PROC_MACRO})

add_library(crypto STATIC IMPORTED)
set_target_properties(crypto PROPERTIES IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/openssl/lib/${CMAKE_ANDROID_ARCH_ABI}/libcrypto.a")

add_library(ssl STATIC IMPORTED)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/openssl/lib/${CMAKE_ANDROID_ARCH_ABI}/libssl.a")

set(OPENSSL_ROOT_DIR ${CMAKE_SOURCE_DIR}/OpenSSL)
set(OPENSSL_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/OpenSSL/include)
set(OPENSSL_CRYPTO_LIBRARY ${CMAKE_SOURCE_DIR}/OpenSSL/lib)

#list(APPEND CMAKE_FIND_ROOT_PATH "${OPENSSL_ROOT_DIR}")

find_package(OpenSSL REQUIRED)
if (OpenSSL_FOUND)
    add_definitions(-DHAVE_LIBCRYPTO)
endif ()

target_link_libraries(yara
        android
        log
        jansson
        crypto
        ssl)