#!/usr/bin/env bash
#
# mayhem/build.sh — builds zmap with the sanitizers, the libFuzzer harnesses (plus their -standalone
# reproducers), and an unsanitized copy of the project for mayhem/test.sh. Offline and re-runnable.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT=/mayhem
B="$SRC/mayhem/build"
rm -rf "$B"
mkdir -p "$B"

# 1) The project, sanitized, as upstream documents (cmake); -fsanitize=fuzzer-no-link gives the
#    library SanCov edges so libFuzzer sees coverage inside zmap, not just in the harness.
cmake -S . -B "$B/fuzz" -G Ninja -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fno-sanitize=alignment,float-cast-overflow -fsanitize=fuzzer-no-link" \
    -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS"
ninja -C "$B/fuzz" -j"$MAYHEM_JOBS" zmap

# The harnesses replace zmap.c's main(): link every other object of the zmap target plus libzmaplib.
mapfile -t OBJS < <(find "$B/fuzz/src/CMakeFiles/zmap.dir" -name '*.o' ! -name 'zmap.c.o' | sort)
LIBS=("$B/fuzz/lib/libzmaplib.a" -lpcap -lgmp -lm -lunistring -ljson-c -lJudy -lpthread)
INC=(-I"$SRC/lib" -I"$SRC/src" -I"$B/fuzz/src" $(pkg-config --cflags json-c))
HFLAGS=($SANITIZER_FLAGS $DEBUG_FLAGS -fno-sanitize=alignment,float-cast-overflow -std=gnu11 -O1)

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

# 2) Each harness twice: libFuzzer binary and run-once reproducer.
build_harness() { # name source [extra cc flags...]
  local name=$1 src=$2; shift 2
  $CC "${HFLAGS[@]}" "$@" "${INC[@]}" $LIB_FUZZING_ENGINE "$src" "$B/lsan_off.o" "${OBJS[@]}" "${LIBS[@]}" -o "$OUT/$name"
  $CC "${HFLAGS[@]}" "$@" "${INC[@]}" "$B/standalone_main.o" "$src" "$B/lsan_off.o" "${OBJS[@]}" "${LIBS[@]}" -o "$OUT/$name-standalone"
}
build_harness fuzz_tcp_response mayhem/fuzz_probe.c -DFAMILY_TCP
build_harness fuzz_udp_response mayhem/fuzz_probe.c -DFAMILY_UDP
build_harness fuzz_dns_response mayhem/fuzz_probe.c -DFAMILY_DNS
build_harness fuzz_ntp_upnp_response mayhem/fuzz_probe.c -DFAMILY_NTP_UPNP
build_harness fuzz_icmp_response mayhem/fuzz_probe.c -DFAMILY_ICMP
build_harness fuzz_icmp_echo_time_response mayhem/fuzz_probe.c -DFAMILY_ICMP_TIME
build_harness fuzz_ports mayhem/fuzz_ports.c
build_harness fuzz_constraint mayhem/fuzz_constraint.c

# 3) The project's own tests, normal flags, for mayhem/test.sh: zblocklist (exercised by
#    test/test_zblocklist.py upstream) and the JA4TS unit test (test/unit/test_ja4ts.c).
cmake -S . -B "$B/normal" -G Ninja -DCMAKE_C_COMPILER="$CC" -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
ninja -C "$B/normal" -j"$MAYHEM_JOBS" zblocklist
$CC -O2 -std=c99 $COVERAGE_FLAGS -Isrc -DJA4TS_UNIT_TEST test/unit/test_ja4ts.c -o "$B/test_ja4ts"
