#!/usr/bin/env bash
set -e
USAGE="$0 <fib_path> <sum_path> <n>"

fib_path=${1?$USAGE}
sum_path=${2?$USAGE}
n=${3?$USAGE}
create_thunk_path=$(which gg-create-thunk-static)

fib_hash=$(gg-hash $fib_path)
sum_hash=$(gg-hash $sum_path)
create_thunk_hash=$(gg-hash $create_thunk_path)

function placeholder() {
    echo "@{GGHASH:$1}"
}

gg-init 2>/dev/null

gg-collect $fib_path $sum_path $create_thunk_path >/dev/null

gg-create-thunk-static \
    --output out \
    --output out1 \
    --output out2 \
    --executable $fib_hash \
    --executable $create_thunk_hash \
    --envar fib_hash=$fib_hash \
    --envar sum_hash=$sum_hash \
    --envar create_thunk_hash=$create_thunk_hash \
    --placeholder f$n \
    -- \
    $fib_hash \
    fib.py \
    $n \
    $(placeholder $create_thunk_hash) \
