#!/usr/bin/env bash
set -e

USAGE="$0 <echo_path> <message>"

echo_path=${1?$USAGE}
m=${2?$USAGE}
in_path=i.txt
function placeholder() {
    echo "@{GGHASH:$1}"
}

echo $m > $in_path
echo_hash=$(gg-hash $echo_path)
in_hash=$(gg-hash $in_path)
gg-init
gg-collect $echo_path $in_path
gg-create-thunk \
    --value $in_hash \
    --output out \
    --executable $echo_hash \
    --placeholder out \
    -- \
    $echo_hash \
    'echo.py' \
    $(placeholder $in_hash) \
    out \
    out2
    
