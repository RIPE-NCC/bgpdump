#!/usr/bin/env bash

FAILURES=0

echo "Running Regression Tests..."
for mrt in `ls test_data`; do
    echo -n "      testing $mrt..."
    OUT=$mrt.bgp.gz
    ./bgpdump -vm test_data/$mrt | gzip > test_out/$OUT
    cmp -si 6 test_out/$OUT test_expect/$OUT
    if [ $? == 0 ]; then
        echo "success"
    else
        echo "FAILURE"
        FAILURES=$(( $FAILURES + 1 ))
    fi
done

if [ $FAILURES != 0 ]; then
    echo !!! $FAILURES failures !!!
    exit 1
else
    exit 0
fi
