#!/bin/sh

FAILURES=0

mkdir -p test_out

echo "Running Regression Tests..."
for mrt in `ls test_data`; do
    /bin/echo -n "      testing $mrt..."
    OUT=$mrt.bgp.gz
    ./bgpdump -vm test_data/$mrt > test_out/$OUT
    gzip -cd test_expect/$OUT | diff -q test_out/$OUT -
    if [ $? = 0 ]; then
        echo "success"
    else
        FAILURES=$(( $FAILURES + 1 ))
    fi
done

if [ $FAILURES != 0 ]; then
    echo !!! $FAILURES failures !!!
    exit 1
else
    exit 0
fi
