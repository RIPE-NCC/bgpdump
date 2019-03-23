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

if [ ! -z "$BGPDUMP_TEST_UATTR" ] ; then
for mrt in $(ls test_data) ; do
    printf "      testing -u %s..." "$mrt"
    OUT="$mrt.bgp.gz"
    # The pipe into sed removes the last field added by -u on table dump
    # and announcement (update files) lines, and allows us to chekc
    # everything else is the same without adding new test_expect files
    # to the repository.
    ./bgpdump -u -vm test_data/$mrt | sed '/|A\|B|/ s/|[^|]*|$/|/' > test_out/$OUT
    gzip -cd test_expect/$OUT | diff -q test_out/$OUT -
    if [ $? = 0 ]; then
        echo "success"
    else
        FAILURES=$(( FAILURES + 1 ))
    fi
done
fi

if [ $FAILURES != 0 ]; then
    echo !!! $FAILURES failures !!!
    exit 1
else
    exit 0
fi
