#!/bin/bash
mkdir -p fuzz
test_case=0
while true; do
    dd if=/dev/urandom of=test bs=512 count=1
    cheeseshredder -i test >test.out 2>&1
    result=$?
    if [[ "$result" -ne "0" ]]; then
        echo "FAILED TEST! $result"
        # Increment test case number to avoid file collisions
        until [ ! -f "fuzz/test_case_$test_case" ]; do
            test_case=$((test_case+1))
        done
        cp test "fuzz/test_case_$test_case"
        cp test.out "fuzz/test_case_$test_case.out"
        break
    fi
done
