#!/bin/sh

# Runs performance tests of several MAC implementations and message sizes

short_message="'H'*100"
long_message="'H'*(4*2**20)"
key=$(python -c "print 'K'*32")
alias avg='head -1 | cut -d : -f 2 | python -c "import sys; nums = [float(i) for i in sys.stdin.read().split()]; print sum(nums)/len(nums)"'

#echo "Testing message of size 100B"
#echo HMAC-MD5: $(python -m timeit -v -r 10 -n 5000 -s "msg = $short_message; import hmac, hashlib" "hmac.new('$key', msg, hashlib.md5).digest()" | avg)
#echo HMAC-SHA1: $(python -m timeit -v -r 10 -n 5000 -s "msg = $short_message; import hmac, hashlib" "hmac.new('$key', msg, hashlib.sha1).digest()" | avg)
#echo Keccak-256: $(python -m timeit -v -r 10 -n 5000 -s "msg = $short_message; import hashlib, sha3" "hashlib.sha3_256('$key' + msg).digest()" | avg)
#echo Keccak-512: $(python -m timeit -v -r 10 -n 5000 -s "msg = $short_message; import hashlib, sha3" "hashlib.sha3_512('$key' + msg).digest()" | avg)

echo "Testing message of size 4MB"
echo HMAC-MD5: $(python -m timeit -v -r 10 -n 10 -s "msg = $long_message; import hmac, hashlib" "hmac.new('$key', msg, hashlib.md5).digest()" | avg)
echo HMAC-SHA1: $(python -m timeit -v -r 10 -n 10 -s "msg = $long_message; import hmac, hashlib" "hmac.new('$key', msg, hashlib.sha1).digest()" | avg)
echo Keccak-256: $(python -m timeit -v -r 10 -n 10 -s "msg = $long_message; import hashlib, sha3" "hashlib.sha3_256('$key' + msg).digest()" | avg)
echo Keccak-512: $(python -m timeit -v -r 10 -n 10 -s "msg = $long_message; import hashlib, sha3" "hashlib.sha3_512('$key' + msg).digest()" | avg)

