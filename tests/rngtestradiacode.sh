#!/bin/sh

kill_rngd() {
	sleep 30
	echo "killing"
	killall -9 rngd
}

kill_rngd &

../rngd -f -o /dev/stdout -x hwrng -x rdrand -x tpm -x jitter -x namedpipe -x rtlsdr -x pkcs11 -n radiacode | ../rngtest -c 100 --pipe > /dev/null
