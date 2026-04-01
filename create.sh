#!/bin/bash

IMAGE_HEADER_SIZE=1024 ./tools/keytools/sign --ecc384 --sha384 ~/work/nxp-appcodehub/dm-wolfssl-tls-hello-server-with-zephyr/debug/zephyr/zephyr_stripped.bin wolfboot_signing_private_key.der 1
IMAGE_HEADER_SIZE=1024 ./tools/keytools/sign --ecc384 --sha384 ~/work/nxp-appcodehub/dm-wolfssl-tls-hello-server-with-zephyr/debug/zephyr/zephyr_stripped.bin wolfboot_signing_private_key.der 2
cp ~/work/nxp-appcodehub/dm-wolfssl-tls-hello-server-with-zephyr/debug/zephyr/zephyr_stripped_v2_signed.bin ~/work/wolfMQTT/examples/
cp wolfboot.bin ~/work/nxp-appcodehub/dm-wolfssl-tls-hello-server-with-zephyr/debug/zephyr
cp wolfboot.elf ~/work/nxp-appcodehub/dm-wolfssl-tls-hello-server-with-zephyr/debug/zephyr
#./tools/bin-assemble/bin-assemble ~/work/nxp-appcodehub/dm-wolfssl-tls-hello-server-with-zephyr/debug/zephyr/factory.bin 0x0 wolfboot.bin 0x10000000 ~/work/nxp-appcodehub/dm-wolfssl-tls-hello-server-with-zephyr/debug/zephyr/zephyr_v1_signed.bin