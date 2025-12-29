set -euxo pipefail

BASE=$(dirname "$0")

$BASE/build-dtbhax.sh && cp $BASE/../sparsehax.ld $BASE/../ccplex.ld && rm -f payload.bin && cargo clean --manifest-path $BASE/Cargo.toml -p payload && cargo build-usb-bin && mv payload.bin $BASE/../../fastbootrs/src/payload.bin
