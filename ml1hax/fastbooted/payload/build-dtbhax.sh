set -euxo pipefail

BASE=$(dirname "$0")
DTBHAX_PAYLOAD=$BASE/src/fastboot/commands/dtbhax.bin

cp $BASE/../dtbhax.ld $BASE/../ccplex.ld
rm -f $DTBHAX_PAYLOAD
cargo clean --manifest-path $(dirname "$0")/Cargo.toml -p payload
cargo build-dtbhax-bin
mv dtbhax.bin $DTBHAX_PAYLOAD
