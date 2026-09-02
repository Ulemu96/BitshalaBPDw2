#!/bin/bash
set -euo pipefail

PRIVKEY1="1111111111111111111111111111111111111111111111111111111111111111"
PRIVKEY1="${PRIVKEY1:0:64}"
PRIVKEY2="2222222222222222222222222222222222222222222222222222222222222222"
PRIVKEY2="${PRIVKEY2:0:64}"

PREV_TXID="0000000000000000000000000000000000000000000000000000000000000000"
PREV_TXID="${PREV_TXID:0:64}"
PREV_VOUT="00000000"
PREV_AMOUNT_SATS_HEX="a086010000000000"

DEST_AMOUNT_SATS_HEX="60cb010000000000"
DEST_SCRIPT="76a9149e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f88ac"

SEQUENCE="ffffffff"
LOCKTIME="00000000"

hex_to_bin_file() {
    python3 -c "import sys; open(sys.argv[2],'wb').write(bytes.fromhex(sys.argv[1]))" "$1" "$2"
}

sha256_hex() {
    local hex="$1" tmp
    tmp=$(mktemp)
    hex_to_bin_file "$hex" "$tmp"
    openssl dgst -sha256 -binary < "$tmp" | od -An -vtx1 | tr -d ' \n'
    rm -f "$tmp"
}

hash256_hex() {
    sha256_hex "$(sha256_hex "$1")"
}

varint() {
    local n=$1
    if   [ "$n" -lt 253 ];   then printf '%02x' "$n"
    elif [ "$n" -le 65535 ]; then printf 'fd%02x%02x' $((n & 0xff)) $((n >> 8))
    else python3 -c "print(bytes([int(('$n'))]).hex())"
    fi
}

push_data() {
    local data="$1"
    local len_bytes=$(( ${#data} / 2 ))
    if [ "$len_bytes" -lt 76 ]; then
        printf '%02x%s' "$len_bytes" "$data"
    else
        printf '4c%02x%s' "$len_bytes" "$data"
    fi
}

pubkey_from_privkey() {
    python3 -c "
import sys
from ecdsa import SigningKey, SECP256k1
sk = SigningKey.from_string(bytes.fromhex(sys.argv[1]), curve=SECP256k1)
vk = sk.get_verifying_key()
x = vk.pubkey.point.x(); y = vk.pubkey.point.y()
prefix = b'\x02' if y % 2 == 0 else b'\x03'
print((prefix + x.to_bytes(32,'big')).hex())
" "$1"
}

ecdsa_sign_digest() {
    local privkey_hex="$1" digest_hex="$2"
    python3 -c "
import sys, hashlib
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize
sk = SigningKey.from_string(bytes.fromhex(sys.argv[1]), curve=SECP256k1)
digest = bytes.fromhex(sys.argv[2])
sig = sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=sigencode_der_canonize)
print((sig + b'\x01').hex())
" "$privkey_hex" "$digest_hex"
}

reverse_bytes_hex() {
    python3 -c "import sys; print(bytes.fromhex(sys.argv[1])[::-1].hex())" "$1"
}

PUBKEY1=$(pubkey_from_privkey "$PRIVKEY1")
PUBKEY2=$(pubkey_from_privkey "$PRIVKEY2")

OP_2="52"
OP_CHECKMULTISIG="ae"
WITNESS_SCRIPT="${OP_2}$(push_data "$PUBKEY1")$(push_data "$PUBKEY2")${OP_2}${OP_CHECKMULTISIG}"

WITNESS_PROGRAM=$(sha256_hex "$WITNESS_SCRIPT")
P2WSH_SCRIPT_PUBKEY="0020${WITNESS_PROGRAM}"

VERSION="01000000"
PREV_TXID_INTERNAL=$(reverse_bytes_hex "$PREV_TXID")
OUTPOINT="${PREV_TXID_INTERNAL}${PREV_VOUT}"

HASH_PREVOUTS=$(hash256_hex "$OUTPOINT")
HASH_SEQUENCE=$(hash256_hex "$SEQUENCE")

OUTPUT_SER="${DEST_AMOUNT_SATS_HEX}$(varint $(( ${#DEST_SCRIPT} / 2 )))${DEST_SCRIPT}"
HASH_OUTPUTS=$(hash256_hex "$OUTPUT_SER")

SCRIPT_CODE="$(varint $(( ${#WITNESS_SCRIPT} / 2 )))${WITNESS_SCRIPT}"
SIGHASH_TYPE="01000000"

PREIMAGE="${VERSION}${HASH_PREVOUTS}${HASH_SEQUENCE}${OUTPOINT}${SCRIPT_CODE}${PREV_AMOUNT_SATS_HEX}${SEQUENCE}${HASH_OUTPUTS}${LOCKTIME}${SIGHASH_TYPE}"
SIGHASH=$(hash256_hex "$PREIMAGE")

SIGNATURE1=$(ecdsa_sign_digest "$PRIVKEY1" "$SIGHASH")
SIGNATURE2=$(ecdsa_sign_digest "$PRIVKEY2" "$SIGHASH")

MARKER="00"
FLAG="01"
INPUT_COUNT="01"
SCRIPT_SIG="00"
OUTPUT_COUNT="01"

WITNESS_STACK="04"
WITNESS_STACK+="00"
WITNESS_STACK+="$(varint $(( ${#SIGNATURE1} / 2 )))${SIGNATURE1}"
WITNESS_STACK+="$(varint $(( ${#SIGNATURE2} / 2 )))${SIGNATURE2}"
WITNESS_STACK+="$(varint $(( ${#WITNESS_SCRIPT} / 2 )))${WITNESS_SCRIPT}"

FINAL_TX="${VERSION}${MARKER}${FLAG}${INPUT_COUNT}${OUTPOINT}${SCRIPT_SIG}${SEQUENCE}${OUTPUT_COUNT}${OUTPUT_SER}${WITNESS_STACK}${LOCKTIME}"

echo "Pubkey 1:           $PUBKEY1"
echo "Pubkey 2:           $PUBKEY2"
echo "Witness script:     $WITNESS_SCRIPT"
echo "P2WSH scriptPubKey: $P2WSH_SCRIPT_PUBKEY"
echo
echo "Sighash (BIP143):   $SIGHASH"
echo "Signature 1:        $SIGNATURE1"
echo "Signature 2:        $SIGNATURE2"
echo
echo "Final raw tx hex:"
echo "$FINAL_TX"

echo "$FINAL_TX" > out.txt
