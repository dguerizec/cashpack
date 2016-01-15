# Copyright (c) 2016 Dridi Boukelmoune
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

set -e
set -o pipefail

TEST_DIR="$(dirname "$0")"
TEST_TMP="$(mktemp -d cashpack.XXXXXXXX)"

trap "rm -fr $TEST_TMP" EXIT

cmd_check() {
	for cmd
	do
		type "$cmd" >/dev/null
	done
}

hex_decode() {
	cut -d '|' -f 1 |
	xxd -r -p
}

hex_encode() {
	hexdump -v -f "$TEST_DIR/rfcfmt" |
	sed -e 's/[ ]*$//'
}

mk_input() {
	cat >"$TEST_TMP/input"
}

hdecode() {
	cat >"$TEST_TMP/expected"

	hex_decode <"$TEST_TMP/input" >"$TEST_TMP/bindump"
	./hdecode $@ "$TEST_TMP/bindump" >"$TEST_TMP/output"

	diff -u "$TEST_TMP/expected" "$TEST_TMP/output" >&2
}
