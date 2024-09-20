#!/usr/bin/env python
#
# Copyright 2024 Carter Yagemann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import random

NUM_SAMPLES = 512
CLUSTERS = "1234"
ALPHANUMERIC = "abcdef0123456789"
HASH_LENGTH = 64


def generate_hash():
    hash = ""
    for _ in range(HASH_LENGTH):
        hash += random.choice(ALPHANUMERIC)
    return hash


def main():
    random.seed()

    print("sha256sum,malicious,cluster")
    for _ in range(NUM_SAMPLES):
        sha256sum = generate_hash()
        malicious = random.choice("01")
        cluster = random.choice(CLUSTERS)
        print("%s,%s,%s" % (sha256sum, malicious, cluster))


if __name__ == "__main__":
    main()
