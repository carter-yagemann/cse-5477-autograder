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

import os
import random
import sys


def main():
    random.seed()

    if len(sys.argv) != 2:
        print("Usage: %s [file]" % os.path.basename(__file__))
        sys.exit(1)

    with open(sys.argv[1], "ab") as ofile:
        ofile.write(random.randbytes(random.randint(1, 8)))

    print("Padded: %s" % sys.argv[1])


if __name__ == "__main__":
    main()
