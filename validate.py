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

import argparse
import csv
import os

from grade import Submission, parse_submission


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        description="Validate a CSV submission for the auto grader",
    )

    parser.add_argument("submission_csv", help="Path to CSV submission file")

    return parser.parse_args()


def main():
    args = parse_arguments()
    sub = parse_submission(args.submission_csv)
    print("Parsed submission successfully, found %d samples!" % sub.num_samples())


if __name__ == "__main__":
    main()
