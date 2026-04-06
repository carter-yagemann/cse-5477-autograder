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
import logging
import os
import sys

log = logging.getLogger(__name__)


class Submission(object):
    def __init__(self):
        self.hash2label = dict()
        self.hash2cluster = dict()
        self.cluster2hashes = dict()
        self.namespaced = True

    def add_sample(self, hash: str, label: str, cluster: str, namespace=None):
        assert label in "01"

        self.hash2label[hash] = label

        # only apply cluster if label is malicious: 1
        if label == "1":
            # cluster names are namespaced to avoid collisions while remapping
            if namespace is None:
                c_name = cluster
                # this submission is no longer safe for remapping because there could be collisions!
                self.namespaced = False
            else:
                c_name = "%s.%s" % (namespace, cluster)

            self.hash2cluster[hash] = c_name

            if not c_name in self.cluster2hashes:
                self.cluster2hashes[c_name] = set()
            self.cluster2hashes[c_name].add(hash)

    def get_cluster(self, cluster: str):
        return self.cluster2hashes[cluster]

    def get_cluster_names(self):
        return self.cluster2hashes.keys()

    def get_hashes(self):
        return self.hash2label.keys()

    def lookup_label(self, hash: str):
        if hash in self.hash2label:
            return self.hash2label[hash]
        return None

    def lookup_cluster(self, hash: str):
        if hash in self.hash2cluster:
            return self.hash2cluster[hash]
        return None

    def num_samples(self):
        return len(self.hash2label)

    def num_malicious(self):
        mal = 0
        for hash in self.hash2label:
            if self.hash2label[hash] == "1":
                mal += 1
        return mal

    def is_malicious(self, hash: str):
        return self.hash2label[hash] == "1"

    def convert_cluster(self, old_name: str, new_name: str):
        assert self.namespaced

        for hash in self.hash2cluster:
            if not hash in self.hash2cluster:
                continue

            if self.hash2cluster[hash] == old_name:
                self.hash2cluster[hash] = new_name

        self.cluster2hashes[new_name] = self.cluster2hashes.pop(old_name)


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        description="Auto grader for CSE 5477.02 and CSE 5479",
    )

    parser.add_argument(
        "-l",
        "--logging",
        type=int,
        default=logging.INFO,
        help="Set logging level, 0-50",
    )
    parser.add_argument(
        "--disable-popularity",
        action="store_true",
        help="Only consider ground truth CSV when awarding points, ignore other submissions",
    )
    parser.add_argument("ground_truth_csv", help="Path to CSV file with ground truth")
    parser.add_argument(
        "submissions_directory", help="Path to directory containing student submissions"
    )
    parser.add_argument(
        "output_csv_filepath", help="Write final scores to provided file path"
    )
    parser.add_argument(
        "transcripts_directory", help="Directory to store grading transcripts"
    )

    return parser.parse_args()


def remap_clusters(sub, gt):
    """We can't tell students what to name their clusters because that would give away most of
    the answer, so we infer the mapping from their cluster names to our ground truth names by
    finding the minimum edit distance between sets.

    Keyword Arguments:
    subs -- Student submission from parse_submission
    gt -- Ground truth CSV parsed with parse_submission

    Returns: None, sub is directly modified.
    """
    mapping = dict()

    for orig_name in sub.get_cluster_names():
        sub_cluster = sub.get_cluster(orig_name)
        best_match = None

        for gt_name in gt.get_cluster_names():
            gt_cluster = gt.get_cluster(gt_name)
            distance = len(sub_cluster - gt_cluster) + len(gt_cluster - sub_cluster)
            if best_match is None or distance < best_match[1]:
                # this is the new best match
                best_match = (gt_name, distance)

        assert not best_match is None

        mapping[orig_name] = best_match[0]

    log.debug("Mapping: %s" % str(mapping))

    for orig_name in mapping:
        gt_name = mapping[orig_name]
        sub.convert_cluster(orig_name, gt_name)


def _dict_max(dict):
    """Returns the key with the highest value."""
    winner = None
    for key in dict:
        if winner is None or dict[key] > winner[1]:
            winner = (key, dict[key])
    return winner[0]


def popularity_contest(subs, gt):
    """Generates a submission where each sample has the label and cluster most voted for by
    students based on their submissions.

    This can be helpful for spotting potentially wrong ground truth.
    (Yes, it's funny to say that ground truth might not be true, but our ground truth comes from
    an external source, so we need to "trust but verify.")

    Returns: Submission
    """
    vt = Submission()

    for hash in gt.get_hashes():
        label_counts = dict()
        cluster_counts = dict()

        for id in subs:
            sub = subs[id]
            label = sub.lookup_label(hash)
            cluster = sub.lookup_cluster(hash)

            if not label is None:
                if not label in label_counts:
                    label_counts[label] = 0
                label_counts[label] += 1

            if not cluster is None:
                if not cluster in cluster_counts:
                    cluster_counts[cluster] = 0
                cluster_counts[cluster] += 1

        pop_label = _dict_max(label_counts)
        pop_cluster = _dict_max(label_counts)

        log.debug(
            "Popular: %s, %s (gt: %s), %s (gt: %s)"
            % (
                hash,
                pop_label,
                gt.lookup_label(hash),
                pop_cluster,
                gt.lookup_cluster(hash),
            )
        )
        vt.add_sample(hash, pop_label, pop_cluster)

    return vt


def score_students(subs, gt, vt, use_popularity=True):
    """Calculates the score for each student's submission.

    Keyword Arguments:
    subs -- Dictionary of submissions.
    gt -- Ground truth Submission.
    vt -- Submission based on popularity contest.
    use_popularity -- If True, a student will get points for matching gt *OR* vt, otherwise only
    gt is compared.

    Returns: Dictionary keyed by student ID containing their score under the "score" key and
    their transcript under the "transcript" key. The transcript is a list of tuples (hash,
    is_correct_label, is_correct_cluster).
    """
    num_samples = gt.num_samples()
    num_malicious = gt.num_malicious()

    assert num_samples > 0

    results = dict()

    for student in subs:
        sub = subs[student]

        labels_correct = 0
        clusters_correct = 0
        transcript = list()

        for hash in gt.get_hashes():
            result = [hash]
            if gt.lookup_label(hash) == sub.lookup_label(hash):
                # correct based on ground truth
                labels_correct += 1
                result.append(1)
            elif use_popularity and vt.lookup_label(hash) == sub.lookup_label(hash):
                # correct based on popularity contest
                labels_correct += 1
                result.append(1)
            else:
                # incorrect label
                result.append(0)

            if not gt.is_malicious(hash):
                # cluster doesn't matter for benign samples
                result.append(-1)
            elif gt.lookup_cluster(hash) == sub.lookup_cluster(hash):
                # correct based on ground truth
                clusters_correct += 1
                result.append(1)
            elif use_popularity and vt.lookup_cluster(hash) == sub.lookup_cluster(hash):
                # correct based on popularity contest
                clusters_correct += 1
                result.append(1)
            else:
                # incorrect cluster
                result.append(0)

            assert len(result) == 3
            transcript.append(result)

        acc_labels = float(labels_correct) / num_samples
        acc_clusters = float(clusters_correct) / num_malicious

        log.info(
            "Score: ID: %s, Labels: %f, Clusters: %f"
            % (student, acc_labels, acc_clusters)
        )
        results[student] = {
            "label_accuracy": acc_labels,
            "cluster_accuracy": acc_clusters,
            "score": (acc_labels + acc_clusters) / 2,
            "transcript": transcript,
        }

    return results


def trim_ext(val: str):
    """Removes .exe and .elf from the end of strings."""
    if val.endswith(".elf") or val.endswith(".exe"):
        return val[:-4]
    return val


def parse_submission(fp, namespace=None):
    """
    Parses a submission CSV and returns a populated Submission object.
    Supports both standard comma-separated and space-separated values.
    """
    sub = Submission()

    try:
        with open(fp, "r", encoding='utf-8-sig', errors='ignore') as ifile:
            # Using DictReader to handle CSV headers automatically
            reader = csv.DictReader(ifile)
            for row in reader:
                try:
                    # Try standard CSV retrieval
                    raw_hash = row.get("sha256sum")
                    raw_label = row.get("malicious")
                    raw_cluster = row.get("cluster")

                    # FALLBACK: If raw_label is None, the student likely used spaces instead of commas
                    if raw_label is None:
                        # DictReader puts the whole un-split line in the first key
                        full_line = list(row.values())[0] if row.values() else ""
                        parts = full_line.split()
                        if len(parts) >= 3:
                            raw_hash, raw_label, raw_cluster = parts[0], parts[1], parts[2]
                        else:
                            continue # Still can't parse, skip this row

                    # Basic safety check
                    if raw_hash is None or raw_label is None:
                        continue

                    # Clean data: strip whitespace and standardize casing
                    clean_hash = raw_hash.strip().lower()
                    clean_label = raw_label.strip()
                    # Default cluster to '0' or 'unknown' if missing
                    clean_cluster = (raw_cluster or "0").strip().lower()

                    # Validate label format
                    if clean_label not in ["0", "1"]:
                        log.warning(f"Skipping invalid label '{clean_label}' in {fp}")
                        continue

                    # Standardize extensions and add to submission object
                    cleaned = [
                        trim_ext(clean_hash),
                        clean_label,
                        trim_ext(clean_cluster)
                    ]
                    sub.add_sample(*cleaned, namespace)

                except Exception as row_err:
                    log.error(f"Error processing row in {fp}: {row_err}")
                    continue

    except (KeyError, FileNotFoundError, csv.Error) as ex:
        log.error("Critical error parsing file: %s, %s" % (fp, str(ex)))

    return sub

def parse_submissions(root):
    """
    Parses the submissions directory. 
    Supports two structures:
    1. root/student_id/file.csv
    2. root/student_id_other_stuff.csv
    """
    subs = dict()

    for item in os.listdir(root):
        path = os.path.join(root, item)
        
        if os.path.isdir(path):
            student_id = item 
            log.debug("Scanning submission directory: %s" % path)

            csv_fp = None
            for sub_item in os.listdir(path):
                if not sub_item.lower().endswith(".csv"):
                    continue
                csv_fp = os.path.join(path, sub_item)
                break

            if csv_fp is None:
                log.warning("Cannot find CSV for student directory: %s" % student_id)
                subs[student_id] = Submission()
            else:
                log.info("Parsing (from dir): %s" % csv_fp)
                subs[student_id] = parse_submission(csv_fp, student_id)

        elif item.lower().endswith(".csv"):
            student_id = item.split('_')[0]
            log.info("Parsing (flat file): %s" % path)
            subs[student_id] = parse_submission(path, student_id)

    return subs


def write_scores(scores, fp):
    """
    Writes the final scores to a CSV, sorted alphabetically by student_id.
    The format is ready for a quick copy-paste to students.
    """
    with open(fp, "w") as ofile:
        writer = csv.writer(ofile)
        
        writer.writerow(["Student ID", "Grade Summary (Ready to Copy)"])
        
        for id in sorted(scores.keys()):
            label_acc = scores[id]["label_accuracy"] * 100
            cluster_acc = scores[id]["cluster_accuracy"] * 100
            avg_score = scores[id]["score"] * 100
            
            summary = (
                f"Binary Classification: {label_acc:.2f}%\n"
                f"Clustering Accuracy: {cluster_acc:.2f}%\n"
                f"Average: {avg_score:.2f}%"
            )
            
            writer.writerow([id, summary])


def write_transcripts(scores, tdir):
    for id in scores:
        tfp = os.path.join(tdir, id + ".csv")
        with open(tfp, "w") as ofile:
            writer = csv.DictWriter(
                ofile, fieldnames=["hash", "is_correct_label", "is_correct_cluster"]
            )
            writer.writeheader()
            for hash, label, cluster in scores[id]["transcript"]:
                writer.writerow(
                    {
                        "hash": hash,
                        "is_correct_label": label,
                        "is_correct_cluster": cluster,
                    }
                )


def main():
    args = parse_arguments()

    # initialize logging
    log.setLevel(args.logging)
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(levelname)7s | %(asctime)-15s " "| %(message)s")
    )
    log.addHandler(handler)

    # input validation for transcripts directory
    if not os.path.isdir(args.transcripts_directory):
        if os.path.exists(args.transcripts_directory):
            log.error(
                "Transcripts directory is not a directory: %s"
                % args.transcripts_directory
            )
            sys.exit(1)
        os.mkdir(args.transcripts_directory)

    log.info("Parsing ground truth CSV: %s" % args.ground_truth_csv)
    gt = parse_submission(args.ground_truth_csv, "gt")

    log.info("Parsing student submissions")
    subs = parse_submissions(args.submissions_directory)

    log.info("Mapping student clusters to ground truth")
    for id in subs:
        remap_clusters(subs[id], gt)

    log.info("Performing student voting")
    vt = popularity_contest(subs, gt)

    log.info("Calculating scores")
    scores = score_students(subs, gt, vt, not args.disable_popularity)
    log.info("Writing: %s" % args.output_csv_filepath)
    write_scores(scores, args.output_csv_filepath)
    log.info("Writing: %s" % args.transcripts_directory)
    write_transcripts(scores, args.transcripts_directory)


if __name__ == "__main__":
    main()
