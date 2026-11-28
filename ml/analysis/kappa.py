"""Score completed blinded sheets with Cohen's kappa on common items."""
import argparse
import csv
import json
from pathlib import Path

from ml.analysis.label_sample import LABELS


def score(pairs):
    if not pairs:
        raise ValueError("no paired labels")
    codes = tuple(LABELS)
    matrix = [[0 for _ in codes] for _ in codes]
    for a, b in pairs:
        matrix[codes.index(a)][codes.index(b)] += 1
    n = len(pairs)
    observations = sum(matrix[i][i] for i in range(len(codes)))
    chance_numerator = sum(sum(matrix[i]) * sum(row[i] for row in matrix) for i in range(len(codes)))
    return {"pairs": n, "agreement": observations / n,
            "cohens_kappa": ((observations * n - chance_numerator) / (n * n - chance_numerator)
                             if n * n != chance_numerator else None),
            "rows_rater_A_columns_rater_B": matrix, "labels": LABELS}


def read_labels(path, expected):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        answers = {}
        for row in csv.DictReader(stream):
            key = row["sample_id"]
            label = row["label"].strip()
            if key in answers or key not in expected or (label and label not in LABELS):
                raise ValueError(f"invalid row or label in {path.name}: {key}")
            answers[key] = label
    if answers.keys() != expected:
        raise ValueError(f"missing rows in {path.name}")
    return answers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "a", "b"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    paired = {"A": {}, "B": {}}
    for rater, path in (("A", args.a), ("B", args.b)):
        relevant = [row for row in manifest["rows"] if row["rater"] == rater]
        labels = read_labels(path, {row["sample_id"] for row in relevant})
        paired[rater] = {tuple(row["source_session"]): labels[row["sample_id"]]
                         for row in relevant if row["shared"]}
    if (paired["A"].keys() != paired["B"].keys() or len(paired["A"]) != manifest["common"]
            or any(not value for labels in paired.values() for value in labels.values())):
        parser.error("all common items in both sheets need a valid label")
    pairs = [(label, paired["B"][key]) for key, label in paired["A"].items()]
    print(json.dumps(score(pairs), ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
