# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Loads the LGG brain MRI segmentation set (Buda et al., kaggle_3m layout) into
Texera as the datasets an active-labeling run uses: the scans, the expert
masks, a labels dataset holding a few seed labels, and an empty review queue.

    USER_JWT_TOKEN=<token> python prepare_lgg.py ~/data/lgg-mri/kaggle_3m
"""

import argparse
import csv
import glob
import io
import json
import os
import random
import sys
from concurrent.futures import ThreadPoolExecutor

import numpy as np
from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../amber/src/main/python"))
from pytexera.storage.resource_type import ResourceType  # noqa: E402
from pytexera.storage.versioned_resource import VersionedResource  # noqa: E402

SIZE = 128
FLAIR_CHANNEL = 1  # kaggle_3m slices are pre-contrast, FLAIR, post-contrast


def to_png(array: np.ndarray, resample) -> bytes:
    image = Image.fromarray(array).resize((SIZE, SIZE), resample)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", help="kaggle_3m directory")
    parser.add_argument("--scans", default="brain-mri")
    parser.add_argument("--truth", default="brain-mri-gt")
    parser.add_argument("--labels", default="brain-masks")
    parser.add_argument("--queue", default="brain-review-queue")
    parser.add_argument("--seed-labels", type=int, default=20)
    parser.add_argument("--negatives-per-positive", type=float, default=0.5)
    args = parser.parse_args()
    rng = random.Random(0)

    patients = sorted(p for p in os.listdir(args.source) if os.path.isdir(os.path.join(args.source, p)))
    validation = set(rng.sample(patients, len(patients) // 5))
    cases = []
    for patient in patients:
        positives, negatives = [], []
        for mask_path in glob.glob(os.path.join(args.source, patient, "*_mask.tif")):
            mask = np.asarray(Image.open(mask_path))
            entry = (os.path.basename(mask_path)[: -len("_mask.tif")], mask_path)
            (positives if mask.max() > 0 else negatives).append(entry)
        keep = rng.sample(negatives, min(len(negatives), int(len(positives) * args.negatives_per_positive)))
        for case, mask_path, tumor in [(c, m, True) for c, m in positives] + [(c, m, False) for c, m in keep]:
            cases.append(
                {
                    "case": case,
                    "patient": patient,
                    "split": "val" if patient in validation else "train",
                    "has_tumor": int(tumor),
                    "mask_path": mask_path,
                }
            )
    print(f"{len(cases)} slices from {len(patients)} patients")

    seeds = rng.sample([c for c in cases if c["split"] == "train" and c["has_tumor"]], args.seed_labels)
    scans = VersionedResource(ResourceType.DATASET, args.scans, create=True)
    truth = VersionedResource(ResourceType.DATASET, args.truth, create=True)
    labels = VersionedResource(ResourceType.DATASET, args.labels, create=True)
    VersionedResource(ResourceType.DATASET, args.queue, create=True)

    def upload_case(case: dict) -> None:
        image = np.asarray(Image.open(case["mask_path"].replace("_mask.tif", ".tif")))[..., FLAIR_CHANNEL]
        mask = np.asarray(Image.open(case["mask_path"]))
        scans.upload(f"scans/{case['case']}.png", to_png(image, Image.BILINEAR))
        truth.upload(f"masks/{case['case']}.png", to_png(mask, Image.NEAREST))

    with ThreadPoolExecutor(8) as pool:
        for done, _ in enumerate(pool.map(upload_case, cases), 1):
            if done % 250 == 0:
                print(f"  uploaded {done}/{len(cases)}")

    table = io.StringIO()
    writer = csv.DictWriter(table, fieldnames=["case", "patient", "split", "has_tumor"], extrasaction="ignore")
    writer.writeheader()
    writer.writerows(cases)
    scans.upload("cases.csv", table.getvalue().encode())
    scans.commit("LGG FLAIR slices, 128px")
    truth.commit("expert masks")

    for case in seeds:
        mask = np.asarray(Image.open(case["mask_path"]))
        labels.upload(f"masks/{case['case']}.png", to_png(mask, Image.NEAREST))
        labels.upload(
            f"provenance/{case['case']}.json",
            json.dumps({"case": case["case"], "annotator": "seed", "suggested_by": None}).encode(),
        )
    labels.commit(f"{len(seeds)} seed labels")
    print("done")


if __name__ == "__main__":
    main()
