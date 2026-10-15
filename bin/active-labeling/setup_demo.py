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
Sets up a fresh active-labeling demo on top of the datasets prepare_lgg.py
loaded: a labels dataset holding only the seed labels, an empty review queue,
and the six-operator workflow that trains, suggests, and collects labels. The
canvas draws the loop from "Corrected labels" back into the trainer: the labels
reach it through the labels dataset's versions, not through a workflow link.

    USER_JWT_TOKEN=<token> python setup_demo.py --prefix demo [--simulated]

The model is created by the workflow's first epoch, so a new prefix starts
the whole story from 20 labels and no model.
"""

import argparse
import csv
import io
import json
import os
import random
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../amber/src/main/python"))
from pytexera.storage.resource_type import ResourceType  # noqa: E402
from pytexera.storage.versioned_resource import VersionedResource  # noqa: E402

API = os.getenv("TEXERA_API", "http://localhost:8080/api")


def operator(metadata: dict, op_type: str, op_id: str, name: str, overrides: dict) -> dict:
    entry = next(o for o in metadata["operators"] if o["operatorType"] == op_type)
    properties = {
        key: spec["default"]
        for key, spec in entry["jsonSchema"]["properties"].items()
        if spec.get("default") is not None
    }
    extra = entry["additionalMetadata"]
    return {
        "operatorID": op_id,
        "operatorType": op_type,
        "operatorVersion": entry["operatorVersion"],
        "operatorProperties": {**properties, **overrides},
        "customDisplayName": name,
        "inputPorts": [
            {"portID": f"input-{i}", "displayName": p.get("displayName", "")}
            for i, p in enumerate(extra["inputPorts"])
        ],
        "outputPorts": [
            {"portID": f"output-{i}", "displayName": p.get("displayName", "")}
            for i, p in enumerate(extra["outputPorts"])
        ],
        "showAdvanced": False,
    }


def link(source: str, target: str, port: int = 0) -> dict:
    return {
        "linkID": f"link-{source}-{target}",
        "source": {"operatorID": source, "portID": "output-0"},
        "target": {"operatorID": target, "portID": f"input-{port}"},
    }


def seed_labels(scans_name: str, truth_name: str, labels_name: str, queue_name: str, count: int) -> str:
    """Creates the labels dataset with `count` expert masks and an empty queue; returns the cohort path."""
    scans = VersionedResource(ResourceType.DATASET, scans_name)
    truth = VersionedResource(ResourceType.DATASET, truth_name)
    scans_version = scans.latest_version()["name"]
    cases = list(csv.DictReader(io.StringIO(scans.read_file(scans_version, "cases.csv").decode())))
    tumors = sorted(c["case"] for c in cases if c["split"] == "train" and c["has_tumor"] == "1")
    seeds = random.Random(0).sample(tumors, count)

    path = f"/dataset/{scans.owner_email}/{scans_name}/{scans_version}/cases.csv"
    if _exists(labels_name):
        print(f"'{labels_name}' exists; reusing its labels (use a new --prefix to start over)")
        return path
    labels = VersionedResource(ResourceType.DATASET, labels_name, create=True)
    VersionedResource(ResourceType.DATASET, queue_name, create=True)
    truth_version = truth.latest_version()["name"]
    for case in seeds:
        labels.upload(f"masks/{case}.png", truth.read_file(truth_version, f"masks/{case}.png"))
        labels.upload(
            f"provenance/{case}.json",
            json.dumps({"case": case, "annotator": "seed", "suggested_by": None}).encode(),
        )
    labels.commit(f"{count} seed labels")
    return path


def _exists(name: str) -> bool:
    try:
        VersionedResource(ResourceType.DATASET, name)
        return True
    except ValueError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", default="demo", help="names the demo's labels, queue, and model")
    parser.add_argument("--scans", default="brain-mri")
    parser.add_argument("--truth", default="brain-mri-gt")
    parser.add_argument("--seed-labels", type=int, default=20)
    parser.add_argument("--simulated", action="store_true", help="label with the simulated annotator")
    parser.add_argument(
        "--live-editing",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="keep every output, so operators can be added to the workflow while it runs",
    )
    args = parser.parse_args()
    labels, queue, model = f"{args.prefix}-masks", f"{args.prefix}-review-queue", f"{args.prefix}-unet"

    cohort = seed_labels(args.scans, args.truth, labels, queue, args.seed_labels)
    headers = {"Authorization": f"Bearer {os.environ['USER_JWT_TOKEN']}"}
    metadata = requests.get(f"{API}/resources/operator-metadata", headers=headers, timeout=30).json()
    shared = {"scansDataset": args.scans, "labelsDataset": labels, "modelName": model}

    operators = [
        operator(metadata, "CSVFileScan", "cohort", "Patient cohort", {"fileName": cohort}),
        operator(
            metadata,
            "Filter",
            "pool",
            "Training slices",
            {"predicates": [{"attribute": "split", "condition": "=", "value": "train"}]},
        ),
        operator(
            metadata, "TrainSegmenter", "train", "Train U-Net", {**shared, "truthDataset": args.truth}
        ),
        operator(metadata, "SuggestCases", "suggest", "Suggest cases", {**shared, "queueDataset": queue}),
        operator(
            metadata,
            "ReviewAndCorrect",
            "review",
            "Review & Correct",
            {**shared, "queueDataset": queue, "truthDataset": args.truth, "simulated": args.simulated},
        ),
        operator(
            metadata,
            "Projection",
            "corrected",
            "Corrected labels",
            {
                "isDrop": False,
                "attributes": [
                    {"originalAttribute": name, "alias": ""}
                    for name in ("case", "labels_version", "versions_behind", "dice_suggested_vs_final", "annotator")
                ],
            },
        ),
    ]
    content = {
        "operators": operators,
        "operatorPositions": {
            "cohort": {"x": 80, "y": 240},
            "pool": {"x": 340, "y": 120},
            "train": {"x": 340, "y": 360},
            "suggest": {"x": 600, "y": 240},
            "review": {"x": 860, "y": 240},
            "corrected": {"x": 1120, "y": 240},
        },
        "links": [
            link("cohort", "train"),
            link("cohort", "pool"),
            link("pool", "suggest", 0),
            link("train", "suggest", 1),
            link("suggest", "review"),
            link("review", "corrected"),
        ],
        "commentBoxes": [],
        # One tuple per batch: suggestions and labels must reach the next
        # operator as soon as they exist, not when 400 have piled up.
        "settings": {
            "dataTransferBatchSize": 1,
            "executionMode": "PIPELINED",
            "liveEditing": args.live_editing,
        },
    }
    name = f"Brain MRI active labeling ({args.prefix})" + (" simulated" if args.simulated else "")
    created = requests.post(
        f"{API}/workflow/create",
        headers=headers,
        json={"name": name, "content": json.dumps(content)},
        timeout=30,
    )
    created.raise_for_status()
    print(f"labels '{labels}' ({args.seed_labels} seeds), queue '{queue}', model '{model}'")
    print(f"workflow {created.json()['workflow']['wid']}: {name}")


if __name__ == "__main__":
    main()
