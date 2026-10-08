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
Layout of the three datasets an active-labeling run uses:

  scans   cases.csv (case, patient, split, has_tumor) and scans/<case>.png
  labels  masks/<case>.png and provenance/<case>.json, one pair per label
  truth   masks/<case>.png for every case; only the simulated annotator and
          the validation score read it

Images are 128x128 single-channel PNGs; masks are 0 or 255.
"""

import csv
import glob
import io
import json
import os
import shutil
import tempfile
from typing import Dict, Optional, Tuple

import numpy as np
from PIL import Image

from ..storage.resource_type import ResourceType
from ..storage.versioned_resource import VersionedResource


def read_png(data_or_path) -> np.ndarray:
    source = io.BytesIO(data_or_path) if isinstance(data_or_path, bytes) else data_or_path
    return np.asarray(Image.open(source).convert("L"), dtype=np.uint8)


def png_bytes(array: np.ndarray) -> bytes:
    buffer = io.BytesIO()
    Image.fromarray(array.astype(np.uint8)).save(buffer, format="PNG")
    return buffer.getvalue()


def load_version(resource: VersionedResource, folder: str) -> Tuple[Optional[dict], Dict[str, np.ndarray], Dict[str, dict]]:
    """
    The newest version's row, its PNGs under `folder` keyed by case, and its
    cases.csv rows if it has one. The download is deleted once loaded.
    """
    target = tempfile.mkdtemp(prefix=f"al-{resource.name}-")
    try:
        version = resource.download_latest(target)
        cases = load_cases(target) if os.path.exists(os.path.join(target, "cases.csv")) else {}
        return version, load_images(target, folder), cases
    finally:
        shutil.rmtree(target, ignore_errors=True)


def load_images(root: str, folder: str) -> Dict[str, np.ndarray]:
    return {
        os.path.splitext(os.path.basename(p))[0]: read_png(p)
        for p in glob.glob(os.path.join(root, folder, "*.png"))
    }


def load_cases(root: str) -> Dict[str, dict]:
    with open(os.path.join(root, "cases.csv")) as handle:
        return {row["case"]: row for row in csv.DictReader(handle)}


def load_provenance(root: str) -> Dict[str, dict]:
    result = {}
    for path in glob.glob(os.path.join(root, "provenance", "*.json")):
        with open(path) as handle:
            result[os.path.splitext(os.path.basename(path))[0]] = json.load(handle)
    return result


def dice(a: np.ndarray, b: np.ndarray) -> float:
    a, b = a > 127, b > 127
    total = a.sum() + b.sum()
    return 1.0 if total == 0 else float(2 * (a & b).sum() / total)


def dataset(name: str) -> VersionedResource:
    return VersionedResource(ResourceType.DATASET, name)


def model(name: str, create: bool = False) -> VersionedResource:
    return VersionedResource(ResourceType.MODEL, name, create=create)
