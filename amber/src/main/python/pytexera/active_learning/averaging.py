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
Serves the average of the trainer's last few model versions instead of the
newest one. A tool like MONAI Label keeps only the newest weights, so each
round's suggestions swing with whatever the last few labels pulled the model
toward; the average of recent versions is steadier and usually better.
"""

import io
import json
import random
from typing import Dict, Iterator, List, Optional

import numpy as np
import torch

from .data import dataset, dice, load_version, model
from .loops import Row, _load_model, _now, _predict, _tensor
from .unet import UNet

# Labeled scans the batch-norm statistics of an average are recomputed on.
RECALIBRATION_SCANS = 256


def average_weights(states: List[Dict[str, torch.Tensor]], images: List[np.ndarray]) -> UNet:
    """
    The uniform average of `states`. Averaged batch-norm statistics do not
    describe the averaged weights, so they are recomputed on `images`.
    """
    averaged = {
        key: torch.stack([s[key].float() for s in states]).mean(0).to(value.dtype)
        if value.is_floating_point()
        else value.clone()
        for key, value in states[-1].items()
    }
    net = UNet()
    net.load_state_dict(averaged)
    for module in net.modules():
        if isinstance(module, torch.nn.BatchNorm2d):
            module.reset_running_stats()
            module.momentum = None  # a plain average over the recalibration batches
    net.train()
    with torch.no_grad():
        for start in range(0, len(images), 32):
            net(_tensor(images[start:start + 32]))
    return net.eval()


class WeightAverager:
    """
    Every time the trainer publishes a version, publishes the average of its
    last `keep` versions as a version of the averaged model, and scores both
    the newest and the averaged model on the cohort's validation cases.
    """

    def __init__(
        self,
        scans_name: str,
        labels_name: str,
        truth_name: str,
        source_model: str,
        averaged_model: str,
        keep: int,
        validation_size: int,
    ):
        if keep < 2:
            raise ValueError("Average at least 2 versions.")
        self.keep = keep
        self.source = model(source_model)
        self.averaged = model(averaged_model, create=True)
        self.labels_res = dataset(labels_name)
        _, self.scans, cases = load_version(dataset(scans_name), "scans")
        _, truth, _ = load_version(dataset(truth_name), "masks")
        validation = sorted(c for c, row in cases.items() if row.get("split") == "val" and c in truth)
        if not validation:
            raise ValueError("The scans dataset's cases.csv has no validation cases (split = 'val').")
        self.validation = random.Random(0).sample(validation, min(validation_size, len(validation)))
        self.truth = {c: truth[c] for c in self.validation}
        self.done: Optional[int] = None

    def _score(self, net: UNet) -> Iterator[Optional[float]]:
        probs = None
        for probs in _predict(net, [self.scans[c] for c in self.validation]):
            if probs is None:
                yield None
        yield float(np.mean([dice((p > 0.5) * 255, self.truth[c]) for p, c in zip(probs, self.validation)]))

    def update(self) -> Iterator[Row]:
        """Averages the newest versions if the trainer published since the last call."""
        versions = self.source.versions()
        if len(versions) < 2 or versions[-1]["mvid"] == self.done:
            return
        recent = versions[-self.keep:]
        states = []
        for version in recent:
            weights = self.source.read_file(version["name"], "model.pt")
            states.append(torch.load(io.BytesIO(weights), weights_only=True))
            yield None
        labeled = [
            p.split("/")[-1][:-4]
            for p in self.labels_res.latest_file_paths()
            if p.startswith("masks/") and p.split("/")[-1][:-4] in self.scans
        ]
        sample = random.Random(len(labeled)).sample(labeled, min(RECALIBRATION_SCANS, len(labeled)))
        averaged = average_weights(states, [self.scans[c] for c in sample])
        yield None
        newest_dice = averaged_dice = None
        for newest_dice in self._score(_load_model(self.source, recent[-1])):
            if newest_dice is None:
                yield None
        for averaged_dice in self._score(averaged):
            if averaged_dice is None:
                yield None

        names = [v["name"].split(" ")[0] for v in recent]
        buffer = io.BytesIO()
        torch.save(averaged.state_dict(), buffer)
        meta = {
            "averaged_versions": [v["name"] for v in recent],
            "source_version_id": recent[-1]["mvid"],
            "validation_dice": round(averaged_dice, 4),
            "newest_validation_dice": round(newest_dice, 4),
            "recalibrated_on": len(sample),
            "created_at": _now(),
        }
        self.averaged.upload("model.pt", buffer.getvalue())
        self.averaged.upload("meta.json", json.dumps(meta, indent=2).encode())
        published = self.averaged.commit(
            f"Dice {averaged_dice:.3f}, average of {names[0]}..{names[-1]}"
        )["name"]
        self.done = recent[-1]["mvid"]
        yield {
            "labeled_cases": len(labeled),
            "newest_version": recent[-1]["name"],
            "averaged_versions": len(recent),
            "newest_dice": newest_dice,
            "averaged_dice": averaged_dice,
            "gain": averaged_dice - newest_dice,
            "published_model_version": published,
            "time": _now(),
        }
