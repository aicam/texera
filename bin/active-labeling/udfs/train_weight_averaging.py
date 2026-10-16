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

# U-Net with weight averaging: a second model, trained next to the plain U-Net.
#
# Input 0, the patient cohort: names the validation cases, the same 200 the plain
#   U-Net scores itself on, so the two Dice scores compare directly.
# Input 1, the corrected labels: every label a doctor submits. Once ROUND new labels
#   arrived, this model takes every label there is now, trains EPOCHS more epochs and
#   saves a version, so it keeps up however fast people label; the model it serves is
#   the average of its last KEEP versions, where the plain U-Net serves its newest
#   weights.
#
# It starts from the plain U-Net's newest weights, so the two are equal when this
# branch is added and every difference after that comes from averaging.
#
# Training runs on the GPU machine at GPU_TRAINER (bin/active-labeling/gpu_trainer.py),
# which gets the round's labeled scans and the model's state and sends back the new
# state; everything else stays here. Without it, or if it cannot be reached, the round
# trains on this machine's CPU.
from pytexera import *

import io
import json
import os
import random
import time
from datetime import datetime, timezone

import numpy as np
import requests
import torch

from pytexera.active_learning.data import dataset, dice, load_version, model
from pytexera.active_learning.unet import UNet, train_epochs

SCANS, TRUTH = "brain-mri", "brain-mri-gt"
LABELS, PLAIN_MODEL, AVERAGED_MODEL = "{labels}", "{plain_model}", "{averaged_model}"
ROUND, EPOCHS, KEEP, VALIDATION, BATCH = 8, 4, 3, 200, 16
GPU_TRAINER = "http://100.83.167.29:8790"  # empty: train on this machine's CPU
GPU_TOKEN_FILE = "~/.cache/active-labeling/gpu_trainer_token"


def tensor(images):
    return torch.from_numpy(np.stack(images)).float().div(255).unsqueeze(1)


class TrainWithWeightAveraging(UDFOperatorV2):
    def open(self) -> None:
        self.cohort, self.waiting = [], []
        self.net = None

    @overrides
    def process_tuple(self, tuple_: Tuple, port: int) -> Iterator[Optional[TupleLike]]:
        if port == 0:
            self.cohort.append(tuple_.as_dict())
            yield None
        elif self.net is None:
            self.waiting.append(tuple_.as_dict())  # labels that came before the cohort
            yield None
        else:
            yield from self.add_label(tuple_.as_dict())

    @overrides
    def on_finish(self, port: int) -> Iterator[Optional[TupleLike]]:
        if port != 0:
            return
        yield from self.start()
        for row in self.waiting:
            yield from self.add_label(row)
        self.waiting = []

    def start(self):
        torch.set_num_threads(2)
        _, self.scans, _ = load_version(dataset(SCANS), "scans")
        _, truth, _ = load_version(dataset(TRUTH), "masks")
        validation = sorted(str(row["case"]) for row in self.cohort if row.get("split") == "val")
        self.validation = random.Random(0).sample(validation, min(VALIDATION, len(validation)))
        self.truth = {case: truth[case] for case in self.validation}
        self.labels_res = dataset(LABELS)
        _, self.labels, _ = load_version(self.labels_res, "masks")  # seeds and labels so far
        self.net = UNet()
        plain = model(PLAIN_MODEL)
        newest = plain.latest_version()
        if newest is not None:
            weights = plain.read_file(newest["name"], "model.pt")
            self.net.load_state_dict(torch.load(io.BytesIO(weights), weights_only=True))
        self.optimizer = torch.optim.Adam(self.net.parameters(), lr=1e-3)
        self.averaged_res = model(AVERAGED_MODEL, create=True)
        self.versions, self.new_labels, self.best = [], 0, -1.0
        yield from self.train_round()

    def add_label(self, row):
        if str(row["case"]) not in self.labels:
            self.new_labels += 1
        yield None
        if self.new_labels >= ROUND:
            _, self.labels, _ = load_version(self.labels_res, "masks")  # every label there is now
            self.new_labels = 0
            yield from self.train_round()

    def train_round(self):
        names = [n for n in self.labels if n in self.scans]
        images = torch.from_numpy(np.stack([self.scans[n] for n in names]))
        masks = torch.from_numpy(np.stack([self.labels[n] for n in names]))
        yield None
        started = time.time()
        where = self.train_on_gpu(images, masks)
        if where is None:
            train_epochs(self.net, self.optimizer, images, masks, EPOCHS, BATCH, random)
            where = "this machine's CPU"
        print(f"{len(names)} labels, {EPOCHS} epochs on {where} in {time.time() - started:.1f} s")
        yield None
        self.versions = (self.versions + [{k: v.detach().clone() for k, v in self.net.state_dict().items()}])[-KEEP:]
        averaged = self.average(names)
        newest_dice, averaged_dice = self.score(self.net), self.score(averaged)
        yield None

        published = ""
        if averaged_dice > self.best + 1e-3:
            self.best = averaged_dice
            buffer = io.BytesIO()
            torch.save(averaged.state_dict(), buffer)
            self.averaged_res.upload("model.pt", buffer.getvalue())
            self.averaged_res.upload("meta.json", json.dumps({
                "validation_dice": round(averaged_dice, 4),
                "averaged_versions": len(self.versions),
                "labeled_cases": len(names),
            }).encode())
            published = self.averaged_res.commit(
                f"Dice {averaged_dice:.3f}, average of {len(self.versions)} versions, {len(names)} labels"
            )["name"]
        yield {
            "labeled_cases": len(names),
            "newest_dice": newest_dice,
            "averaged_dice": averaged_dice,
            "published_model_version": published,
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def train_on_gpu(self, images, masks):
        """Trains the round on the GPU machine; None if there is none or it cannot be reached."""
        if not GPU_TRAINER:
            return None
        request = io.BytesIO()
        torch.save({"model": self.net.state_dict(), "optimizer": self.optimizer.state_dict(), "lr": 1e-3,
                    "images": images, "masks": masks, "epochs": EPOCHS, "batch_size": BATCH,
                    "seed": random.randrange(2**31)}, request)
        try:
            token = open(os.path.expanduser(GPU_TOKEN_FILE)).read().strip()
            reply = requests.post(f"{GPU_TRAINER}/train", data=request.getvalue(), timeout=600,
                                  headers={"Authorization": f"Bearer {token}"})
            reply.raise_for_status()
        except (OSError, requests.RequestException) as err:
            print(f"GPU trainer unavailable ({err}); training on this machine's CPU")
            return None
        result = torch.load(io.BytesIO(reply.content), weights_only=True)
        self.net.load_state_dict(result["model"])
        self.optimizer.load_state_dict(result["optimizer"])
        return f"{result['device']} at {GPU_TRAINER} ({result['seconds']:.1f} s on the GPU)"

    def average(self, names):
        """The mean of the kept versions; batch-norm statistics are averaged with the weights."""
        states = self.versions
        mean = {
            k: torch.stack([s[k].float() for s in states]).mean(0).to(v.dtype) if v.is_floating_point() else v.clone()
            for k, v in states[-1].items()
        }
        net = UNet()
        net.load_state_dict(mean)
        return net.eval()

    def score(self, net):
        net.eval()
        probs = []
        with torch.no_grad():
            for start in range(0, len(self.validation), 64):
                chunk = self.validation[start:start + 64]
                probs.extend(torch.sigmoid(net(tensor([self.scans[c] for c in chunk]))).squeeze(1).numpy())
        self.net.train()
        return float(np.mean([dice((p > 0.5) * 255, self.truth[c]) for p, c in zip(probs, self.validation)]))
