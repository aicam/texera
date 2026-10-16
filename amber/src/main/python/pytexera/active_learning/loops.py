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
The three loops of an active-labeling run. Training and labeling run at the
same time and only meet through versions: the trainer publishes model
versions and reads the newest labels version every epoch; the suggester
publishes review batches built from the newest model version; every
submitted label is its own labels version, carrying provenance that names
the model version that suggested it.

Each loop is a generator. Yielding None hands control back to the engine so a
long wait never blocks pause, console output or other control messages.
"""

import io
import json
import math
import os
import random
import time
import zlib
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional

import numpy as np
import torch

from .data import dataset, dice, load_version, model, png_bytes, read_png
from .unet import UNet, dice_loss

Row = Optional[Dict[str, object]]


def _wait(seconds: float) -> Iterator[None]:
    deadline = time.time() + seconds
    while time.time() < deadline:
        time.sleep(min(0.5, max(0.0, deadline - time.time())))
        yield None


def _tensor(images: List[np.ndarray]) -> torch.Tensor:
    return torch.from_numpy(np.stack(images)).float().div(255).unsqueeze(1)


def _predict(net: UNet, images: List[np.ndarray], chunk: int = 64) -> Iterator[Optional[np.ndarray]]:
    """Yields None between chunks, then the stacked probabilities."""
    net.eval()
    out = []
    for start in range(0, len(images), chunk):
        # Scoped per chunk: a generator suspended inside no_grad would leave
        # gradients off for whatever else runs on this thread.
        with torch.no_grad():
            out.append(torch.sigmoid(net(_tensor(images[start:start + chunk]))).squeeze(1).numpy())
        yield None
    yield np.concatenate(out) if out else np.zeros((0, 128, 128))


def _load_model(model_res, version: dict) -> UNet:
    net = UNet()
    weights = model_res.read_file(version["name"], "model.pt")
    net.load_state_dict(torch.load(io.BytesIO(weights), weights_only=True))
    return net


def _trained_by(model_res, version: dict) -> int:
    """
    The trainer's version a model version stands for: itself, or for a model
    derived from the trainer's versions (such as their average) the newest
    version it was derived from. Staleness counts trainer versions either way.
    """
    meta = json.loads(model_res.read_file(version["name"], "meta.json"))
    return meta.get("source_version_id", version["mvid"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def train(
    cases: List[Dict[str, object]],
    scans_name: str,
    labels_name: str,
    truth_name: str,
    model_name: str,
    max_epochs: int,
    batch_size: int,
    validation_size: int,
    warm_start: bool,
) -> Iterator[Row]:
    """
    Trains on the newest labels every epoch and validates on the cohort's
    validation cases. With `warm_start` it continues from the newest model
    version, so stopping and re-running the workflow never throws learning away.
    """
    torch.manual_seed(0)
    torch.set_num_threads(max(1, (os.cpu_count() or 2) // 2))
    _, scans, _ = load_version(dataset(scans_name), "scans")
    _, truth, _ = load_version(dataset(truth_name), "masks")
    validation = sorted(str(row["case"]) for row in cases if row.get("split") == "val")
    validation = random.Random(0).sample(validation, min(validation_size, len(validation)))
    if not validation:
        raise ValueError("The cohort has no validation cases (split = 'val'); the trainer cannot score models.")
    labels_res, model_res = dataset(labels_name), model(model_name, create=True)
    yield None

    net = UNet()
    resumed_from = model_res.latest_version() if warm_start else None
    if resumed_from is not None:
        net = _load_model(model_res, resumed_from)
    optimizer = torch.optim.Adam(net.parameters(), lr=1e-3)
    labels_version, labeled, best = None, {}, -1.0
    for epoch in range(1, max_epochs + 1):
        newest = labels_res.latest_version()
        if newest is not None and (labels_version is None or newest["dvid"] != labels_version["dvid"]):
            labels_version, labeled, _ = load_version(labels_res, "masks")
        names = [n for n in labeled if n in scans]
        if not names:
            yield from _wait(5)
            continue

        net.train()
        random.shuffle(names)
        losses = []
        for start in range(0, len(names), batch_size):
            batch = names[start:start + batch_size]
            x = _tensor([scans[n] for n in batch])
            y = _tensor([labeled[n] for n in batch]).round()
            if random.random() < 0.5:
                x, y = x.flip(-1), y.flip(-1)
            logits = net(x)
            loss = dice_loss(logits, y) + torch.nn.functional.binary_cross_entropy_with_logits(logits, y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            losses.append(loss.item())
            yield None

        probs = None
        for probs in _predict(net, [scans[c] for c in validation]):
            if probs is None:
                yield None
        score = float(np.mean([dice((p > 0.5) * 255, truth[c]) for p, c in zip(probs, validation)]))

        published = ""
        if score > best + 1e-3:
            best = score
            buffer = io.BytesIO()
            torch.save(net.state_dict(), buffer)
            meta = {
                "epoch": epoch,
                "validation_dice": round(score, 4),
                "labels_version": labels_version["name"],
                "labels_version_id": labels_version["dvid"],
                "labeled_cases": len(names),
                "resumed_from": resumed_from["name"] if resumed_from else None,
                "created_at": _now(),
            }
            model_res.upload("model.pt", buffer.getvalue())
            model_res.upload("meta.json", json.dumps(meta, indent=2).encode())
            published = model_res.commit(
                f"Dice {score:.3f}, labels {labels_version['name'].split(' ')[0]}, epoch {epoch}"
            )["name"]
        yield {
            "epoch": epoch,
            "labels_version": labels_version["name"],
            "labeled_cases": len(names),
            "train_loss": float(np.mean(losses)),
            "validation_dice": score,
            "published_model_version": published,
            "time": _now(),
        }


# Slices past the edge of the brain hold no tissue (none of the 50 in the LGG set
# has tumor), yet they are what an uncertain model is least sure about. They
# would crowd out real cases, so they are never suggested.
BLANK_SCAN_MAX = 30


class Suggester:
    """
    Keeps the review queue topped up from a candidate pool. The pool arrives on
    one input; every row on the other input means the trainer finished an epoch
    and is the moment to check whether a new round is due. Cases a previous run
    suggested and nobody has labeled yet stay in the queue, so stopping and
    re-running the workflow never takes work away from a reviewer.
    """

    def __init__(
        self,
        scans_name: str,
        labels_name: str,
        queue_name: str,
        model_name: str,
        batch_size: int,
        refill_below: int,
        pool_sample: int,
        max_rounds: int,
        ranking: str,
    ):
        if ranking not in ("uncertainty", "random"):
            raise ValueError(f"Unknown ranking '{ranking}'; use 'uncertainty' or 'random'.")
        self.scans_name, self.model_name = scans_name, model_name
        self.labels_res, self.queue_res = dataset(labels_name), dataset(queue_name)
        self.batch_size, self.refill_below = batch_size, refill_below
        self.pool_sample, self.max_rounds, self.ranking = pool_sample, max_rounds, ranking
        self.pool: List[str] = []
        self.scans: Optional[Dict[str, np.ndarray]] = None
        self.model_res = None
        self.rounds = 0
        self.rng = random.Random(0)
        self.pending: Dict[str, dict] = {}
        self.carried: List[dict] = []
        latest = self.queue_res.latest_version()
        if latest is not None:
            items = json.loads(self.queue_res.read_file(latest["name"], "queue.json"))["items"]
            self.pending = {item["case"]: item for item in items}
            self.rounds = max([item["round"] for item in items] + [0])
            self.carried = [{**item, "queue_version": latest["name"]} for item in items]

    def reconfigure(self, model_name: str, batch_size: int, refill_below: int, pool_sample: int, max_rounds: int, ranking: str) -> None:
        """Applies settings changed while the run goes on; the pool and the open suggestions stay."""
        if ranking not in ("uncertainty", "random"):
            raise ValueError(f"Unknown ranking '{ranking}'; use 'uncertainty' or 'random'.")
        if model_name != self.model_name:
            self.model_name, self.model_res = model_name, None
        self.batch_size, self.refill_below = batch_size, refill_below
        self.pool_sample, self.max_rounds, self.ranking = pool_sample, max_rounds, ranking

    def add_to_pool(self, case: str) -> None:
        self.pool.append(case)

    def _labeled(self) -> set:
        return {p.split("/")[-1][:-4] for p in self.labels_res.latest_file_paths() if p.startswith("masks/")}

    def tick(self) -> Iterator[Row]:
        """Publishes a round if the queue is running low and a model exists."""
        if self.carried:
            # Re-emit what a previous run left open, so this run's reviewer waits on it too.
            labeled = self._labeled()
            yield from (item for item in self.carried if item["case"] not in labeled)
            self.carried = []
        if not self.pool or self.rounds >= self.max_rounds:
            return
        labeled = self._labeled()
        self.pending = {c: item for c, item in self.pending.items() if c not in labeled}
        if len(self.pending) >= self.refill_below:
            return
        if self.model_res is None:
            try:
                self.model_res = model(self.model_name)
            except ValueError:
                return
        version = self.model_res.latest_version()
        if version is None:
            return
        if self.scans is None:
            _, self.scans, _ = load_version(dataset(self.scans_name), "scans")
        candidates = [
            c
            for c in self.pool
            if c in self.scans and self.scans[c].max() >= BLANK_SCAN_MAX and c not in labeled and c not in self.pending
        ]
        if not candidates:
            return
        candidates = self.rng.sample(candidates, min(self.pool_sample, len(candidates)))
        net = _load_model(self.model_res, version)
        trained_by = _trained_by(self.model_res, version)
        probs = None
        for probs in _predict(net, [self.scans[c] for c in candidates]):
            if probs is None:
                yield None
        p = np.clip(probs, 1e-6, 1 - 1e-6)
        entropy = -(p * np.log(p) + (1 - p) * np.log(1 - p)).mean(axis=(1, 2)) / math.log(2)
        order = np.argsort(-entropy) if self.ranking == "uncertainty" else self.rng.sample(
            range(len(candidates)), len(candidates)
        )

        self.rounds += 1
        new_items = []
        for index in list(order)[: self.batch_size]:
            case = candidates[index]
            self.queue_res.upload(f"items/{case}.png", png_bytes((probs[index] > 0.5) * 255))
            new_items.append(
                {
                    "case": case,
                    "uncertainty": round(float(entropy[index]), 4),
                    "round": self.rounds,
                    "suggested_by": version["name"],
                    "suggested_by_id": trained_by,
                }
            )
        self.pending.update({item["case"]: item for item in new_items})
        # The queue always lists every unlabeled suggestion, oldest first, so a
        # reviewer sees what is still open whichever round produced it.
        queue = {"created_at": _now(), "ranking": self.ranking, "items": list(self.pending.values())}
        self.queue_res.upload("queue.json", json.dumps(queue, indent=2).encode())
        queue_version = self.queue_res.commit(
            f"round {self.rounds}, {self.ranking}, from model {version['name'].split(' ')[0]}"
        )
        for item in new_items:
            yield {**item, "queue_version": queue_version["name"]}

    def drain(self) -> Iterator[Row]:
        """After training stops, keeps refilling from the last model until the rounds run out."""
        while self.pool and self.rounds < self.max_rounds:
            if not set(self.pool) - self._labeled():
                return
            produced = False
            for row in self.tick():
                produced = produced or row is not None
                yield row
            if not produced:
                yield from _wait(5)


def submit_label(
    labels_res,
    model_res,
    case: str,
    mask: np.ndarray,
    suggested: np.ndarray,
    suggestion: Dict[str, object],
    seconds: float,
    annotator: str,
) -> Dict[str, object]:
    """Commits one label as its own version, with the history that produced it."""
    newest = model_res.latest_version()
    provenance = {
        "case": case,
        "round": suggestion["round"],
        "suggested_by": suggestion["suggested_by"],
        "suggested_by_id": suggestion["suggested_by_id"],
        "newest_model_at_submit": newest["name"],
        "newest_model_id_at_submit": newest["mvid"],
        "versions_behind": newest["mvid"] - suggestion["suggested_by_id"],
        "uncertainty": suggestion["uncertainty"],
        "dice_suggested_vs_final": round(dice(suggested, mask), 4),
        "pixels_changed": int(((suggested > 127) != (mask > 127)).sum()),
        "seconds": round(seconds, 1),
        "annotator": annotator,
        "submitted_at": _now(),
    }
    labels_res.upload(f"masks/{case}.png", png_bytes(mask))
    # The suggestion travels with the label, so a record shows what the model
    # proposed next to what the person kept, whatever the queue holds later.
    labels_res.upload(f"suggestions/{case}.png", png_bytes(suggested))
    labels_res.upload(f"provenance/{case}.json", json.dumps(provenance, indent=2).encode())
    version = labels_res.commit(f"label {case}, suggested by {suggestion['suggested_by'].split(' ')[0]}")
    return {**provenance, "labels_version": version["name"]}


def review(
    suggestion: Dict[str, object],
    labels_name: str,
    queue_name: str,
    truth_name: str,
    model_name: str,
    annotator: str,
    anchoring: float,
    seconds_per_case: float,
    time_scale: float,
    _truth_cache: Dict[str, Dict[str, np.ndarray]] = {},
) -> Iterator[Row]:
    """
    Waits until the suggested case is labeled and emits its label row.

    With annotator "simulated" it labels the case itself: it fixes the
    suggestion toward the truth mask but leaves a fraction `anchoring` of the
    suggestion's wrong pixels in place, and takes longer the more it changes.
    Otherwise a person labels it from the Review panel.
    """
    case = suggestion["case"]
    labels_res, model_res = dataset(labels_name), model(model_name)

    if annotator == "simulated":
        if truth_name not in _truth_cache:
            _truth_cache[truth_name] = load_version(dataset(truth_name), "masks")[1]
        queue_res = dataset(queue_name)
        suggested = read_png(queue_res.read_file(suggestion["queue_version"], f"items/{case}.png"))
        target = _truth_cache[truth_name][case]
        wrong = (suggested > 127) != (target > 127)
        rng = np.random.default_rng(zlib.crc32(case.encode()))
        left = wrong & (rng.random(target.shape) < anchoring)
        mask = np.where(left, suggested, target)
        changed = int(((suggested > 127) != (mask > 127)).sum())
        seconds = seconds_per_case * (0.4 + 0.6 * min(1.0, changed / 400))
        yield from _wait(seconds * time_scale)
        yield submit_label(labels_res, model_res, case, mask, suggested, suggestion, seconds, "simulated")
        return

    while True:
        if f"provenance/{case}.json" in set(labels_res.latest_file_paths()):
            version = labels_res.latest_version()
            provenance = json.loads(labels_res.read_file(version["name"], f"provenance/{case}.json"))
            yield {**provenance, "labels_version": version["name"]}
            return
        yield from _wait(3)
