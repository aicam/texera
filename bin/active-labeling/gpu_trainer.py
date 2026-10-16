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
Trains U-Net rounds on a GPU machine for a workflow running elsewhere.

POST /train with a torch-serialized dict of tensors: the model's and optimizer's
state, the round's labeled scans and masks (uint8, N x 128 x 128), and the epochs,
batch size and seed. It trains with the same `train_epochs` the workflow uses on
CPU and answers with the new model and optimizer state. The caller keeps all
state, so a restart of this service loses nothing.

    LD_LIBRARY_PATH=$(cat libpath) .venv/bin/python gpu_trainer.py --host <tailscale ip>

Requests carry the token in ./token as `Authorization: Bearer <token>`.
"""

import argparse
import io
import os
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import torch

from unet import UNet, train_epochs

TOKEN = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "token")).read().strip()
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
GPU = threading.Lock()  # one round at a time on the one GPU


def train(request: dict) -> dict:
    net = UNet().to(DEVICE)
    net.load_state_dict(request["model"])
    optimizer = torch.optim.Adam(net.parameters(), lr=float(request["lr"]))
    if request.get("optimizer"):
        optimizer.load_state_dict(request["optimizer"])
    started = time.time()
    train_epochs(net, optimizer, request["images"], request["masks"], int(request["epochs"]),
                 int(request["batch_size"]), random.Random(int(request["seed"])))
    to_cpu = lambda state: {k: v.cpu() if torch.is_tensor(v) else v for k, v in state.items()}
    optimizer_state = optimizer.state_dict()
    optimizer_state["state"] = {k: to_cpu(v) for k, v in optimizer_state["state"].items()}
    return {"model": to_cpu(net.state_dict()), "optimizer": optimizer_state,
            "seconds": time.time() - started, "device": str(DEVICE)}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.reply(200, b"ok " + str(DEVICE).encode(), "text/plain")

    def do_POST(self):
        if self.path != "/train" or self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self.reply(403, b"forbidden", "text/plain")
        body = self.rfile.read(int(self.headers["Content-Length"]))
        try:
            request = torch.load(io.BytesIO(body), weights_only=True)  # tensors and plain values only
            with GPU:
                result = train(request)
        except Exception as err:  # the caller sees why and can fall back to its CPU
            return self.reply(500, repr(err).encode(), "text/plain")
        buffer = io.BytesIO()
        torch.save(result, buffer)
        self.reply(200, buffer.getvalue(), "application/octet-stream")

    def reply(self, status, body, kind):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(time.strftime("%X"), self.address_string(), fmt % args, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="address to listen on, e.g. the Tailscale IP")
    parser.add_argument("--port", type=int, default=8790)
    args = parser.parse_args()
    print(f"training on {DEVICE} at http://{args.host}:{args.port}", flush=True)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
