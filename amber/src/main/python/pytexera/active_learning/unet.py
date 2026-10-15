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

import math

import torch
from torch import nn

# Tumor covers about 1% of a slice. Starting the output at that prior makes an
# untrained or barely trained model say "no tumor" rather than "all tumor",
# so the first suggestions a person sees are not the whole scan.
TUMOR_PRIOR = 0.01


def _block(in_channels: int, out_channels: int) -> nn.Sequential:
    return nn.Sequential(
        nn.Conv2d(in_channels, out_channels, 3, padding=1),
        nn.BatchNorm2d(out_channels),
        nn.ReLU(inplace=True),
        nn.Conv2d(out_channels, out_channels, 3, padding=1),
        nn.BatchNorm2d(out_channels),
        nn.ReLU(inplace=True),
    )


class UNet(nn.Module):
    """A small 2D U-Net: one input channel, one logit channel, three down-steps."""

    def __init__(self, width: int = 16):
        super().__init__()
        w = width
        self.enc1, self.enc2, self.enc3 = _block(1, w), _block(w, 2 * w), _block(2 * w, 4 * w)
        self.bottom = _block(4 * w, 8 * w)
        self.pool = nn.MaxPool2d(2)
        self.up3 = nn.ConvTranspose2d(8 * w, 4 * w, 2, stride=2)
        self.dec3 = _block(8 * w, 4 * w)
        self.up2 = nn.ConvTranspose2d(4 * w, 2 * w, 2, stride=2)
        self.dec2 = _block(4 * w, 2 * w)
        self.up1 = nn.ConvTranspose2d(2 * w, w, 2, stride=2)
        self.dec1 = _block(2 * w, w)
        self.head = nn.Conv2d(w, 1, 1)
        nn.init.constant_(self.head.bias, math.log(TUMOR_PRIOR / (1 - TUMOR_PRIOR)))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        e1 = self.enc1(x)
        e2 = self.enc2(self.pool(e1))
        e3 = self.enc3(self.pool(e2))
        b = self.bottom(self.pool(e3))
        d3 = self.dec3(torch.cat([self.up3(b), e3], 1))
        d2 = self.dec2(torch.cat([self.up2(d3), e2], 1))
        d1 = self.dec1(torch.cat([self.up1(d2), e1], 1))
        return self.head(d1)


def dice_loss(logits: torch.Tensor, target: torch.Tensor, eps: float = 1.0) -> torch.Tensor:
    probs = torch.sigmoid(logits)
    inter = (probs * target).sum(dim=(1, 2, 3))
    total = probs.sum(dim=(1, 2, 3)) + target.sum(dim=(1, 2, 3))
    return (1 - (2 * inter + eps) / (total + eps)).mean()


def train_epochs(net: UNet, optimizer: torch.optim.Optimizer, images: torch.Tensor, masks: torch.Tensor,
                 epochs: int, batch_size: int, rng) -> None:
    """
    Trains `net` in place for `epochs` passes over uint8 `images` and 0/255 `masks`
    (N x 128 x 128), on whatever device `net` is on: dice + cross-entropy loss, random
    horizontal flips, a fresh shuffle every epoch.
    """
    device = next(net.parameters()).device
    x_all = images.float().div(255).unsqueeze(1)
    y_all = masks.float().div(255).round().unsqueeze(1)
    net.train()
    for _ in range(epochs):
        order = list(range(len(x_all)))
        rng.shuffle(order)
        for start in range(0, len(order), batch_size):
            index = order[start:start + batch_size]
            x, y = x_all[index].to(device), y_all[index].to(device)
            if rng.random() < 0.5:
                x, y = x.flip(-1), y.flip(-1)
            logits = net(x)
            loss = dice_loss(logits, y) + nn.functional.binary_cross_entropy_with_logits(logits, y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
