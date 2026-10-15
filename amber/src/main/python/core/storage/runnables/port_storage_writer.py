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

import time
from dataclasses import dataclass
from overrides import overrides
from queue import Empty
from typing import Optional

from core.models import Tuple
from core.storage.model.buffered_item_writer import BufferedItemWriter
from core.storage.storage_config import StorageConfig
from core.util import StoppableQueueBlockingRunnable, IQueue
from core.util.customized_queue.queue_base import QueueElement


@dataclass
class PortStorageWriterElement(QueueElement):
    data_tuple: Tuple


class PortStorageWriter(StoppableQueueBlockingRunnable):
    """
    Writes a port's tuples to storage. A partly filled buffer is flushed once
    it has waited the commit interval, so a slow producer's rows reach readers
    that follow the port live.
    """

    def __init__(
        self,
        buffered_item_writer: BufferedItemWriter,
        queue: IQueue,
        commit_interval_seconds: Optional[float] = None,
    ):
        super().__init__(name=self.__class__.__name__, queue=queue)
        self.buffered_item_writer: BufferedItemWriter = buffered_item_writer
        self._commit_interval_seconds = commit_interval_seconds
        self._oldest_unflushed_at: Optional[float] = None

    @property
    def commit_interval_seconds(self) -> float:
        if self._commit_interval_seconds is None:
            self._commit_interval_seconds = (
                StorageConfig.ICEBERG_TABLE_COMMIT_INTERVAL_MS / 1000
            )
        return self._commit_interval_seconds

    @overrides
    def interruptible_get(self):
        while self._oldest_unflushed_at is not None:
            wait = self._oldest_unflushed_at + self.commit_interval_seconds
            try:
                return self._check_stop(
                    self._internal_queue.get(timeout=max(0.0, wait - time.time()))
                )
            except Empty:
                self.buffered_item_writer.flush()
                self._oldest_unflushed_at = None
        return super().interruptible_get()

    @staticmethod
    def _check_stop(entry):
        if entry == StoppableQueueBlockingRunnable.RUNNABLE_STOP:
            raise StoppableQueueBlockingRunnable.InterruptRunnable
        return entry

    @overrides
    def receive(self, next_entry: QueueElement) -> None:
        if isinstance(next_entry, PortStorageWriterElement):
            self.buffered_item_writer.put_one(next_entry.data_tuple)
            if self._oldest_unflushed_at is None:
                self._oldest_unflushed_at = time.time()
        else:
            raise TypeError(f"Unexpected entry {next_entry}")

    @overrides
    def pre_start(self) -> None:
        self.buffered_item_writer.open()

    @overrides
    def post_stop(self) -> None:
        self.buffered_item_writer.close()
