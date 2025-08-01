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

import threading
import typing
from collections import OrderedDict
from itertools import chain
from queue import Queue
from threading import Thread
from typing import Iterable, Iterator

from loguru import logger
from pyarrow import Table

from core.architecture.packaging.input_manager import WorkerPort, Channel
from core.architecture.sendsemantics.broad_cast_partitioner import (
    BroadcastPartitioner,
)
from core.architecture.sendsemantics.hash_based_shuffle_partitioner import (
    HashBasedShufflePartitioner,
)
from core.architecture.sendsemantics.one_to_one_partitioner import OneToOnePartitioner
from core.architecture.sendsemantics.partitioner import Partitioner
from core.architecture.sendsemantics.range_based_shuffle_partitioner import (
    RangeBasedShufflePartitioner,
)
from core.architecture.sendsemantics.round_robin_partitioner import (
    RoundRobinPartitioner,
)
from core.models import Tuple, Schema, StateFrame
from core.models.state import State
from core.models.payload import DataPayload, DataFrame
from core.storage.document_factory import DocumentFactory
from core.storage.runnables.port_storage_writer import (
    PortStorageWriter,
    PortStorageWriterElement,
)
from core.util import get_one_of
from core.util.virtual_identity import get_worker_index
from proto.edu.uci.ics.amber.core import (
    ActorVirtualIdentity,
    PhysicalLink,
    PortIdentity,
    ChannelIdentity,
)
from proto.edu.uci.ics.amber.engine.architecture.rpc import EmbeddedControlMessage
from proto.edu.uci.ics.amber.engine.architecture.sendsemantics import (
    HashBasedShufflePartitioning,
    OneToOnePartitioning,
    Partitioning,
    RoundRobinPartitioning,
    RangeBasedShufflePartitioning,
    BroadcastPartitioning,
)
from typing import Union


class OutputManager:
    def __init__(self, worker_id: str):
        self.worker_id = worker_id
        self._partitioners: OrderedDict[PhysicalLink, Partitioning] = OrderedDict()
        self._partitioning_to_partitioner: dict[
            type(Partitioning), type(Partitioner)
        ] = {
            OneToOnePartitioning: OneToOnePartitioner,
            RoundRobinPartitioning: RoundRobinPartitioner,
            HashBasedShufflePartitioning: HashBasedShufflePartitioner,
            RangeBasedShufflePartitioning: RangeBasedShufflePartitioner,
            BroadcastPartitioning: BroadcastPartitioner,
        }
        self._ports: typing.Dict[PortIdentity, WorkerPort] = dict()
        self._channels: typing.Dict[ChannelIdentity, Channel] = dict()
        self._port_storage_writers: typing.Dict[
            PortIdentity, typing.Tuple[Queue, PortStorageWriter, Thread]
        ] = dict()

    def is_missing_output_ports(self):
        """
        This method is only used for ensuring correct region execution.
        Some operators may have input port dependency relationships, for
        which we currently use a two-phase region execution scheme.
        (See `RegionExecutionCoordinator.scala` for details.)
        This logic will only be executed when the worker is part of an
        `executingDependeePortPhase` region-execution phase.
        We currently assume that in this phase the operator (worker) will
        not output any data, hence no output ports.
        However we still need to keep this worker open for the next
        `executingNonDependeePortPhase` phase.
        :return: Whether this worker currently does not have any output port.
        """
        return not self._ports

    def add_output_port(
        self,
        port_id: PortIdentity,
        schema: Schema,
        storage_uri: typing.Optional[str] = None,
    ) -> None:
        if port_id.id is None:
            port_id.id = 0
        if port_id.internal is None:
            port_id.internal = False

        if storage_uri is not None:
            self.set_up_port_storage_writer(port_id, storage_uri)

        # each port can only be added and initialized once.
        if port_id not in self._ports:
            self._ports[port_id] = WorkerPort(schema)

    def set_up_port_storage_writer(self, port_id: PortIdentity, storage_uri: str):
        """
        Create a separate thread for saving output tuples of a port
        to storage in batch.
        """
        document, _ = DocumentFactory.open_document(storage_uri)
        buffered_item_writer = document.writer(str(get_worker_index(self.worker_id)))
        writer_queue = Queue()
        port_storage_writer = PortStorageWriter(
            buffered_item_writer=buffered_item_writer, queue=writer_queue
        )
        writer_thread = threading.Thread(
            target=port_storage_writer.run,
            daemon=True,
            name=f"port_storage_writer_thread_{port_id}",
        )
        writer_thread.start()
        self._port_storage_writers[port_id] = (
            writer_queue,
            port_storage_writer,
            writer_thread,
        )

    def get_port(self, port_id=None) -> WorkerPort:
        return list(self._ports.values())[0]

    def get_port_ids(self) -> typing.List[PortIdentity]:
        return list(self._ports.keys())

    def get_output_channel_ids(self) -> typing.List[ChannelIdentity]:
        return self._channels.keys()

    def save_tuple_to_storage_if_needed(self, tuple_: Tuple, port_id=None) -> None:
        """
        Optionally write the tuple to storage if the specified output port
        is determined by the scheduler to need storage. This method is not blocking
        because a separate thread is used to flush the tuple to storage in batch.
        :param tuple_: A tuple produced by the data processor.
        :param port_id: If not specified, the tuple will be written to all
        output ports that need storage.
        :return:
        """
        if port_id is None:
            for writer_queue, _, _ in self._port_storage_writers.values():
                writer_queue.put(PortStorageWriterElement(data_tuple=tuple_))
        elif port_id in self._port_storage_writers.keys():
            self._port_storage_writers[port_id][0].put(
                PortStorageWriterElement(data_tuple=tuple_)
            )

    def close_port_storage_writers(self) -> None:
        """
        Flush the buffers of port storage writers and wait for all the
        writer threads to finish, which indicates the port storage writing
        are finished.
        """
        for _, writer, _ in self._port_storage_writers.values():
            # This non-blocking stop call will let the storage writers
            # flush the remaining buffer
            writer.stop()
        for _, _, writer_thread in self._port_storage_writers.values():
            # This blocking call will wait for all the writer to finish commit
            writer_thread.join()

    def add_partitioning(self, tag: PhysicalLink, partitioning: Partitioning) -> None:
        """
        Add down stream operator and its transfer policy
        :param tag:
        :param partitioning:
        :return:
        """
        the_partitioning = get_one_of(partitioning)
        logger.debug(f"adding {the_partitioning}")
        for channel_id in the_partitioning.channels:
            if channel_id.from_worker_id.name == self.worker_id:
                # Explicitly set is_control to trigger lazy computation.
                # If not set, it may be computed at different times,
                # causing hash inconsistencies.
                channel_id.is_control = False
                self._channels[channel_id] = Channel()
        partitioner = self._partitioning_to_partitioner[type(the_partitioning)]
        self._partitioners[tag] = (
            partitioner(the_partitioning)
            if partitioner != OneToOnePartitioner
            else partitioner(the_partitioning, self.worker_id)
        )

    def tuple_to_batch(
        self, tuple_: Tuple
    ) -> Iterator[typing.Tuple[ActorVirtualIdentity, DataFrame]]:
        return chain(
            *(
                (
                    (receiver, self.tuple_to_frame(tuples))
                    for receiver, tuples in partitioner.add_tuple_to_batch(tuple_)
                )
                for partitioner in self._partitioners.values()
            )
        )

    def emit_ecm(
        self, to: ActorVirtualIdentity, ecm: EmbeddedControlMessage
    ) -> Iterable[Union[DataPayload, EmbeddedControlMessage]]:
        return chain(
            *(
                (
                    (
                        payload
                        if isinstance(payload, EmbeddedControlMessage)
                        else self.tuple_to_frame(payload)
                    )
                    for payload in partitioner.flush(to, ecm)
                )
                for partitioner in self._partitioners.values()
            )
        )

    def emit_state(
        self, state: State
    ) -> Iterable[typing.Tuple[ActorVirtualIdentity, DataPayload]]:
        return chain(
            *(
                (
                    (
                        receiver,
                        (
                            StateFrame(payload)
                            if isinstance(payload, State)
                            else self.tuple_to_frame(payload)
                        ),
                    )
                    for receiver, payload in partitioner.flush_state(state)
                )
                for partitioner in self._partitioners.values()
            )
        )

    def tuple_to_frame(self, tuples: typing.List[Tuple]) -> DataFrame:
        return DataFrame(
            frame=Table.from_pydict(
                {
                    name: [t[name] for t in tuples]
                    for name in self.get_port().get_schema().get_attr_names()
                },
                schema=self.get_port().get_schema().as_arrow_schema(),
            )
        )
