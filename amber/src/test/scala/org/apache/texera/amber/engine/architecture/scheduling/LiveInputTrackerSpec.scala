/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.texera.amber.engine.architecture.scheduling

import org.apache.texera.amber.core.virtualidentity.{
  ActorVirtualIdentity,
  OperatorIdentity,
  PhysicalOpIdentity
}
import org.apache.texera.amber.core.workflow.{GlobalPortIdentity, PortIdentity}
import org.apache.texera.amber.engine.architecture.coordinator.execution.WorkflowExecution
import org.scalatest.flatspec.AnyFlatSpec

import java.net.URI

class LiveInputTrackerSpec extends AnyFlatSpec {
  private val producer =
    GlobalPortIdentity(PhysicalOpIdentity(OperatorIdentity("train"), "main"), PortIdentity())
  private val storage = URI.create("vfs:///wid/1/eid/1/globalportid/train")
  private val reader = ActorVirtualIdentity("Worker:WF1-average-main-0")

  "LiveInputTracker" should "follow a running producer and hand its readers over when it finishes" in {
    val tracker = new LiveInputTracker(WorkflowExecution())
    tracker.attach(storage, producer)

    assert(tracker.assignReader(storage, reader))
    assert(tracker.producerCompleted(producer) == Map(storage -> Set(reader)))
    // Told once: a second completion has nobody left to tell.
    assert(tracker.producerCompleted(producer).isEmpty)
  }

  it should "read storage nobody attached to once, not live" in {
    val tracker = new LiveInputTracker(WorkflowExecution())

    assert(!tracker.assignReader(storage, reader))
    assert(tracker.producerCompleted(producer).isEmpty)
  }
}
