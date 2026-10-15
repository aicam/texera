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

import org.apache.texera.amber.core.virtualidentity.ActorVirtualIdentity
import org.apache.texera.amber.core.workflow.GlobalPortIdentity
import org.apache.texera.amber.engine.architecture.coordinator.execution.WorkflowExecution

import java.net.URI
import scala.collection.mutable

/**
  * Inputs of operators added to a running execution read the materialized output port of an
  * operator that may still be running. A reader assigned while its producer runs follows the
  * storage live, and must be told when the producer finishes so it can end its channel.
  */
class LiveInputTracker(workflowExecution: WorkflowExecution) extends Serializable {

  // base storage URI -> the output port that writes it
  private val producers = mutable.HashMap[URI, GlobalPortIdentity]()
  // base storage URI -> workers whose readers follow it live
  private val liveReaders = mutable.HashMap[URI, mutable.Set[ActorVirtualIdentity]]()

  def attach(storageUri: URI, producer: GlobalPortIdentity): Unit =
    producers(storageUri) = producer

  /**
    * Whether `worker`, assigned now to read `storageUri`, must follow it live. A live reader is
    * remembered, so it is told when the producer finishes.
    */
  def assignReader(storageUri: URI, worker: ActorVirtualIdentity): Boolean =
    producers.get(storageUri) match {
      case Some(producer) if !isCompleted(producer) =>
        liveReaders.getOrElseUpdate(storageUri, mutable.Set()) += worker
        true
      case _ => false
    }

  /**
    * The producer port finished: the storage URIs it wrote, each with the workers following it.
    */
  def producerCompleted(producer: GlobalPortIdentity): Map[URI, Set[ActorVirtualIdentity]] =
    producers.collect {
      case (uri, port) if port == producer => uri -> liveReaders.remove(uri).map(_.toSet)
    }.collect { case (uri, Some(readers)) => uri -> readers }.toMap

  private def isCompleted(producer: GlobalPortIdentity): Boolean =
    workflowExecution
      .getLatestOperatorExecutionOption(producer.opId)
      .exists(_.isOutputPortCompleted(producer.portId))
}
