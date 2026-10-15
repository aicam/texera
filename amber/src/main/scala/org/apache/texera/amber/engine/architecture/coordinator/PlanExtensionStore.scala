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

package org.apache.texera.amber.engine.architecture.coordinator

import org.apache.texera.amber.core.workflow.{GlobalPortIdentity, PhysicalPlan}

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
  * An edited plan to merge into a running execution.
  *
  * @param physicalPlan              the whole edited plan, compiled for the running execution
  * @param outputPortsNeedingStorage the ports of the edited plan whose results are kept
  */
case class PlanExtension(
    physicalPlan: PhysicalPlan,
    outputPortsNeedingStorage: Set[GlobalPortIdentity]
)

/**
  * Hands a [[PlanExtension]] from the web service to the coordinator of the same computing unit.
  * A physical plan carries code and functions that do not travel as a control message, so the
  * message (`ExtendWorkflowRequest`) carries only the id it is kept under here.
  */
object PlanExtensionStore {
  private val pending = new ConcurrentHashMap[String, PlanExtension]()

  def put(extension: PlanExtension): String = {
    val id = UUID.randomUUID().toString
    pending.put(id, extension)
    id
  }

  def take(id: String): Option[PlanExtension] = Option(pending.remove(id))
}
