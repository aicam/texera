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

package org.apache.texera.amber.engine.architecture.coordinator.promisehandlers

import com.twitter.util.Future
import org.apache.texera.amber.engine.architecture.coordinator.{
  CoordinatorAsyncRPCHandlerInitializer,
  PlanExtensionStore
}
import org.apache.texera.amber.engine.architecture.rpc.controlcommands.{
  AsyncRPCContext,
  ExtendWorkflowRequest
}
import org.apache.texera.amber.engine.architecture.rpc.controlreturns.EmptyReturn

/** Add the operators of an edited plan to this running execution and start them right away.
  *
  * possible sender: client
  */
trait ExtendWorkflowHandler {
  this: CoordinatorAsyncRPCHandlerInitializer =>

  override def extendWorkflow(
      msg: ExtendWorkflowRequest,
      ctx: AsyncRPCContext
  ): Future[EmptyReturn] = {
    val extension = PlanExtensionStore
      .take(msg.extensionId)
      .getOrElse(throw new IllegalStateException(s"No plan extension ${msg.extensionId}"))
    val (schedule, attachments) = cp.workflowScheduler.extend(
      extension.physicalPlan,
      extension.outputPortsNeedingStorage,
      cp.workflowExecutionManager.allScheduledRegions
    )
    cp.workflowExecutionManager.extend(schedule, attachments)
    cp.workflowExecutionManager.advanceRegionExecutions(cp.actorService).map(_ => EmptyReturn())
  }
}
