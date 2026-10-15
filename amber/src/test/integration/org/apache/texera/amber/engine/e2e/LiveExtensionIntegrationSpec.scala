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

package org.apache.texera.amber.engine.e2e

import com.twitter.util.{Await, Duration, Promise}
import org.apache.pekko.actor.{ActorSystem, Props}
import org.apache.pekko.testkit.{ImplicitSender, TestKit}
import org.apache.texera.amber.clustering.SingleNodeListener
import org.apache.texera.amber.core.workflow.{PortIdentity, WorkflowSettings}
import org.apache.texera.amber.engine.architecture.coordinator.{
  CoordinatorConfig,
  ExecutionStateUpdate,
  PlanExtension,
  PlanExtensionStore
}
import org.apache.texera.amber.engine.architecture.rpc.controlcommands.{
  EmptyRequest,
  ExtendWorkflowRequest
}
import org.apache.texera.amber.engine.architecture.rpc.controlreturns.WorkflowAggregatedState.COMPLETED
import org.apache.texera.amber.engine.common.AmberRuntime
import org.apache.texera.amber.engine.common.client.AmberClient
import org.apache.texera.amber.engine.e2e.TestUtils._
import org.apache.texera.amber.operator.TestOperators
import org.apache.texera.amber.tags.IntegrationTest
import org.apache.texera.common.compiler.model.LogicalLink
import org.scalatest.BeforeAndAfterAll
import org.scalatest.flatspec.AnyFlatSpecLike

/**
  * Operators added to a running execution start inside it and read the running operators'
  * output as it is produced.
  */
@IntegrationTest
class LiveExtensionIntegrationSpec
    extends TestKit(ActorSystem("LiveExtensionIntegrationSpec", AmberRuntime.pekkoConfig))
    with ImplicitSender
    with AnyFlatSpecLike
    with BeforeAndAfterAll {

  private val specId = 7
  private val rows = 20

  override def beforeAll(): Unit = {
    system.actorOf(Props[SingleNodeListener](), "cluster-info")
    Class.forName("org.postgresql.Driver")
    initiateTexeraDBForTestCases()
    setUpWorkflowExecutionData(specId)
  }

  override def afterAll(): Unit = {
    cleanupWorkflowExecutionData(specId)
    TestKit.shutdownActorSystem(system)
  }

  "Engine" should "start operators added while the workflow runs, and give them every row of the running operator" in {
    val source = TestOperators.slowRegionSourceOpDesc(numTuple = rows, delaySeconds = 0.3)
    val added = TestOperators.keywordSearchOpDesc("Region", "Asia")
    val live = WorkflowSettings(liveEditing = true)
    val running = buildWorkflow(List(source), List.empty, workflowContext(specId, live))
    val edited = buildWorkflow(
      List(source, added),
      List(
        LogicalLink(source.operatorIdentifier, PortIdentity(), added.operatorIdentifier, PortIdentity())
      ),
      workflowContext(specId, live)
    )

    val client = new AmberClient(
      system,
      running.context,
      running.physicalPlan,
      CoordinatorConfig.default,
      _ => {}
    )
    registerResultUriPersistence(client, running.context.executionId)
    val completion = Promise[Unit]()
    client.registerCallback[ExecutionStateUpdate](evt => if (evt.state == COMPLETED) completion.setDone())
    val commandTimeout = Duration.fromSeconds(60)
    Await.result(client.coordinatorInterface.startWorkflow(EmptyRequest(), ()), commandTimeout)

    // Let the source emit part of its rows before the branch arrives.
    Thread.sleep(3000)
    val extensionId = PlanExtensionStore.put(
      PlanExtension(edited.physicalPlan, edited.context.workflowSettings.outputPortsNeedingStorage)
    )
    Await.result(
      client.coordinatorInterface.extendWorkflow(ExtendWorkflowRequest(extensionId), ()),
      commandTimeout
    )
    Await.result(completion, Duration.fromMinutes(2))

    val results = readMaterializedResults(
      running.context.executionId,
      List(source.operatorIdentifier, added.operatorIdentifier),
      _.get().toList
    )
    client.shutdown()
    assert(results(source.operatorIdentifier).size == rows)
    assert(results(added.operatorIdentifier).size == rows)
  }
}
