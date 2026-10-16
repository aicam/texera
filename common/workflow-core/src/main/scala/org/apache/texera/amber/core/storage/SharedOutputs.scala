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

package org.apache.texera.amber.core.storage

import org.apache.texera.amber.core.storage.model.VirtualDocument
import org.apache.texera.amber.core.tuple.{Schema, Tuple}
import org.apache.texera.dao.SqlServer
import org.apache.texera.dao.jooq.generated.enums.PrivilegeEnum
import org.apache.texera.dao.jooq.generated.tables.OperatorPortExecutions.OPERATOR_PORT_EXECUTIONS
import org.apache.texera.dao.jooq.generated.tables.SharedOutput.SHARED_OUTPUT
import org.apache.texera.dao.jooq.generated.tables.SharedOutputUserAccess.SHARED_OUTPUT_USER_ACCESS
import org.apache.texera.dao.jooq.generated.tables.User.USER
import org.apache.texera.dao.jooq.generated.tables.WorkflowExecutions.WORKFLOW_EXECUTIONS
import org.apache.texera.dao.jooq.generated.tables.WorkflowVersion.WORKFLOW_VERSION
import org.jooq.DSLContext

import java.net.URI
import scala.jdk.CollectionConverters._

/**
  * An operator output port published under a name, read in place by other workflows.
  *
  * @param reference how a reader names it: `<owner email>/<name>`
  */
case class SharedOutput(
    soid: Int,
    reference: String,
    ownerUid: Int,
    wid: Int,
    operatorId: String,
    portId: Int
)

/**
  * The newest result of a shared output.
  *
  * @param producing whether the execution that writes it may still add rows
  */
case class SharedOutputResult(uri: URI, executionId: Long, producing: Boolean)

object SharedOutputs {

  // workflow_executions.status of an execution that has not finished: ready, running, paused
  private val UnfinishedStatus: Set[Short] = Set(0, 1, 2)

  private def context: DSLContext = SqlServer.getInstance().createDSLContext()

  def reference(ownerEmail: String, name: String): String = s"$ownerEmail/$name"

  /**
    * The shared output a reference names, `<owner email>/<name>`.
    */
  def find(reference: String): Option[SharedOutput] = {
    val split = reference.lastIndexOf('/')
    if (split <= 0) return None
    val (ownerEmail, name) = (reference.take(split).trim, reference.drop(split + 1).trim)
    Option(
      context
        .select(SHARED_OUTPUT.fields: _*)
        .from(SHARED_OUTPUT)
        .join(USER)
        .on(USER.UID.eq(SHARED_OUTPUT.OWNER_UID))
        .where(USER.EMAIL.eq(ownerEmail).and(SHARED_OUTPUT.NAME.eq(name)))
        .fetchOne()
    ).map(row =>
      SharedOutput(
        row.get(SHARED_OUTPUT.SOID),
        SharedOutputs.reference(ownerEmail, name),
        row.get(SHARED_OUTPUT.OWNER_UID),
        row.get(SHARED_OUTPUT.WID),
        row.get(SHARED_OUTPUT.OPERATOR_ID),
        row.get(SHARED_OUTPUT.PORT_ID)
      )
    )
  }

  def canRead(shared: SharedOutput, uid: Int): Boolean =
    shared.ownerUid == uid || context.fetchExists(
      SHARED_OUTPUT_USER_ACCESS,
      SHARED_OUTPUT_USER_ACCESS.SOID
        .eq(shared.soid)
        .and(SHARED_OUTPUT_USER_ACCESS.UID.eq(uid))
        .and(SHARED_OUTPUT_USER_ACCESS.PRIVILEGE.in(PrivilegeEnum.READ, PrivilegeEnum.WRITE))
    )

  /**
    * The result of the newest execution of the shared output's workflow that has one.
    */
  def latestResult(shared: SharedOutput): Option[SharedOutputResult] =
    resultsOf(shared.wid, shared.operatorId, shared.portId).headOption.map {
      case (eid, uri) => SharedOutputResult(uri, eid, isProducing(eid))
    }

  /**
    * The schema of the shared output's newest result.
    */
  def schemaOf(shared: SharedOutput): Option[Schema] =
    latestResult(shared).flatMap(result => DocumentFactory.openDocument(result.uri)._2)

  def open(result: SharedOutputResult): VirtualDocument[Tuple] =
    DocumentFactory.openDocument(result.uri)._1.asInstanceOf[VirtualDocument[Tuple]]

  def isProducing(executionId: Long): Boolean =
    Option(
      context
        .select(WORKFLOW_EXECUTIONS.STATUS)
        .from(WORKFLOW_EXECUTIONS)
        .where(WORKFLOW_EXECUTIONS.EID.eq(executionId.toInt))
        .fetchOne(WORKFLOW_EXECUTIONS.STATUS)
    ).exists(status => UnfinishedStatus.contains(status.shortValue()))

  /**
    * Whether `resultUri`, a result of workflow `wid`, is the output of a port shared from it.
    */
  def isSharedResult(wid: Int, resultUri: URI): Boolean = {
    val ports = sharedPorts(wid)
    ports.nonEmpty && portOf(resultUri).exists(ports.contains)
  }

  /**
    * The results of shared ports that executions of `wid` older than `executionId` still keep.
    */
  def keptResultsBefore(wid: Int, executionId: Long): List[(Long, URI)] =
    sharedPorts(wid).toList.flatMap {
      case (operatorId, portId) =>
        resultsOf(wid, operatorId, portId).filter { case (eid, _) => eid < executionId }
    }

  private def sharedPorts(wid: Int): Set[(String, Int)] =
    context
      .select(SHARED_OUTPUT.OPERATOR_ID, SHARED_OUTPUT.PORT_ID)
      .from(SHARED_OUTPUT)
      .where(SHARED_OUTPUT.WID.eq(wid))
      .fetch()
      .asScala
      .map(row => (row.value1(), row.value2().intValue()))
      .toSet

  private def portOf(resultUri: URI): Option[(String, Int)] = {
    val components = VFSURIFactory.decodeURI(resultUri)
    components.globalPortId
      .filter(port => !port.portId.internal && components.resourceType == VFSResourceType.RESULT)
      .map(port => (port.opId.logicalOpId.id, port.portId.id))
  }

  /** The port's results in executions of `wid`, newest first. */
  private def resultsOf(wid: Int, operatorId: String, portId: Int): List[(Long, URI)] =
    context
      .select(OPERATOR_PORT_EXECUTIONS.WORKFLOW_EXECUTION_ID, OPERATOR_PORT_EXECUTIONS.RESULT_URI)
      .from(OPERATOR_PORT_EXECUTIONS)
      .join(WORKFLOW_EXECUTIONS)
      .on(WORKFLOW_EXECUTIONS.EID.eq(OPERATOR_PORT_EXECUTIONS.WORKFLOW_EXECUTION_ID))
      .join(WORKFLOW_VERSION)
      .on(WORKFLOW_VERSION.VID.eq(WORKFLOW_EXECUTIONS.VID))
      .where(WORKFLOW_VERSION.WID.eq(wid).and(OPERATOR_PORT_EXECUTIONS.RESULT_URI.isNotNull))
      .orderBy(OPERATOR_PORT_EXECUTIONS.WORKFLOW_EXECUTION_ID.desc())
      .fetch()
      .asScala
      .map(row => (row.value1().longValue(), URI.create(row.value2())))
      .filter { case (_, uri) => portOf(uri).contains((operatorId, portId)) }
      .toList
}
