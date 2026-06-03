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

package org.apache.texera.web.service

import com.typesafe.scalalogging.LazyLogging
import org.apache.texera.amber.core.virtualidentity.{ExecutionIdentity, WorkflowIdentity}
import org.apache.texera.amber.engine.common.Utils
import org.apache.texera.dao.SqlServer
import org.jooq.exception.DataAccessException
import org.apache.texera.dao.jooq.generated.tables.daos.WorkflowExecutionsDao
import org.apache.texera.dao.jooq.generated.tables.pojos.WorkflowExecutions
import org.apache.texera.web.resource.dashboard.user.workflow.WorkflowExecutionsResource
import org.apache.texera.web.resource.dashboard.user.workflow.WorkflowVersionResource._

import java.sql.Timestamp

/**
  * This global object handles inserting a new entry to the DB to store metadata information about every workflow execution
  * It also updates the entry if an execution status is updated
  */
object ExecutionsMetadataPersistService extends LazyLogging {
  private def context =
    SqlServer
      .getInstance()
      .createDSLContext()
  private def workflowExecutionsDao =
    new WorkflowExecutionsDao(
      context.configuration
    )

  /**
    * This method inserts a new entry of a workflow execution in the database and returns the generated eId
    *
    * @param workflowId the given workflow
    * @param uid        user id that initiated the execution
    * @return generated execution ID
    */

  def insertNewExecution(
      workflowId: WorkflowIdentity,
      uid: Integer,
      executionName: String,
      environmentVersion: String,
      computingUnitId: Integer,
      userJwtToken: Option[String] = None
  ): ExecutionIdentity = {
    if (RemoteExecutionMetadata.enabled) {
      return RemoteExecutionMetadata.createExecution(
        workflowId.id,
        uid,
        executionName,
        environmentVersion,
        computingUnitId,
        userJwtToken
      )
    }
    // first retrieve the latest version of this workflow
    val vid = getLatestVersion(workflowId.id.toInt)
    val newExecution = new WorkflowExecutions()
    if (executionName != "") {
      newExecution.setName(executionName)
    }
    newExecution.setVid(vid)
    newExecution.setUid(uid)
    newExecution.setStartingTime(new Timestamp(System.currentTimeMillis()))
    newExecution.setEnvironmentVersion(environmentVersion)

    // Set computing unit ID if provided
    newExecution.setCuid(computingUnitId)

    try {
      workflowExecutionsDao.insert(newExecution)
    } catch {
      // A NOT NULL column (e.g. uid, vid, cuid) was null. Postgres reports this
      // as SQLState 23502; surface a readable message instead of the raw
      // jOOQ/JDBC stack trace, while preserving the original as the cause.
      case e: DataAccessException if e.sqlState() == "23502" =>
        throw new IllegalArgumentException(
          "Cannot persist workflow execution: a required field (uid, vid, or cuid) was null.",
          e
        )
    }
    ExecutionIdentity(newExecution.getEid.longValue())
  }

  /**
    * The single chokepoint for persisting an execution's status. Replaces the old POJO-mutator path
    * (which could not cross HTTP and therefore silently no-op'd on the Postgres-free computing unit).
    *
    * Both modes converge on the same conditional, terminal-monotonic UPDATE
    * (WorkflowExecutionsResource.updateExecutionStatus): remote routes it over HTTP to the dashboard
    * service; local runs it directly. Terminal writes (COMPLETED/FAILED/KILLED) are the ones whose
    * loss strands a workflow as "running forever" and they fire during teardown when the dashboard
    * call is most likely to blip, so they are retried; the conditional UPDATE is idempotent, so the
    * retry is safe. Non-terminal writes are best-effort: a lost one is overwritten by the next
    * transition, and the retried terminal write clears the editing lock regardless.
    *
    * `retryTerminal = false` skips the retry — used by the CU's graceful-shutdown flush, where many
    * executions are finalized under a shutdown deadline and a blocking retry against an unresponsive
    * dashboard would risk a hard kill before the flush finishes (lazy on-read staleness is the
    * backstop for any write lost there).
    */
  def updateExecutionStatus(
      executionId: ExecutionIdentity,
      statusCode: Short,
      retryTerminal: Boolean = true
  ): Unit = {
    if (!RemoteExecutionMetadata.enabled) {
      WorkflowExecutionsResource.updateExecutionStatus(executionId.id.toLong, statusCode)
      return
    }
    val isTerminal = statusCode == 3 || statusCode == 4 || statusCode == 5
    try {
      if (isTerminal && retryTerminal) {
        Utils.retry(attempts = 3, baseBackoffTimeInMS = 200) {
          RemoteExecutionMetadata.updateExecutionStatus(executionId.id.toLong, statusCode)
        }
      } else {
        RemoteExecutionMetadata.updateExecutionStatus(executionId.id.toLong, statusCode)
      }
    } catch {
      case t: Throwable =>
        logger.warn(
          s"Failed to persist status $statusCode for execution $executionId" +
            (if (isTerminal && retryTerminal) " after retries" else "") + s": ${t.getMessage}"
        )
    }
  }

  def tryGetExistingExecution(executionId: ExecutionIdentity): Option[WorkflowExecutions] = {
    if (RemoteExecutionMetadata.enabled) {
      // degraded: previous-execution lookup is not needed on the computing unit in remote mode.
      return None
    }
    try {
      Option(workflowExecutionsDao.fetchOneByEid(executionId.id.toInt))
    } catch {
      case t: Throwable =>
        logger.info("Unable to get execution. Error = " + t.getMessage)
        None
    }
  }

  def tryUpdateExistingExecution(
      executionId: ExecutionIdentity
  )(updateFunc: WorkflowExecutions => Unit): Unit = {
    if (RemoteExecutionMetadata.enabled) {
      // no-op: execution-status updates are owned by the dashboard service in remote mode.
      logger.debug("Skipping execution update in remote mode.")
      return
    }
    try {
      val execution = workflowExecutionsDao.fetchOneByEid(executionId.id.toInt)
      updateFunc(execution)
      workflowExecutionsDao.update(execution)
    } catch {
      case t: Throwable =>
        logger.info("Unable to update execution. Error = " + t.getMessage)
    }
  }
}
