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

package org.apache.texera.web.resource

import io.dropwizard.auth.Auth
import org.apache.texera.amber.core.virtualidentity.{
  ExecutionIdentity,
  OperatorIdentity,
  WorkflowIdentity
}
import org.apache.texera.amber.core.workflow.PortIdentity
import org.apache.texera.amber.util.serde.GlobalPortIdentitySerde
import org.apache.texera.auth.SessionUser
import org.apache.texera.dao.SqlServer
import org.apache.texera.web.dao.{OperatorPortCacheDao, OperatorPortCacheRecord}
import org.apache.texera.web.resource.dashboard.user.workflow.WorkflowExecutionsResource
import org.apache.texera.web.service.{ExecutionsMetadataPersistService, OperatorPortCacheService}

import java.net.URI
import javax.annotation.security.RolesAllowed
import javax.ws.rs._
import javax.ws.rs.core.MediaType

case class CreateExecutionRequest(
    workflowId: Long,
    uid: Option[Integer],
    executionName: String,
    environmentVersion: String,
    computingUnitId: Integer
)

case class CreateExecutionResponse(eid: Long)

case class StatusUpdateRequest(status: Int)

case class RuntimeStatsUriRequest(workflowId: Long, uri: String)

case class OperatorConsoleUriRequest(operatorId: String, uri: String)

case class PortResultUriRequest(globalPortId: String, uri: String)

case class ResultUriResponse(uri: String)

case class ResultUrisResponse(uris: List[String])

case class LatestExecutionResponse(eid: Int)

case class ExecutionIdsResponse(eids: List[Int])

// Operator-port-result cache (issue #5011): a Postgres-free computing unit routes cache
// lookup/upsert/invalidate here, where the dashboard service holds the DB connection.
case class CacheLookupPort(gpid: String, subdagHash: String)

case class CacheLookupRequest(workflowId: Long, ports: List[CacheLookupPort])

case class CacheHit(
    gpid: String,
    resultUri: String,
    fingerprintJson: String,
    tupleCount: Option[Long],
    sourceExecutionId: Option[Long]
)

case class CacheLookupResponse(hits: List[CacheHit])

case class CacheUpsertRequest(
    workflowId: Long,
    globalPortId: String,
    subdagHash: String,
    fingerprintJson: String,
    resultUri: String,
    tupleCount: Option[Long],
    sourceExecutionId: Long
)

case class CacheInvalidateBySourceRequest(executionIds: List[Long])

case class CacheInvalidationResultResponse(deletedRows: Int, deletedResultUris: List[String])

/**
  * Internal HTTP endpoints that the dashboard service exposes so a computing unit can perform
  * execution-metadata operations without holding Postgres credentials (issue #5011).
  *
  * These endpoints run on the dashboard service, where `SqlServer` is initialized, so the companion
  * methods they delegate to take their direct-DB branch and never recurse back to the remote client.
  */
@Path("/internal/execution-metadata")
@Consumes(Array(MediaType.APPLICATION_JSON))
@Produces(Array(MediaType.APPLICATION_JSON))
class InternalExecutionMetadataResource {

  @POST
  @Path("/create")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def createExecution(
      request: CreateExecutionRequest,
      @Auth user: SessionUser
  ): CreateExecutionResponse = {
    // The execution owner is the request's uid when the caller knows the real user; when the
    // caller is a no-auth Computing Unit that sends no uid, fall back to the authenticated user of
    // this metadata call (the holder of the CU's USER_JWT_TOKEN). workflow_executions.uid is NOT NULL.
    val eid = ExecutionsMetadataPersistService.insertNewExecution(
      WorkflowIdentity(request.workflowId),
      request.uid.getOrElse(user.getUid),
      request.executionName,
      request.environmentVersion,
      request.computingUnitId
    )
    CreateExecutionResponse(eid.id.toLong)
  }

  // The computing unit persists every execution-status transition here (it holds no Postgres
  // connection). The status is applied through a conditional, terminal-monotonic UPDATE on the
  // dashboard, so a stale/late write can never regress a finished execution.
  @PUT
  @Path("/{eid}/status")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def updateExecutionStatus(
      @PathParam("eid") eid: Long,
      request: StatusUpdateRequest,
      @Auth user: SessionUser
  ): Unit = {
    if (request.status < 0 || request.status > 5) {
      throw new BadRequestException(s"Invalid execution status code: ${request.status}")
    }
    WorkflowExecutionsResource.updateExecutionStatus(eid, request.status.toShort)
  }

  @PUT
  @Path("/{eid}/runtime-stats-uri")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def updateRuntimeStatsUri(
      @PathParam("eid") eid: Long,
      request: RuntimeStatsUriRequest,
      @Auth user: SessionUser
  ): Unit = {
    WorkflowExecutionsResource.updateRuntimeStatsUri(request.workflowId, eid, new URI(request.uri))
  }

  @POST
  @Path("/{eid}/operator-console")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def insertOperatorConsoleUri(
      @PathParam("eid") eid: Long,
      request: OperatorConsoleUriRequest,
      @Auth user: SessionUser
  ): Unit = {
    WorkflowExecutionsResource.insertOperatorExecutions(
      eid,
      request.operatorId,
      new URI(request.uri)
    )
  }

  @POST
  @Path("/{eid}/port-result")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def insertPortResultUri(
      @PathParam("eid") eid: Long,
      request: PortResultUriRequest,
      @Auth user: SessionUser
  ): Unit = {
    WorkflowExecutionsResource.insertOperatorPortResultUriSerialized(
      ExecutionIdentity(eid),
      request.globalPortId,
      new URI(request.uri)
    )
  }

  @GET
  @Path("/{eid}/port-result")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def getResultUri(
      @PathParam("eid") eid: Long,
      @QueryParam("opId") opId: String,
      @QueryParam("portId") portId: Int,
      @QueryParam("internal") internal: Boolean,
      @Auth user: SessionUser
  ): ResultUriResponse = {
    WorkflowExecutionsResource
      .getResultUriByLogicalPortId(
        ExecutionIdentity(eid),
        OperatorIdentity(opId),
        PortIdentity(portId, internal)
      )
      .map(uri => ResultUriResponse(uri.toString))
      .getOrElse(throw new NotFoundException(s"No result URI found for execution $eid"))
  }

  // All stored result URIs for an execution. A no-DB computing unit uses this to discover which
  // operators produced results (it only ever wrote them via POST /port-result), which drives the
  // WebResultUpdateEvent that tells the frontend a result is viewable.
  @GET
  @Path("/{eid}/port-results")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def getResultUris(
      @PathParam("eid") eid: Long,
      @Auth user: SessionUser
  ): ResultUrisResponse = {
    ResultUrisResponse(
      WorkflowExecutionsResource
        .getResultUrisByExecutionId(ExecutionIdentity(eid))
        .map(_.toString)
    )
  }

  @GET
  @Path("/latest")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def getLatestExecutionId(
      @QueryParam("wid") wid: Integer,
      @QueryParam("cuid") cuid: Integer,
      @Auth user: SessionUser
  ): LatestExecutionResponse = {
    WorkflowExecutionsResource
      .getLatestExecutionID(wid, cuid)
      .map(eid => LatestExecutionResponse(eid.intValue()))
      .getOrElse(throw new NotFoundException(s"No execution found for workflow $wid"))
  }

  // All execution ids for a workflow + computing unit (newest first). A Postgres-free CU uses this
  // for lifecycle cleanup of execution-scoped artifacts.
  @GET
  @Path("/executions")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def getExecutionIds(
      @QueryParam("wid") wid: Integer,
      @QueryParam("cuid") cuid: Integer,
      @Auth user: SessionUser
  ): ExecutionIdsResponse = {
    ExecutionIdsResponse(WorkflowExecutionsResource.getExecutionIDs(wid, cuid).map(_.intValue()))
  }

  // Result URI for a (execution, serialized global port) pair. Used by the engine's cache hook on
  // the CU (PortCompletedHandler) when a materialized output port completes.
  @GET
  @Path("/{eid}/port-result-by-gpid")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def getResultUriByGlobalPortId(
      @PathParam("eid") eid: Long,
      @QueryParam("gpid") gpid: String,
      @Auth user: SessionUser
  ): ResultUriResponse = {
    WorkflowExecutionsResource
      .getResultUriByPhysicalPortId(
        ExecutionIdentity(eid),
        GlobalPortIdentitySerde.deserializeFromString(gpid)
      )
      .map(uri => ResultUriResponse(uri.toString))
      .getOrElse(throw new NotFoundException(s"No result URI for port $gpid in execution $eid"))
  }

  // ── Operator-port-result cache (issue #5011): the Postgres-free CU routes cache persistence here.

  @POST
  @Path("/{eid}/cache-lookup")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def cacheLookup(
      @PathParam("eid") eid: Long,
      request: CacheLookupRequest,
      @Auth user: SessionUser
  ): CacheLookupResponse = {
    val dao = new OperatorPortCacheDao(SqlServer.getInstance())
    val hits = request.ports.flatMap { port =>
      dao
        .get(request.workflowId, port.gpid, port.subdagHash)
        .map(rec =>
          CacheHit(
            gpid = port.gpid,
            resultUri = rec.resultUri.toString,
            fingerprintJson = rec.fingerprintJson,
            tupleCount = rec.tupleCount,
            sourceExecutionId = rec.sourceExecutionId
          )
        )
    }
    CacheLookupResponse(hits)
  }

  @POST
  @Path("/{eid}/cache")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def cacheUpsert(
      @PathParam("eid") eid: Long,
      request: CacheUpsertRequest,
      @Auth user: SessionUser
  ): Unit = {
    val dao = new OperatorPortCacheDao(SqlServer.getInstance())
    dao.upsert(
      OperatorPortCacheRecord(
        workflowId = request.workflowId,
        globalPortId = request.globalPortId,
        subdagHash = request.subdagHash,
        fingerprintJson = request.fingerprintJson,
        resultUri = new URI(request.resultUri),
        // Jackson-Scala boxes the inner of Option[Long] as Integer for small JSON numbers; coerce
        // via Number so the DAO's Long unbox doesn't ClassCastException.
        tupleCount = request.tupleCount.asInstanceOf[Option[Number]].map(_.longValue()),
        sourceExecutionId = Some(request.sourceExecutionId)
      )
    )
  }

  @POST
  @Path("/{eid}/cache/invalidate-by-source")
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  def cacheInvalidateBySource(
      @PathParam("eid") eid: Long,
      request: CacheInvalidateBySourceRequest,
      @Auth user: SessionUser
  ): CacheInvalidationResultResponse = {
    val cacheService = new OperatorPortCacheService(new OperatorPortCacheDao(SqlServer.getInstance()))
    // Jackson-Scala boxes List[Long] elements as Integer for small JSON numbers; coerce via Number.
    val result = cacheService.invalidateCacheBySourceExecutionsWithArtifacts(
      request.executionIds.asInstanceOf[List[Number]].map(n => ExecutionIdentity(n.longValue()))
    )
    CacheInvalidationResultResponse(
      result.deletedRows,
      result.deletedResultUris.map(_.toString).toList
    )
  }
}
