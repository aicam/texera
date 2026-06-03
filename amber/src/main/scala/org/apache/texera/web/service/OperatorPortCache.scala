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

import org.apache.texera.amber.core.virtualidentity.{ExecutionIdentity, WorkflowIdentity}
import org.apache.texera.amber.core.workflow.{CachedOutput, GlobalPortIdentity, PhysicalPlan}

import java.net.URI

/**
  * The operator-port-result cache operations used along the workflow EXECUTION path
  * (submission lookup, per-port upsert, source-execution invalidation).
  *
  * Two implementations select on whether this process holds a Postgres connection
  * (issue #5011):
  *   - [[OperatorPortCacheService]] talks to Postgres directly (the Dashboard Service).
  *   - [[RemoteOperatorPortCacheService]] routes over HTTP to the Dashboard Service
  *     (a Postgres-free computing unit), mirroring [[RemoteExecutionMetadata]].
  *
  * Fingerprint computation ([[org.apache.texera.amber.core.workflow.cache.FingerprintUtil]])
  * is pure and stays local in both implementations; only the persistence round-trips differ.
  */
trait OperatorPortCache {

  /**
    * Batch-lookup cached outputs for all materializable ports in the plan (submission time).
    *
    * `executionId` is the current execution; the direct-DB implementation ignores it, while the
    * remote implementation uses it to authenticate the HTTP call as the issuing user.
    */
  def lookupCachedOutputs(
      workflowId: WorkflowIdentity,
      executionId: ExecutionIdentity,
      physicalPlan: PhysicalPlan
  ): Map[GlobalPortIdentity, CachedOutput]

  /** Upsert a cache entry when an output port materializes (runtime). */
  def upsertCachedOutput(
      workflowId: WorkflowIdentity,
      executionId: ExecutionIdentity,
      portId: GlobalPortIdentity,
      physicalPlan: PhysicalPlan,
      resultUri: URI,
      tupleCount: Option[Long]
  ): Unit

  /** Invalidate cache entries produced by the given executions, returning the deleted artifacts. */
  def invalidateCacheBySourceExecutionsWithArtifacts(
      executionIds: Seq[ExecutionIdentity]
  ): OperatorPortCache.SourceExecutionInvalidationResult
}

object OperatorPortCache {

  /**
    * Result of cache invalidation by source executions.
    *
    * @param deletedRows       number of rows removed from operator_port_cache
    * @param deletedResultUris cached result URIs deleted/cleared during invalidation
    */
  case class SourceExecutionInvalidationResult(
      deletedRows: Int,
      deletedResultUris: Set[URI]
  )
}
