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
import org.apache.texera.amber.core.workflow.cache.FingerprintUtil
import org.apache.texera.amber.core.workflow.{CachedOutput, GlobalPortIdentity, PhysicalPlan}
import org.apache.texera.amber.util.JSONUtils.objectMapper
import org.apache.texera.amber.util.serde.GlobalPortIdentitySerde
import org.apache.texera.amber.util.serde.GlobalPortIdentitySerde.SerdeOps

import java.net.URI
import scala.jdk.CollectionConverters._

/**
  * Operator-port-result cache that routes all persistence to the Dashboard Service over HTTP,
  * for a Postgres-free computing unit (issue #5011). Mirrors [[RemoteExecutionMetadata]]: the
  * subDAG fingerprints are computed locally (pure, no DB) and only the lookup/upsert/invalidate
  * round-trips go over HTTP, authenticated with the issuing user's per-execution token.
  *
  * The Dashboard Service handles the actual Postgres reads/writes and the cached-result-document
  * clearing (it holds STORAGE_JDBC_* and can reach the result store), via
  * InternalExecutionMetadataResource's cache endpoints.
  */
class RemoteOperatorPortCacheService extends OperatorPortCache {

  override def lookupCachedOutputs(
      workflowId: WorkflowIdentity,
      executionId: ExecutionIdentity,
      physicalPlan: PhysicalPlan
  ): Map[GlobalPortIdentity, CachedOutput] = {
    val ports = physicalPlan.operators
      .flatMap(op => op.outputPorts.keys.map(pid => GlobalPortIdentity(op.id, pid)))
    if (ports.isEmpty) return Map.empty

    val body = objectMapper.createObjectNode()
    body.put("workflowId", workflowId.id)
    val portsArray = body.putArray("ports")
    ports.foreach { gpid =>
      val node = portsArray.addObject()
      node.put("gpid", gpid.serializeAsString)
      node.put("subdagHash", FingerprintUtil.computeSubdagFingerprint(physicalPlan, gpid).subdagHash)
    }

    RemoteExecutionMetadata
      .request(
        RemoteExecutionMetadata.tokenFor(executionId.id),
        "POST",
        s"/${executionId.id}/cache-lookup",
        Some(body.toString)
      )
      .map { response =>
        val hits = objectMapper.readTree(response).get("hits")
        if (hits == null) Map.empty[GlobalPortIdentity, CachedOutput]
        else
          hits.elements().asScala.flatMap { hit =>
            val gpid = GlobalPortIdentitySerde.deserializeFromString(hit.get("gpid").asText())
            val tupleCount =
              if (hit.hasNonNull("tupleCount")) Some(hit.get("tupleCount").asLong()) else None
            val sourceExecutionId =
              if (hit.hasNonNull("sourceExecutionId"))
                Some(ExecutionIdentity(hit.get("sourceExecutionId").asLong()))
              else None
            Some(
              gpid -> CachedOutput(
                resultUri = new URI(hit.get("resultUri").asText()),
                fingerprintJson = hit.get("fingerprintJson").asText(),
                tupleCount = tupleCount,
                sourceExecutionId = sourceExecutionId
              )
            )
          }.toMap
      }
      .getOrElse(Map.empty)
  }

  override def upsertCachedOutput(
      workflowId: WorkflowIdentity,
      executionId: ExecutionIdentity,
      portId: GlobalPortIdentity,
      physicalPlan: PhysicalPlan,
      resultUri: URI,
      tupleCount: Option[Long]
  ): Unit = {
    val fingerprint = FingerprintUtil.computeSubdagFingerprint(physicalPlan, portId)
    val body = objectMapper.createObjectNode()
    body.put("workflowId", workflowId.id)
    body.put("globalPortId", portId.serializeAsString)
    body.put("subdagHash", fingerprint.subdagHash)
    body.put("fingerprintJson", fingerprint.fingerprintJson)
    body.put("resultUri", resultUri.toString)
    tupleCount match {
      case Some(c) => body.put("tupleCount", c)
      case None    => body.putNull("tupleCount")
    }
    body.put("sourceExecutionId", executionId.id)
    RemoteExecutionMetadata.request(
      RemoteExecutionMetadata.tokenFor(executionId.id),
      "POST",
      s"/${executionId.id}/cache",
      Some(body.toString)
    )
  }

  override def invalidateCacheBySourceExecutionsWithArtifacts(
      executionIds: Seq[ExecutionIdentity]
  ): OperatorPortCache.SourceExecutionInvalidationResult = {
    if (executionIds.isEmpty) {
      return OperatorPortCache.SourceExecutionInvalidationResult(0, Set.empty)
    }
    val body = objectMapper.createObjectNode()
    val idsArray = body.putArray("executionIds")
    executionIds.foreach(eid => idsArray.add(eid.id))
    RemoteExecutionMetadata
      .request(
        RemoteExecutionMetadata.tokenFor(executionIds.head.id),
        "POST",
        s"/${executionIds.head.id}/cache/invalidate-by-source",
        Some(body.toString)
      )
      .map { response =>
        val root = objectMapper.readTree(response)
        val deletedRows = Option(root.get("deletedRows")).map(_.asInt()).getOrElse(0)
        val urisNode = root.get("deletedResultUris")
        val uris =
          if (urisNode == null) Set.empty[URI]
          else urisNode.elements().asScala.map(node => new URI(node.asText())).toSet
        OperatorPortCache.SourceExecutionInvalidationResult(deletedRows, uris)
      }
      .getOrElse(OperatorPortCache.SourceExecutionInvalidationResult(0, Set.empty))
  }
}
