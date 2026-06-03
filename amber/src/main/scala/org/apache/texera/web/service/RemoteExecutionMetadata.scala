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

import org.apache.texera.amber.config.{ApplicationConfig, EnvironmentalVariable}
import org.apache.texera.amber.core.virtualidentity.ExecutionIdentity
import org.apache.texera.amber.util.JSONUtils.objectMapper

import java.net.{HttpURLConnection, URI, URL, URLEncoder}
import java.nio.charset.StandardCharsets
import scala.collection.concurrent.TrieMap
import scala.jdk.CollectionConverters._

/**
  * Routes execution-metadata operations to the dashboard service over HTTP, instead of querying
  * Postgres directly.
  *
  * This lets a computing-unit pod — which runs user-defined functions and therefore must not hold
  * database credentials (issue #5011) — persist and read execution metadata without a JDBC
  * connection.
  *
  * Remote mode is active exactly when `SqlServer` is NOT initialized in this process: the CU skips
  * initializing it, while the dashboard service keeps initializing it, so the dashboard service
  * always takes the direct-DB path and the metadata endpoints never recurse back onto themselves.
  */
object RemoteExecutionMetadata {

  // Fallback token from the environment, used when the execution did not carry a per-request token
  // (e.g. a CU pod minted a static token at creation). Per-execution request tokens take precedence.
  private lazy val envToken: String =
    sys.env.getOrElse(EnvironmentalVariable.ENV_USER_JWT_TOKEN, "").trim

  private lazy val baseEndpoint: String =
    ApplicationConfig.dashboardServiceExecutionMetadataEndpoint.trim

  /** Remote routing is active only when this process has no database connection of its own. */
  def enabled: Boolean = !org.apache.texera.dao.SqlServer.isInitialized

  // The JWT supplied by the user that issued each execution, keyed by execution id. Populated at
  // execution creation so that the metadata calls made later in the run (which only know the eid)
  // authenticate as the issuing user rather than as a static token embedded in the computing unit.
  private val executionTokens: TrieMap[Long, String] = TrieMap.empty

  /** Remember the issuing user's token for an execution; ignored when blank. */
  def registerExecutionToken(eid: Long, token: Option[String]): Unit =
    token.map(_.trim).filter(_.nonEmpty).foreach(executionTokens.put(eid, _))

  /** Forget an execution's token (call when the execution is cleaned up). */
  def clearExecutionToken(eid: Long): Unit = executionTokens.remove(eid)

  /** The issuing user's token for an execution, falling back to the environment token. */
  private[service] def tokenFor(eid: Long): String = executionTokens.getOrElse(eid, envToken)

  /** Resolve an explicitly-supplied per-request token, falling back to the environment token. */
  private[service] def resolve(token: Option[String]): String =
    token.map(_.trim).filter(_.nonEmpty).getOrElse(envToken)

  def createExecution(
      workflowId: Long,
      uid: Integer,
      executionName: String,
      environmentVersion: String,
      computingUnitId: Integer,
      userJwtToken: Option[String] = None
  ): ExecutionIdentity = {
    val body = objectMapper.createObjectNode()
    body.put("workflowId", workflowId)
    // A no-auth computing unit has no local user, so uid may be null; the dashboard service then
    // resolves the owner from the forwarded user token.
    if (uid != null) body.put("uid", uid.intValue()) else body.putNull("uid")
    body.put("executionName", executionName)
    body.put("environmentVersion", environmentVersion)
    body.put("computingUnitId", computingUnitId.intValue())
    val response = request(resolve(userJwtToken), "POST", "/create", Some(body.toString))
      .getOrElse(
        throw new RuntimeException("dashboard service returned no body for execution create")
      )
    val eid = objectMapper.readTree(response).get("eid").asLong()
    // Remember the issuing user's token so later eid-keyed metadata calls authenticate as them.
    registerExecutionToken(eid, userJwtToken)
    ExecutionIdentity(eid)
  }

  /**
    * Persist an execution's status code on the dashboard service. The dashboard applies it through a
    * conditional, terminal-monotonic UPDATE (see WorkflowExecutionsResource.updateExecutionStatus),
    * so this call is idempotent and safe to retry.
    */
  def updateExecutionStatus(eid: Long, statusCode: Short): Unit = {
    val body = objectMapper.createObjectNode()
    body.put("status", statusCode.toInt)
    request(tokenFor(eid), "PUT", s"/$eid/status", Some(body.toString))
  }

  def updateRuntimeStatsUri(wid: Long, eid: Long, uri: URI): Unit = {
    val body = objectMapper.createObjectNode()
    body.put("workflowId", wid)
    body.put("uri", uri.toString)
    request(tokenFor(eid), "PUT", s"/$eid/runtime-stats-uri", Some(body.toString))
  }

  def insertOperatorConsoleUri(eid: Long, operatorId: String, uri: URI): Unit = {
    val body = objectMapper.createObjectNode()
    body.put("operatorId", operatorId)
    body.put("uri", uri.toString)
    request(tokenFor(eid), "POST", s"/$eid/operator-console", Some(body.toString))
  }

  def insertPortResultUri(eid: Long, globalPortIdSerialized: String, uri: URI): Unit = {
    val body = objectMapper.createObjectNode()
    body.put("globalPortId", globalPortIdSerialized)
    body.put("uri", uri.toString)
    request(tokenFor(eid), "POST", s"/$eid/port-result", Some(body.toString))
  }

  /** All stored result URIs for an execution, used to discover which operators produced results. */
  def getResultUrisByExecutionId(eid: Long): List[URI] = {
    request(tokenFor(eid), "GET", s"/$eid/port-results", None)
      .map { response =>
        val urisNode = objectMapper.readTree(response).get("uris")
        if (urisNode == null) List.empty[URI]
        else urisNode.elements().asScala.map(node => new URI(node.asText())).toList
      }
      .getOrElse(List.empty)
  }

  def getResultUri(
      eid: Long,
      opId: String,
      portIdId: Int,
      portIdInternal: Boolean
  ): Option[URI] = {
    val path =
      s"/$eid/port-result?opId=${enc(opId)}&portId=$portIdId&internal=$portIdInternal"
    request(tokenFor(eid), "GET", path, None)
      .map(response => new URI(objectMapper.readTree(response).get("uri").asText()))
  }

  def getLatestExecutionId(
      wid: Integer,
      cuid: Integer,
      userJwtToken: Option[String] = None
  ): Option[Integer] = {
    request(resolve(userJwtToken), "GET", s"/latest?wid=$wid&cuid=$cuid", None)
      .map(response => Integer.valueOf(objectMapper.readTree(response).get("eid").asInt()))
  }

  /** All execution ids for a workflow + computing unit, newest first. Used by cleanup. */
  def getExecutionIds(wid: Integer, cuid: Integer): List[Integer] = {
    request(resolve(None), "GET", s"/executions?wid=$wid&cuid=$cuid", None)
      .map { response =>
        val eidsNode = objectMapper.readTree(response).get("eids")
        if (eidsNode == null) List.empty[Integer]
        else eidsNode.elements().asScala.map(node => Integer.valueOf(node.asInt())).toList
      }
      .getOrElse(List.empty)
  }

  /** The stored result URI for a (execution, global port) pair, by serialized GlobalPortIdentity. */
  def getResultUriByGlobalPortId(eid: Long, serializedPortId: String): Option[URI] = {
    request(tokenFor(eid), "GET", s"/$eid/port-result-by-gpid?gpid=${enc(serializedPortId)}", None)
      .map(response => new URI(objectMapper.readTree(response).get("uri").asText()))
  }

  private def enc(value: String): String =
    URLEncoder.encode(value, StandardCharsets.UTF_8.name())

  private[service] def request(
      token: String,
      method: String,
      path: String,
      body: Option[String]
  ): Option[String] =
    request(baseEndpoint, token, method, path, body)

  /** Endpoint/token are injectable so the HTTP round-trip can be unit-tested in isolation. */
  private[service] def request(
      baseEndpoint: String,
      token: String,
      method: String,
      path: String,
      body: Option[String]
  ): Option[String] = {
    val connection = new URL(baseEndpoint + path).openConnection().asInstanceOf[HttpURLConnection]
    connection.setRequestMethod(method)
    // Bound the blocking time: these calls run on the controller/stats/shutdown threads (the heartbeat
    // and terminal flush among them), so an unresponsive dashboard must fail fast rather than wedge a
    // thread or delay CU shutdown. The payloads are tiny, so these are generous.
    connection.setConnectTimeout(5000)
    connection.setReadTimeout(10000)
    connection.setRequestProperty("Authorization", s"Bearer $token")
    connection.setRequestProperty("Content-Type", "application/json")
    try {
      body.foreach { payload =>
        connection.setDoOutput(true)
        connection.getOutputStream.write(payload.getBytes(StandardCharsets.UTF_8))
      }
      val code = connection.getResponseCode
      if (code >= 200 && code < 300) {
        val stream = connection.getInputStream
        Some(new String(stream.readAllBytes(), StandardCharsets.UTF_8))
      } else if (code == HttpURLConnection.HTTP_NOT_FOUND) {
        None
      } else {
        throw new RuntimeException(
          s"dashboard service execution-metadata request failed: $method $path (HTTP $code)"
        )
      }
    } finally {
      connection.disconnect()
    }
  }
}
