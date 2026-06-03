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

import org.apache.texera.amber.config.EnvironmentalVariable

/**
  * Supplies the JWT the computing unit presents on its outbound dataset calls (presigned-URL fetch
  * and dataset-path resolution). The token is per execution: it is the JWT of the user that issued
  * the running workflow, carried in the execute request and pushed down to each worker (issue
  * #5011), so a shared, identity-free computing unit reads datasets as the actual requester rather
  * than via a static token embedded in the unit.
  *
  * Each Amber worker runs its operator on its own dedicated DP thread, so the token is held in a
  * thread-local that the worker sets once when that thread starts. When no per-execution token has
  * been bound to the current thread (legacy CU pods that inject a static token, local dev, or
  * non-worker threads) it falls back to the USER_JWT_TOKEN environment variable, so existing
  * deployments keep working unchanged.
  */
object UserJwtTokenProvider {

  private val threadLocalToken: ThreadLocal[Option[String]] =
    ThreadLocal.withInitial[Option[String]](() => None)

  private lazy val envToken: Option[String] =
    sys.env.get(EnvironmentalVariable.ENV_USER_JWT_TOKEN).map(_.trim).filter(_.nonEmpty)

  /** Bind the issuing user's token to the current thread (typically a worker's DP thread). */
  def setForCurrentThread(token: Option[String]): Unit =
    threadLocalToken.set(token.map(_.trim).filter(_.nonEmpty))

  /** Remove any thread-bound token so the environment fallback applies again. */
  def clearForCurrentThread(): Unit = threadLocalToken.remove()

  /**
    * The token to present on outbound dataset calls: the thread-bound per-execution token if set,
    * otherwise the environment fallback. May be empty when neither is available.
    */
  def currentToken: String = threadLocalToken.get().orElse(envToken).getOrElse("")
}
