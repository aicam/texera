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

import org.apache.texera.amber.core.workflow.WorkflowContext
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

/**
  * The issuing user's JWT now travels in the execute request and is stored on the per-execution
  * [[WorkflowContext]], so a shared, identity-free computing unit forwards the *requester's* token
  * on its outbound calls instead of a static token embedded in the unit. These tests pin the token
  * selection used by [[RemoteExecutionMetadata]]: an explicit per-request/per-execution token wins,
  * and only when it is absent does it fall back to the environment token.
  *
  * The HTTP forwarding itself (method/bearer/body) is covered by RemoteExecutionMetadataSpec; here
  * we exercise the token-resolution layer those calls route through.
  */
class PerExecutionTokenSpec extends AnyFlatSpec with Matchers {

  // No USER_JWT_TOKEN is set in the test environment, so the environment fallback is the empty string.
  private val envFallback = ""

  "WorkflowContext" should "carry the issuing user's JWT" in {
    val ctx = new WorkflowContext()
    ctx.userJwtToken shouldBe None
    ctx.userJwtToken = Some("jwt-xyz")
    ctx.userJwtToken shouldBe Some("jwt-xyz")
  }

  "RemoteExecutionMetadata.resolve" should "prefer an explicit token over the environment fallback" in {
    RemoteExecutionMetadata.resolve(Some("jwt-1")) shouldBe "jwt-1"
    RemoteExecutionMetadata.resolve(Some("  jwt-2  ")) shouldBe "jwt-2"
  }

  it should "fall back to the environment token when no usable token is supplied" in {
    RemoteExecutionMetadata.resolve(None) shouldBe envFallback
    RemoteExecutionMetadata.resolve(Some("")) shouldBe envFallback
    RemoteExecutionMetadata.resolve(Some("   ")) shouldBe envFallback
  }

  "RemoteExecutionMetadata's per-execution token registry" should
    "return a registered token for its execution and the env fallback otherwise" in {
    val eid = 90001L
    try {
      RemoteExecutionMetadata.tokenFor(eid) shouldBe envFallback // unregistered -> fallback
      RemoteExecutionMetadata.registerExecutionToken(eid, Some("jwt-exec"))
      RemoteExecutionMetadata.tokenFor(eid) shouldBe "jwt-exec"
    } finally RemoteExecutionMetadata.clearExecutionToken(eid)
    RemoteExecutionMetadata.tokenFor(eid) shouldBe envFallback // cleared -> fallback
  }

  it should "ignore a blank or absent token at registration (keeping the env fallback)" in {
    val eid = 90002L
    try {
      RemoteExecutionMetadata.registerExecutionToken(eid, None)
      RemoteExecutionMetadata.tokenFor(eid) shouldBe envFallback
      RemoteExecutionMetadata.registerExecutionToken(eid, Some("   "))
      RemoteExecutionMetadata.tokenFor(eid) shouldBe envFallback
    } finally RemoteExecutionMetadata.clearExecutionToken(eid)
  }

  it should "keep tokens isolated per execution" in {
    val (a, b) = (90003L, 90004L)
    try {
      RemoteExecutionMetadata.registerExecutionToken(a, Some("tok-a"))
      RemoteExecutionMetadata.registerExecutionToken(b, Some("tok-b"))
      RemoteExecutionMetadata.tokenFor(a) shouldBe "tok-a"
      RemoteExecutionMetadata.tokenFor(b) shouldBe "tok-b"
    } finally {
      RemoteExecutionMetadata.clearExecutionToken(a)
      RemoteExecutionMetadata.clearExecutionToken(b)
    }
  }
}
