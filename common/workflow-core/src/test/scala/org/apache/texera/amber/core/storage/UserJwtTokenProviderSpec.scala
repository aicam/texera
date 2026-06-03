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

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

import java.util.concurrent.{Executors, TimeUnit}

/**
  * The per-execution user token is bound to a worker's DP thread and read by the dataset-read code
  * (`DatasetFileDocument` presign, `RemoteDatasetResolver`). These tests pin that thread-local
  * behavior: a token bound on one thread is visible to reads on that thread, isolated from other
  * threads (so concurrent workers running different users' executions don't cross tokens), blank /
  * absent bindings fall back, and clearing restores the fallback.
  *
  * No USER_JWT_TOKEN is set in the test environment, so the fallback is the empty string.
  */
class UserJwtTokenProviderSpec extends AnyFlatSpec with Matchers {

  private val envFallback = ""

  override def withFixture(test: NoArgTest) = {
    try super.withFixture(test)
    finally UserJwtTokenProvider.clearForCurrentThread()
  }

  "UserJwtTokenProvider" should "fall back to the environment token when nothing is bound" in {
    UserJwtTokenProvider.clearForCurrentThread()
    UserJwtTokenProvider.currentToken shouldBe envFallback
  }

  it should "return the token bound to the current thread, trimmed" in {
    UserJwtTokenProvider.setForCurrentThread(Some("  jwt-abc  "))
    UserJwtTokenProvider.currentToken shouldBe "jwt-abc"
  }

  it should "treat a blank or absent binding as no token (fallback applies)" in {
    UserJwtTokenProvider.setForCurrentThread(Some("   "))
    UserJwtTokenProvider.currentToken shouldBe envFallback
    UserJwtTokenProvider.setForCurrentThread(None)
    UserJwtTokenProvider.currentToken shouldBe envFallback
  }

  it should "restore the fallback after the binding is cleared" in {
    UserJwtTokenProvider.setForCurrentThread(Some("jwt-xyz"))
    UserJwtTokenProvider.currentToken shouldBe "jwt-xyz"
    UserJwtTokenProvider.clearForCurrentThread()
    UserJwtTokenProvider.currentToken shouldBe envFallback
  }

  it should "isolate tokens per thread (one worker cannot see another's token)" in {
    UserJwtTokenProvider.setForCurrentThread(Some("main-thread-token"))

    val executor = Executors.newSingleThreadExecutor()
    try {
      val otherThreadToken = executor
        .submit[String](() => {
          // A fresh thread inherits no binding -> fallback.
          val before = UserJwtTokenProvider.currentToken
          // Binding on this thread must not leak back to the main thread.
          UserJwtTokenProvider.setForCurrentThread(Some("other-thread-token"))
          before + "|" + UserJwtTokenProvider.currentToken
        })
        .get(5, TimeUnit.SECONDS)

      otherThreadToken shouldBe s"$envFallback|other-thread-token"
      // The other thread's binding did not affect this thread.
      UserJwtTokenProvider.currentToken shouldBe "main-thread-token"
    } finally executor.shutdownNow()
  }
}
