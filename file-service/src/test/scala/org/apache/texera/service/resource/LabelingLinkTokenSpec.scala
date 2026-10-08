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

package org.apache.texera.service.resource

import jakarta.ws.rs.NotAuthorizedException
import org.apache.texera.auth.JwtAuth
import org.apache.texera.dao.jooq.generated.enums.UserRoleEnum
import org.apache.texera.dao.jooq.generated.tables.pojos.User
import org.apache.texera.service.resource.LabelingLinkResource.{LabelingScope, dice, issue, verify}
import org.scalatest.flatspec.AnyFlatSpec

class LabelingLinkTokenSpec extends AnyFlatSpec {
  private val scope = LabelingScope(uid = 7, scans = 1, labels = 3, queue = 4, model = 2)

  "A labeling link" should "carry exactly the scope it was issued for" in {
    assert(verify(issue(scope, days = 14).token) == scope)
  }

  it should "not be accepted as a login token" in {
    val link = issue(scope, days = 14).token
    assertThrows[Exception](JwtAuth.jwtConsumer.processToClaims(link))
  }

  it should "reject a login token" in {
    val user = new User()
    user.setUid(7)
    user.setName("dev")
    user.setEmail("dev@example.com")
    user.setRole(UserRoleEnum.ADMIN)
    val login = JwtAuth.jwtToken(JwtAuth.jwtClaims(user))
    assertThrows[NotAuthorizedException](verify(login))
  }

  it should "reject a tampered token" in {
    val link = issue(scope, days = 14).token
    val tampered = link.dropRight(2) + (if (link.endsWith("AA")) "BB" else "AA")
    assertThrows[NotAuthorizedException](verify(tampered))
  }

  "dice" should "be 1 for two empty masks and 0 for disjoint ones" in {
    assert(dice(Array(false, false), Array(false, false)) == 1.0)
    assert(dice(Array(true, false), Array(false, true)) == 0.0)
    assert(dice(Array(true, true), Array(true, false)) == 2.0 / 3)
  }
}
