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

import io.dropwizard.auth.Auth
import jakarta.annotation.security.RolesAllowed
import jakarta.ws.rs.core.{MediaType, Response}
import jakarta.ws.rs._
import org.apache.texera.auth.SessionUser
import org.apache.texera.dao.SqlServer
import org.apache.texera.dao.SqlServer.withTransaction
import org.apache.texera.dao.jooq.generated.Tables.USER
import org.apache.texera.dao.jooq.generated.enums.PrivilegeEnum
import org.apache.texera.dao.jooq.generated.tables.AssetUserAccess.ASSET_USER_ACCESS
import org.apache.texera.dao.jooq.generated.tables.daos.{AssetDao, AssetUserAccessDao, UserDao}
import org.apache.texera.dao.jooq.generated.tables.pojos.{AssetUserAccess, User}
import org.apache.texera.service.resource.AssetAccessResource.{
  AccessEntry,
  context,
  getOwner,
  userHasWriteAccess
}
import org.jooq.{DSLContext, EnumType}

import javax.ws.rs.ForbiddenException

object AssetAccessResource {
  private def context: DSLContext =
    SqlServer
      .getInstance()
      .createDSLContext()

  def isAssetPublic(ctx: DSLContext, aid: Integer): Boolean = {
    val assetDao = new AssetDao(ctx.configuration())
    Option(assetDao.fetchOneByAid(aid))
      .flatMap(asset => Option(asset.getIsPublic))
      .contains(true)
  }

  def userHasReadAccess(ctx: DSLContext, aid: Integer, uid: Integer): Boolean = {
    isAssetPublic(ctx, aid) ||
    userHasWriteAccess(ctx, aid, uid) ||
    getAssetUserAccessPrivilege(ctx, aid, uid) == PrivilegeEnum.READ
  }

  def userOwnAsset(ctx: DSLContext, aid: Integer, uid: Integer): Boolean = {
    val assetDao = new AssetDao(ctx.configuration())

    Option(assetDao.fetchOneByAid(aid))
      .exists(_.getOwnerUid == uid)
  }

  def userHasWriteAccess(ctx: DSLContext, aid: Integer, uid: Integer): Boolean = {
    userOwnAsset(ctx, aid, uid) ||
    getAssetUserAccessPrivilege(ctx, aid, uid) == PrivilegeEnum.WRITE
  }

  def getAssetUserAccessPrivilege(
      ctx: DSLContext,
      aid: Integer,
      uid: Integer
  ): PrivilegeEnum = {
    Option(
      ctx
        .select(ASSET_USER_ACCESS.PRIVILEGE)
        .from(ASSET_USER_ACCESS)
        .where(
          ASSET_USER_ACCESS.AID
            .eq(aid)
            .and(ASSET_USER_ACCESS.UID.eq(uid))
        )
        .fetchOneInto(classOf[PrivilegeEnum])
    ).getOrElse(PrivilegeEnum.NONE)
  }

  def getOwner(ctx: DSLContext, aid: Integer): User = {
    val assetDao = new AssetDao(ctx.configuration())
    val userDao = new UserDao(ctx.configuration())

    Option(assetDao.fetchOneByAid(aid))
      .flatMap(asset => Option(asset.getOwnerUid))
      .map(ownerUid => userDao.fetchOneByUid(ownerUid))
      .orNull
  }

  case class AccessEntry(email: String, name: String, privilege: EnumType) {}

}

@Produces(Array(MediaType.APPLICATION_JSON))
@RolesAllowed(Array("REGULAR", "ADMIN"))
@Path("/access/asset")
class AssetAccessResource {

  /**
    * This method returns the owner of an asset
    *
    * @param aid ,  asset id
    * @return ownerEmail,  the owner's email
    */
  @GET
  @Path("/owner/{aid}")
  def getOwnerEmailOfAsset(@PathParam("aid") aid: Integer): String = {
    var email = ""
    withTransaction(context) { ctx =>
      val owner = getOwner(ctx, aid)
      if (owner != null) {
        email = owner.getEmail
      }
    }
    email
  }

  /**
    * Returns information about all current shared access of the given asset
    *
    * @param aid asset id
    * @return a List of email/name/permission
    */
  @GET
  @Path("/list/{aid}")
  def getAccessList(
      @PathParam("aid") aid: Integer
  ): java.util.List[AccessEntry] = {
    withTransaction(context) { ctx =>
      val assetDao = new AssetDao(ctx.configuration())
      ctx
        .select(
          USER.EMAIL,
          USER.NAME,
          ASSET_USER_ACCESS.PRIVILEGE
        )
        .from(ASSET_USER_ACCESS)
        .join(USER)
        .on(USER.UID.eq(ASSET_USER_ACCESS.UID))
        .where(
          ASSET_USER_ACCESS.AID
            .eq(aid)
            .and(ASSET_USER_ACCESS.UID.notEqual(assetDao.fetchOneByAid(aid).getOwnerUid))
        )
        .fetchInto(classOf[AccessEntry])
    }
  }

  /**
    * This method shares an asset to a user with a specific access type
    *
    * @param aid       the given asset
    * @param email     the email which the access is given to
    * @param privilege the type of Access given to the target user
    * @return rejection if user not permitted to share the workflow or Success Message
    */
  @PUT
  @Path("/grant/{aid}/{email}/{privilege}")
  def grantAccess(
      @PathParam("aid") aid: Integer,
      @PathParam("email") email: String,
      @PathParam("privilege") privilege: String,
      @Auth user: SessionUser
  ): Response = {
    withTransaction(context) { ctx =>
      if (!userHasWriteAccess(ctx, aid, user.getUid)) {
        throw new ForbiddenException(s"You do not have permission to modify asset $aid")
      }
      val assetUserAccessDao = new AssetUserAccessDao(ctx.configuration())
      val userDao = new UserDao(ctx.configuration())
      assetUserAccessDao.merge(
        new AssetUserAccess(
          aid,
          userDao.fetchOneByEmail(email).getUid,
          PrivilegeEnum.valueOf(privilege)
        )
      )
      Response.ok().build()
    }
  }

  /**
    * This method revoke the user's access of the given asset
    *
    * @param aid   the given asset
    * @param email the email of the use whose access is about to be removed
    * @return message indicating a success message
    */
  @DELETE
  @Path("/revoke/{aid}/{email}")
  def revokeAccess(
      @PathParam("aid") aid: Integer,
      @PathParam("email") email: String,
      @Auth user: SessionUser
  ): Response = {
    withTransaction(context) { ctx =>
      if (!userHasWriteAccess(ctx, aid, user.getUid)) {
        throw new ForbiddenException(s"You do not have permission to modify asset $aid")
      }

      val userDao = new UserDao(ctx.configuration())

      ctx
        .delete(ASSET_USER_ACCESS)
        .where(
          ASSET_USER_ACCESS.UID
            .eq(userDao.fetchOneByEmail(email).getUid)
            .and(ASSET_USER_ACCESS.AID.eq(aid))
        )
        .execute()

      Response.ok().build()
    }
  }
}
