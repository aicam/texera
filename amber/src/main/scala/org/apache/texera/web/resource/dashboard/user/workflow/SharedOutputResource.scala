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

package org.apache.texera.web.resource.dashboard.user.workflow

import io.dropwizard.auth.Auth
import org.apache.texera.amber.core.storage.SharedOutputs
import org.apache.texera.auth.SessionUser
import org.apache.texera.dao.SqlServer
import org.apache.texera.dao.jooq.generated.enums.PrivilegeEnum
import org.apache.texera.dao.jooq.generated.tables.SharedOutput.SHARED_OUTPUT
import org.apache.texera.dao.jooq.generated.tables.SharedOutputUserAccess.SHARED_OUTPUT_USER_ACCESS
import org.apache.texera.dao.jooq.generated.tables.User.USER
import org.apache.texera.dao.jooq.generated.tables.Workflow.WORKFLOW
import org.apache.texera.amber.operator.source.shared.SharedOutputSourceOpDesc
import org.apache.texera.common.compiler.model.LogicalPlanPojo
import org.apache.texera.web.resource.dashboard.user.workflow.SharedOutputResource._
import org.jooq.{DSLContext, Record}

import javax.annotation.security.RolesAllowed
import javax.ws.rs._
import javax.ws.rs.core.MediaType
import scala.jdk.CollectionConverters._

object SharedOutputResource {
  private def context: DSLContext = SqlServer.getInstance().createDSLContext()

  case class SharedOutputEntry(
      soid: Int,
      reference: String,
      name: String,
      description: String,
      ownerEmail: String,
      wid: Int,
      workflowName: String,
      operatorId: String,
      portId: Int,
      isOwner: Boolean
  )

  case class PublishRequest(
      wid: Int,
      operatorId: String,
      portId: Option[Int],
      name: String,
      description: Option[String]
  )

  case class ShareRequest(email: String)

  case class AccessEntry(email: String, privilege: String)

  private def toEntry(row: Record, uid: Int): SharedOutputEntry = {
    val ownerEmail = row.get(USER.EMAIL)
    SharedOutputEntry(
      row.get(SHARED_OUTPUT.SOID),
      SharedOutputs.reference(ownerEmail, row.get(SHARED_OUTPUT.NAME)),
      row.get(SHARED_OUTPUT.NAME),
      Option(row.get(SHARED_OUTPUT.DESCRIPTION)).getOrElse(""),
      ownerEmail,
      row.get(SHARED_OUTPUT.WID),
      row.get(WORKFLOW.NAME),
      row.get(SHARED_OUTPUT.OPERATOR_ID),
      row.get(SHARED_OUTPUT.PORT_ID),
      row.get(SHARED_OUTPUT.OWNER_UID) == uid
    )
  }

  /**
    * Refuses a plan that reads a shared output the user cannot read.
    */
  def requireReadable(plan: LogicalPlanPojo, uid: Int): Unit =
    plan.operators.collect { case source: SharedOutputSourceOpDesc => source.sharedOutput }.foreach {
      reference =>
        val readable = SharedOutputs.find(reference).exists(SharedOutputs.canRead(_, uid))
        if (!readable) {
          throw new IllegalStateException(s"'$reference' is not shared with you")
        }
    }

  private def entries(condition: org.jooq.Condition, uid: Int): List[SharedOutputEntry] =
    context
      .select(SHARED_OUTPUT.fields() ++ Seq(USER.EMAIL, WORKFLOW.NAME): _*)
      .from(SHARED_OUTPUT)
      .join(USER)
      .on(USER.UID.eq(SHARED_OUTPUT.OWNER_UID))
      .join(WORKFLOW)
      .on(WORKFLOW.WID.eq(SHARED_OUTPUT.WID))
      .where(condition)
      .orderBy(SHARED_OUTPUT.NAME)
      .fetch()
      .asScala
      .map(toEntry(_, uid))
      .toList
}

/**
  * Publishing an operator's output under a name, so other workflows, including other users'
  * pipelines, read it in place with a Shared Output source.
  */
@Produces(Array(MediaType.APPLICATION_JSON))
@RolesAllowed(Array("REGULAR", "ADMIN"))
@Path("/shared-output")
class SharedOutputResource {

  /** The outputs the user published or was given access to. */
  @GET
  @Path("/list")
  def list(@Auth user: SessionUser): List[SharedOutputEntry] = {
    val uid = user.getUid.intValue()
    entries(
      SHARED_OUTPUT.OWNER_UID
        .eq(uid)
        .or(
          SHARED_OUTPUT.SOID.in(
            context
              .select(SHARED_OUTPUT_USER_ACCESS.SOID)
              .from(SHARED_OUTPUT_USER_ACCESS)
              .where(SHARED_OUTPUT_USER_ACCESS.UID.eq(uid))
          )
        ),
      uid
    )
  }

  /** The outputs published from a workflow the user can read. */
  @GET
  @Path("/workflow/{wid}")
  def ofWorkflow(@PathParam("wid") wid: Integer, @Auth user: SessionUser): List[SharedOutputEntry] = {
    if (!WorkflowAccessResource.hasReadAccess(wid, user.getUid)) {
      throw new ForbiddenException("No access to this workflow")
    }
    entries(SHARED_OUTPUT.WID.eq(wid.intValue()), user.getUid.intValue())
  }

  @POST
  @Consumes(Array(MediaType.APPLICATION_JSON))
  @Path("/publish")
  def publish(request: PublishRequest, @Auth user: SessionUser): SharedOutputEntry = {
    val uid = user.getUid.intValue()
    if (!WorkflowAccessResource.hasWriteAccess(request.wid, uid)) {
      throw new ForbiddenException("Only someone who can edit the workflow can publish its outputs")
    }
    val name = Option(request.name).map(_.trim).getOrElse("")
    if (!name.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")) {
      throw new BadRequestException("Use letters, digits, '.', '_' or '-' for the name")
    }
    val portId = request.portId.getOrElse(0)
    val taken = context.fetchExists(
      SHARED_OUTPUT,
      SHARED_OUTPUT.OWNER_UID.eq(uid).and(SHARED_OUTPUT.NAME.eq(name))
    )
    if (taken) throw new BadRequestException(s"You already published an output named '$name'")
    val published = context.fetchExists(
      SHARED_OUTPUT,
      SHARED_OUTPUT.WID
        .eq(request.wid)
        .and(SHARED_OUTPUT.OPERATOR_ID.eq(request.operatorId))
        .and(SHARED_OUTPUT.PORT_ID.eq(portId))
    )
    if (published) throw new BadRequestException("This output is already published")
    val soid = context
      .insertInto(SHARED_OUTPUT)
      .set(SHARED_OUTPUT.NAME, name)
      .set(SHARED_OUTPUT.DESCRIPTION, request.description.map(_.trim).orNull)
      .set(SHARED_OUTPUT.OWNER_UID, Integer.valueOf(uid))
      .set(SHARED_OUTPUT.WID, Integer.valueOf(request.wid))
      .set(SHARED_OUTPUT.OPERATOR_ID, request.operatorId)
      .set(SHARED_OUTPUT.PORT_ID, Integer.valueOf(portId))
      .returning(SHARED_OUTPUT.SOID)
      .fetchOne()
      .getSoid
    entries(SHARED_OUTPUT.SOID.eq(soid), uid).head
  }

  @DELETE
  @Path("/{soid}")
  def unpublish(@PathParam("soid") soid: Integer, @Auth user: SessionUser): Unit = {
    requireOwner(soid, user)
    context.deleteFrom(SHARED_OUTPUT).where(SHARED_OUTPUT.SOID.eq(soid)).execute()
  }

  @GET
  @Path("/{soid}/access")
  def access(@PathParam("soid") soid: Integer, @Auth user: SessionUser): List[AccessEntry] = {
    requireOwner(soid, user)
    context
      .select(USER.EMAIL, SHARED_OUTPUT_USER_ACCESS.PRIVILEGE)
      .from(SHARED_OUTPUT_USER_ACCESS)
      .join(USER)
      .on(USER.UID.eq(SHARED_OUTPUT_USER_ACCESS.UID))
      .where(SHARED_OUTPUT_USER_ACCESS.SOID.eq(soid))
      .fetch()
      .asScala
      .map(row => AccessEntry(row.value1(), row.value2().getLiteral))
      .toList
  }

  /** Lets another user's workflows read the output. */
  @POST
  @Consumes(Array(MediaType.APPLICATION_JSON))
  @Path("/{soid}/share")
  def share(
      @PathParam("soid") soid: Integer,
      request: ShareRequest,
      @Auth user: SessionUser
  ): Unit = {
    requireOwner(soid, user)
    val reader = Option(
      context.selectFrom(USER).where(USER.EMAIL.eq(Option(request.email).getOrElse("").trim)).fetchOne()
    ).getOrElse(throw new BadRequestException(s"No user with email ${request.email}"))
    context
      .insertInto(SHARED_OUTPUT_USER_ACCESS)
      .set(SHARED_OUTPUT_USER_ACCESS.SOID, soid)
      .set(SHARED_OUTPUT_USER_ACCESS.UID, reader.getUid)
      .set(SHARED_OUTPUT_USER_ACCESS.PRIVILEGE, PrivilegeEnum.READ)
      .onConflictDoNothing()
      .execute()
  }

  @DELETE
  @Path("/{soid}/share/{email}")
  def revoke(
      @PathParam("soid") soid: Integer,
      @PathParam("email") email: String,
      @Auth user: SessionUser
  ): Unit = {
    requireOwner(soid, user)
    context
      .deleteFrom(SHARED_OUTPUT_USER_ACCESS)
      .where(
        SHARED_OUTPUT_USER_ACCESS.SOID
          .eq(soid)
          .and(
            SHARED_OUTPUT_USER_ACCESS.UID.in(
              context.select(USER.UID).from(USER).where(USER.EMAIL.eq(email))
            )
          )
      )
      .execute()
  }

  private def requireOwner(soid: Integer, user: SessionUser): Unit = {
    val owner = Option(
      context.select(SHARED_OUTPUT.OWNER_UID).from(SHARED_OUTPUT).where(SHARED_OUTPUT.SOID.eq(soid)).fetchOne()
    ).getOrElse(throw new NotFoundException("No such shared output"))
    if (owner.value1() != user.getUid) {
      throw new ForbiddenException("Only the owner can change a shared output")
    }
  }
}
