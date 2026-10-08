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

import com.fasterxml.jackson.databind.node.ObjectNode
import io.dropwizard.auth.Auth
import jakarta.annotation.security.{PermitAll, RolesAllowed}
import jakarta.ws.rs._
import jakarta.ws.rs.core.{MediaType, Response}
import org.apache.texera.amber.core.storage.util.LakeFSStorageClient
import org.apache.texera.amber.util.JSONUtils.objectMapper
import org.apache.texera.auth.SessionUser
import org.apache.texera.common.config.AuthConfig
import org.apache.texera.dao.SqlServer
import org.apache.texera.dao.SqlServer.withTransaction
import org.apache.texera.dao.jooq.generated.tables.DatasetVersion.DATASET_VERSION
import org.apache.texera.dao.jooq.generated.tables.ModelVersion.MODEL_VERSION
import org.apache.texera.dao.jooq.generated.tables.daos.{DatasetDao, UserDao}
import org.apache.texera.dao.jooq.generated.tables.pojos.{DatasetVersion, ModelVersion}
import org.apache.texera.service.resource.LabelingLinkResource._
import org.jose4j.jws.{AlgorithmIdentifiers, JsonWebSignature}
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jwt.JwtClaims
import org.jose4j.keys.HmacKey
import org.jooq.DSLContext

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.time.Instant
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.imageio.ImageIO
import scala.jdk.CollectionConverters._

object LabelingLinkResource {
  private val Audience = "texera-labeling-link"
  private val MaxMaskBytes = 1 << 20

  /** The datasets and model one labeling task uses, and who it acts for. */
  case class LabelingScope(uid: Int, scans: Int, labels: Int, queue: Int, model: Int)

  case class CreateLinkRequest(scans: Int, labels: Int, queue: Int, model: Int, days: Option[Int])
  case class CreateLinkResponse(token: String, expiresAt: Long)
  case class OpenCase(
      `case`: String,
      round: Int,
      suggested_by: String,
      suggested_by_id: Int,
      uncertainty: Double
  )
  case class QueueState(open: List[OpenCase], labeled: Int, newestModel: String)
  case class SubmitLabelRequest(`case`: String, mask: String, annotator: String, seconds: Double)

  /**
    * A link token is signed with a key derived from the server secret, not the
    * secret itself, and names its own audience, so it can never pass as a
    * login token and a login token can never pass as a link.
    */
  private lazy val linkKey: HmacKey = {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(AuthConfig.jwtSecretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"))
    new HmacKey(mac.doFinal(Audience.getBytes(StandardCharsets.UTF_8)))
  }

  def issue(scope: LabelingScope, days: Int): CreateLinkResponse = {
    val claims = new JwtClaims()
    claims.setAudience(Audience)
    claims.setSubject(s"labeling:${scope.uid}")
    claims.setGeneratedJwtId()
    claims.setIssuedAtToNow()
    claims.setExpirationTimeMinutesInTheFuture(days * 24 * 60f)
    claims.setClaim("uid", scope.uid)
    claims.setClaim("scans", scope.scans)
    claims.setClaim("labels", scope.labels)
    claims.setClaim("queue", scope.queue)
    claims.setClaim("model", scope.model)
    val jws = new JsonWebSignature()
    jws.setPayload(claims.toJson)
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256)
    jws.setKey(linkKey)
    CreateLinkResponse(jws.getCompactSerialization, claims.getExpirationTime.getValueInMillis)
  }

  def verify(token: String): LabelingScope = {
    val claims =
      try {
        new JwtConsumerBuilder()
          .setRequireExpirationTime()
          .setAllowedClockSkewInSeconds(30)
          .setExpectedAudience(Audience)
          .setVerificationKey(linkKey)
          .build()
          .processToClaims(token)
      } catch {
        case _: Exception => throw new NotAuthorizedException("This labeling link is invalid or has expired.")
      }
    def int(name: String): Int = claims.getClaimValue(name, classOf[java.lang.Long]).intValue()
    LabelingScope(int("uid"), int("scans"), int("labels"), int("queue"), int("model"))
  }

  /** Mask PNGs are 0/255 single-channel; anything above mid-gray counts as tumor. */
  def maskPixels(png: Array[Byte]): Array[Boolean] = {
    val image = Option(ImageIO.read(new ByteArrayInputStream(png)))
      .getOrElse(throw new BadRequestException("The mask is not a PNG image."))
    (for (y <- 0 until image.getHeight; x <- 0 until image.getWidth)
      yield (image.getRGB(x, y) & 0xff) > 127).toArray
  }

  def dice(a: Array[Boolean], b: Array[Boolean]): Double = {
    val total = a.count(identity) + b.count(identity)
    if (total == 0) 1.0 else 2.0 * a.indices.count(i => a(i) && b(i)) / total
  }
}

/**
  * A link a developer hands to a clinician, who labels the open suggestions of
  * an active-labeling run from a plain web page without a Texera account.
  * Every label is written as the developer who made the link, and records
  * the name the clinician entered as its annotator.
  */
@Path("/labeling")
@Produces(Array(MediaType.APPLICATION_JSON))
class LabelingLinkResource {
  private def context: DSLContext = SqlServer.getInstance().createDSLContext()

  @POST
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/link")
  @Consumes(Array(MediaType.APPLICATION_JSON))
  def createLink(request: CreateLinkRequest, @Auth user: SessionUser): CreateLinkResponse = {
    val uid = user.getUid
    withTransaction(context) { ctx =>
      val allowed =
        DatasetAccessResource.userHasReadAccess(ctx, request.scans, uid) &&
          DatasetAccessResource.userHasReadAccess(ctx, request.queue, uid) &&
          DatasetAccessResource.userHasWriteAccess(ctx, request.labels, uid) &&
          ModelAccessResource.userHasReadAccess(ctx, request.model, uid)
      if (!allowed) {
        throw new ForbiddenException(
          "You need read access to the scans, queue and model, and write access to the labels."
        )
      }
    }
    val days = request.days.getOrElse(14).max(1).min(90)
    issue(LabelingScope(uid, request.scans, request.labels, request.queue, request.model), days)
  }

  @GET
  @PermitAll
  @Path("/{token}/queue")
  def queue(@PathParam("token") token: String): QueueState = {
    val scope = verify(token)
    withTransaction(context) { ctx =>
      val labeled = labeledCases(ctx, scope.labels)
      QueueState(
        openCases(ctx, scope.queue).filterNot(c => labeled.contains(c.`case`)),
        labeled.size,
        latestModelVersion(ctx, scope.model).map(_.getName).getOrElse("")
      )
    }
  }

  @GET
  @PermitAll
  @Path("/{token}/image/{kind}/{case}")
  @Produces(Array("image/png"))
  def image(
      @PathParam("token") token: String,
      @PathParam("kind") kind: String,
      @PathParam("case") caseName: String
  ): Response = {
    val scope = verify(token)
    val (did, path) = kind match {
      case "scan"       => (scope.scans, s"scans/$caseName.png")
      case "suggestion" => (scope.queue, s"items/$caseName.png")
      case _            => throw new NotFoundException()
    }
    val bytes = withTransaction(context)(ctx => readLatest(ctx, did, path))
    Response.ok(bytes, "image/png").header("Cache-Control", "private, max-age=300").build()
  }

  @POST
  @PermitAll
  @Path("/{token}/label")
  @Consumes(Array(MediaType.APPLICATION_JSON))
  def submit(@PathParam("token") token: String, request: SubmitLabelRequest): ObjectNode = {
    val scope = verify(token)
    val annotator = Option(request.annotator).map(_.trim.take(80)).filter(_.nonEmpty)
      .getOrElse(throw new BadRequestException("Enter your name before submitting."))
    val maskPng = Base64.getDecoder.decode(Option(request.mask).getOrElse(""))
    if (maskPng.isEmpty || maskPng.length > MaxMaskBytes) {
      throw new BadRequestException("The mask is missing or too large.")
    }

    withTransaction(context) { ctx =>
      // Only a case the run actually suggested, and not yet labeled, can be written.
      val suggestion = openCases(ctx, scope.queue)
        .find(_.`case` == request.`case`)
        .getOrElse(throw new BadRequestException("This case is not waiting for a label."))
      if (labeledCases(ctx, scope.labels).contains(suggestion.`case`)) {
        throw new BadRequestException("This case was already labeled.")
      }
      val suggestedPng = readLatest(ctx, scope.queue, s"items/${suggestion.`case`}.png")
      val (final_, suggested) = (maskPixels(maskPng), maskPixels(suggestedPng))
      if (final_.length != suggested.length) {
        throw new BadRequestException("The mask does not match the scan size.")
      }
      val newest = latestModelVersion(ctx, scope.model)
        .getOrElse(throw new BadRequestException("The model has no version yet."))

      val provenance = objectMapper.createObjectNode()
      provenance.put("case", suggestion.`case`)
      provenance.put("round", suggestion.round)
      provenance.put("suggested_by", suggestion.suggested_by)
      provenance.put("suggested_by_id", suggestion.suggested_by_id)
      provenance.put("newest_model_at_submit", newest.getName)
      provenance.put("newest_model_id_at_submit", newest.getMvid.intValue())
      provenance.put("versions_behind", newest.getMvid.intValue() - suggestion.suggested_by_id)
      provenance.put("uncertainty", suggestion.uncertainty)
      provenance.put("dice_suggested_vs_final", Math.round(dice(suggested, final_) * 10000) / 10000.0)
      provenance.put("pixels_changed", final_.indices.count(i => final_(i) != suggested(i)))
      provenance.put("seconds", Math.round(request.seconds.max(0) * 10) / 10.0)
      provenance.put("annotator", annotator)
      provenance.put("submitted_at", Instant.now().toString)

      val repo = new DatasetDao(ctx.configuration()).fetchOneByDid(scope.labels).getRepositoryName
      def write(path: String, bytes: Array[Byte]): Unit =
        LakeFSStorageClient.writeFileToRepo(repo, path, new ByteArrayInputStream(bytes))
      write(s"masks/${suggestion.`case`}.png", maskPng)
      write(s"suggestions/${suggestion.`case`}.png", suggestedPng)
      write(s"provenance/${suggestion.`case`}.json", objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(provenance))

      val creator = new SessionUser(new UserDao(ctx.configuration()).fetchOneByUid(scope.uid))
      val version = new DatasetResource().createDatasetVersion(
        s"label ${suggestion.`case`}, suggested by ${suggestion.suggested_by.split(' ').head}",
        scope.labels,
        creator
      )
      provenance.put("labels_version", version.datasetVersion.getName)
      provenance
    }
  }

  private def latestDatasetVersion(ctx: DSLContext, did: Int): Option[DatasetVersion] =
    Option(
      ctx
        .selectFrom(DATASET_VERSION)
        .where(DATASET_VERSION.DID.eq(did))
        .orderBy(DATASET_VERSION.CREATION_TIME.desc(), DATASET_VERSION.DVID.desc())
        .limit(1)
        .fetchOneInto(classOf[DatasetVersion])
    )

  private def latestModelVersion(ctx: DSLContext, mid: Int): Option[ModelVersion] =
    Option(
      ctx
        .selectFrom(MODEL_VERSION)
        .where(MODEL_VERSION.MID.eq(mid))
        .orderBy(MODEL_VERSION.CREATION_TIME.desc(), MODEL_VERSION.MVID.desc())
        .limit(1)
        .fetchOneInto(classOf[ModelVersion])
    )

  private def readLatest(ctx: DSLContext, did: Int, path: String): Array[Byte] = {
    val version = latestDatasetVersion(ctx, did).getOrElse(throw new NotFoundException())
    val repo = new DatasetDao(ctx.configuration()).fetchOneByDid(did).getRepositoryName
    try Files.readAllBytes(LakeFSStorageClient.getFileFromRepo(repo, version.getVersionHash, path).toPath)
    catch { case _: Exception => throw new NotFoundException(s"$path was not found.") }
  }

  private def labeledCases(ctx: DSLContext, did: Int): Set[String] =
    latestDatasetVersion(ctx, did) match {
      case None => Set.empty
      case Some(version) =>
        val repo = new DatasetDao(ctx.configuration()).fetchOneByDid(did).getRepositoryName
        LakeFSStorageClient
          .retrieveObjectsOfVersion(repo, version.getVersionHash)
          .map(_.getPath)
          .collect { case p if p.startsWith("provenance/") && p.endsWith(".json") => p.stripPrefix("provenance/").stripSuffix(".json") }
          .toSet
    }

  /** The open suggestions Suggest Cases last published, most uncertain first. */
  private def openCases(ctx: DSLContext, did: Int): List[OpenCase] =
    if (latestDatasetVersion(ctx, did).isEmpty) Nil
    else {
      val items = objectMapper.readTree(readLatest(ctx, did, "queue.json")).get("items")
      items.elements().asScala
        .map(item =>
          OpenCase(
            item.get("case").asText(),
            item.get("round").asInt(),
            item.get("suggested_by").asText(),
            item.get("suggested_by_id").asInt(),
            item.get("uncertainty").asDouble()
          )
        )
        .toList
        .sortBy(-_.uncertainty)
    }
}
