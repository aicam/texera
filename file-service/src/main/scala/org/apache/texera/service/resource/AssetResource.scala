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
import jakarta.ws.rs._
import jakarta.ws.rs.core._
import org.apache.texera.amber.config.StorageConfig
import org.apache.texera.amber.core.storage.model.OnAsset
import org.apache.texera.amber.core.storage.util.LakeFSStorageClient
import org.apache.texera.amber.core.storage.{DocumentFactory, FileResolver}
import org.apache.texera.auth.SessionUser
import org.apache.texera.dao.SqlServer
import org.apache.texera.dao.SqlServer.withTransaction
import org.apache.texera.dao.jooq.generated.enums.PrivilegeEnum
import org.apache.texera.dao.jooq.generated.enums.AssetTypeEnum
import org.apache.texera.dao.jooq.generated.tables.Asset.ASSET
import org.apache.texera.dao.jooq.generated.tables.AssetUserAccess.ASSET_USER_ACCESS
import org.apache.texera.dao.jooq.generated.tables.AssetVersion.ASSET_VERSION
import org.apache.texera.dao.jooq.generated.tables.User.USER
import org.apache.texera.dao.jooq.generated.tables.daos.{
  AssetDao,
  AssetUserAccessDao,
  AssetVersionDao
}
import org.apache.texera.dao.jooq.generated.tables.pojos.{
  Asset,
  AssetUserAccess,
  AssetVersion
}
import org.apache.texera.service.`type`.AssetFileNode
import org.apache.texera.service.resource.AssetAccessResource._
import org.apache.texera.service.resource.AssetResource.{context, _}
import org.apache.texera.service.util.S3StorageClient
import org.apache.texera.service.util.S3StorageClient.{
  MAXIMUM_NUM_OF_MULTIPART_S3_PARTS,
  MINIMUM_NUM_OF_MULTIPART_S3_PART,
  PHYSICAL_ADDRESS_EXPIRATION_TIME_HRS
}
import org.jooq.impl.DSL
import org.jooq.impl.DSL.{inline => inl}
import org.jooq.{DSLContext, EnumType, Record2, Result}

import java.io.{InputStream, OutputStream}
import java.net.{HttpURLConnection, URI, URL, URLDecoder}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.util
import java.util.Optional
import java.util.zip.{ZipEntry, ZipOutputStream}
import scala.collection.mutable.ListBuffer
import scala.jdk.CollectionConverters._
import scala.jdk.OptionConverters._
import org.apache.texera.dao.jooq.generated.tables.AssetUploadSession.ASSET_UPLOAD_SESSION
import org.apache.texera.dao.jooq.generated.tables.AssetUploadSessionPart.ASSET_UPLOAD_SESSION_PART
import org.jooq.exception.DataAccessException
import software.amazon.awssdk.services.s3.model.UploadPartResponse
import org.apache.commons.io.FilenameUtils
import org.apache.texera.service.util.LakeFSExceptionHandler.withLakeFSErrorHandling
import org.apache.texera.dao.jooq.generated.tables.records.AssetUploadSessionRecord

import java.sql.SQLException
import java.time.OffsetDateTime
import scala.util.Try

object AssetResource {

  private def context =
    SqlServer
      .getInstance()
      .createDSLContext()

  private def singleFileUploadMaxBytes(ctx: DSLContext, defaultMiB: Long = 20L): Long = {
    val limit = ctx
      .select(DSL.field("value", classOf[String]))
      .from(DSL.table(DSL.name("texera_db", "site_settings")))
      .where(DSL.field("key", classOf[String]).eq("single_file_upload_max_size_mib"))
      .fetchOneInto(classOf[String])
    Try(Option(limit).getOrElse(defaultMiB.toString).trim.toLong)
      .getOrElse(defaultMiB) * 1024L * 1024L
  }

  /**
    * Maps an AssetTypeEnum to the resource type prefix used in logical paths.
    */
  def resourceTypePrefix(assetType: AssetTypeEnum): String = {
    assetType match {
      case AssetTypeEnum.dataset => "datasets"
      case AssetTypeEnum.model   => "models"
    }
  }

  /**
    * Helper function to get the asset from DB using aid
    */
  private def getAssetByID(ctx: DSLContext, aid: Integer): Asset = {
    val assetDao = new AssetDao(ctx.configuration())
    val asset = assetDao.fetchOneByAid(aid)
    if (asset == null) {
      throw new NotFoundException(f"Asset $aid not found")
    }
    asset
  }

  /**
    * Helper function to PUT exactly len bytes from buf to presigned URL, return the ETag
    */
  private def put(buf: Array[Byte], len: Int, url: String, partNum: Int): String = {
    val conn = new URL(url).openConnection().asInstanceOf[HttpURLConnection]
    conn.setDoOutput(true)
    conn.setRequestMethod("PUT")
    conn.setFixedLengthStreamingMode(len)
    val out = conn.getOutputStream
    out.write(buf, 0, len)
    out.close()

    val code = conn.getResponseCode
    if (code != HttpURLConnection.HTTP_OK && code != HttpURLConnection.HTTP_CREATED)
      throw new RuntimeException(s"Part $partNum upload failed (HTTP $code)")

    val etag = conn.getHeaderField("ETag").replace("\"", "")
    conn.disconnect()
    etag
  }

  /**
    * Helper function to get the asset version from DB using avid
    */
  private def getAssetVersionByID(
      ctx: DSLContext,
      avid: Integer
  ): AssetVersion = {
    val assetVersionDao = new AssetVersionDao(ctx.configuration())
    val version = assetVersionDao.fetchOneByAvid(avid)
    if (version == null) {
      throw new NotFoundException("Asset Version not found")
    }
    version
  }

  /**
    * Helper function to get the latest asset version from the DB
    */
  private def getLatestAssetVersion(
      ctx: DSLContext,
      aid: Integer
  ): Option[AssetVersion] = {
    ctx
      .selectFrom(ASSET_VERSION)
      .where(ASSET_VERSION.AID.eq(aid))
      .orderBy(ASSET_VERSION.CREATION_TIME.desc())
      .limit(1)
      .fetchOptionalInto(classOf[AssetVersion])
      .toScala
  }

  /**
    * Validates a file path using Apache Commons IO.
    */
  def validateAndNormalizeFilePathOrThrow(path: String): String = {
    if (path == null || path.trim.isEmpty) {
      throw new BadRequestException("Path cannot be empty")
    }

    val normalized = FilenameUtils.normalize(path, true)
    if (normalized == null) {
      throw new BadRequestException("Invalid path")
    }

    if (FilenameUtils.getPrefixLength(normalized) > 0) {
      throw new BadRequestException("Absolute paths not allowed")
    }
    normalized
  }

  case class DashboardAsset(
      asset: Asset,
      ownerEmail: String,
      accessPrivilege: EnumType,
      isOwner: Boolean,
      size: Long
  )

  case class DashboardAssetVersion(
      assetVersion: AssetVersion,
      fileNodes: List[AssetFileNode]
  )

  case class CreateAssetRequest(
      assetName: String,
      assetDescription: String,
      assetType: AssetTypeEnum,
      isAssetPublic: Boolean,
      isAssetDownloadable: Boolean
  )

  case class Diff(
      path: String,
      pathType: String,
      diffType: String, // "added", "removed", "changed", etc.
      sizeBytes: Option[Long] // Size of the changed file (None for directories)
  )

  case class AssetDescriptionModification(aid: Integer, description: String)

  case class AssetVersionRootFileNodesResponse(
      fileNodes: List[AssetFileNode],
      size: Long
  )

  case class CoverImageRequest(coverImage: String)
}

@Produces(Array(MediaType.APPLICATION_JSON, "image/jpeg", "application/pdf"))
@Path("/asset")
class AssetResource {
  private val ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE = "User has no access to this asset"
  private val ERR_ASSET_VERSION_NOT_FOUND_MESSAGE = "The version of the asset not found"
  private val EXPIRATION_MINUTES = 5

  private val COVER_IMAGE_SIZE_LIMIT_BYTES: Long = 10 * 1024 * 1024 // 10 MB
  private val ALLOWED_IMAGE_EXTENSIONS: Set[String] = Set(".jpg", ".jpeg", ".png", ".gif", ".webp")

  /**
    * Helper function to get the asset from DB with additional information including user access privilege and owner email
    */
  private def getDashboardAsset(
      ctx: DSLContext,
      aid: Integer,
      requesterUid: Option[Integer]
  ): DashboardAsset = {
    val targetAsset = getAssetByID(ctx, aid)

    if (requesterUid.isEmpty && !targetAsset.getIsPublic) {
      throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
    } else if (requesterUid.exists(uid => !userHasReadAccess(ctx, aid, uid))) {
      throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
    }

    val userAccessPrivilege = requesterUid
      .map(uid => getAssetUserAccessPrivilege(ctx, aid, uid))
      .getOrElse(PrivilegeEnum.READ)

    val isOwner = requesterUid.contains(targetAsset.getOwnerUid)

    DashboardAsset(
      targetAsset,
      getOwner(ctx, aid).getEmail,
      userAccessPrivilege,
      isOwner,
      LakeFSStorageClient.retrieveRepositorySize(targetAsset.getRepositoryName)
    )
  }

  @POST
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/create")
  @Consumes(Array(MediaType.APPLICATION_JSON))
  def createAsset(
      request: CreateAssetRequest,
      @Auth user: SessionUser
  ): DashboardAsset = {

    withTransaction(context) { ctx =>
      val uid = user.getUid
      val assetUserAccessDao: AssetUserAccessDao = new AssetUserAccessDao(ctx.configuration())

      val assetName = request.assetName
      val assetDescription = request.assetDescription
      val isAssetPublic = request.isAssetPublic
      val isAssetDownloadable = request.isAssetDownloadable

      // validate asset name
      try {
        validateAssetName(assetName)
      } catch {
        case e: IllegalArgumentException =>
          throw new BadRequestException(e.getMessage)
      }

      // Check if an asset with the same name already exists
      val existingAssets = context
        .selectFrom(ASSET)
        .where(ASSET.OWNER_UID.eq(uid))
        .and(ASSET.NAME.eq(assetName))
        .fetch()
      if (!existingAssets.isEmpty) {
        throw new BadRequestException("Asset with the same name already exists")
      }

      // insert the asset into the database
      val asset = new Asset()
      asset.setName(assetName)
      asset.setDescription(assetDescription)
      asset.setType(request.assetType)
      asset.setIsPublic(isAssetPublic)
      asset.setIsDownloadable(isAssetDownloadable)
      asset.setOwnerUid(uid)

      // insert record and get created asset with aid
      val createdAsset = ctx
        .insertInto(ASSET)
        .set(ctx.newRecord(ASSET, asset))
        .returning()
        .fetchOne()

      // Initialize the repository in LakeFS
      val repositoryName = s"asset-${createdAsset.getAid}"
      try {
        LakeFSStorageClient.initRepo(repositoryName)
      } catch {
        case e: Exception =>
          ctx
            .deleteFrom(ASSET)
            .where(ASSET.AID.eq(createdAsset.getAid))
            .execute()
          throw new WebApplicationException(
            s"Failed to create the asset: ${e.getMessage}"
          )
      }

      // update repository name of the created asset
      createdAsset.setRepositoryName(repositoryName)
      createdAsset.update()

      // Insert the requester as the WRITE access user for this asset
      val assetUserAccess = new AssetUserAccess()
      assetUserAccess.setAid(createdAsset.getAid)
      assetUserAccess.setUid(uid)
      assetUserAccess.setPrivilege(PrivilegeEnum.WRITE)
      assetUserAccessDao.insert(assetUserAccess)

      DashboardAsset(
        createdAsset.into(classOf[Asset]),
        user.getEmail,
        PrivilegeEnum.WRITE,
        isOwner = true,
        0
      )
    }
  }

  @POST
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/version/create")
  @Consumes(Array(MediaType.TEXT_PLAIN))
  def createAssetVersion(
      versionName: String,
      @PathParam("aid") aid: Integer,
      @Auth user: SessionUser
  ): DashboardAssetVersion = {
    val uid = user.getUid
    withTransaction(context) { ctx =>
      if (!userHasWriteAccess(ctx, aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }

      val asset = getAssetByID(ctx, aid)
      val repoName = asset.getName
      val repositoryName = asset.getRepositoryName

      // Check if there are any changes in LakeFS before creating a new version
      val diffs = withLakeFSErrorHandling {
        LakeFSStorageClient.retrieveUncommittedObjects(repoName = repositoryName)
      }

      if (diffs.isEmpty) {
        throw new WebApplicationException(
          "No changes detected in asset. Version creation aborted.",
          Response.Status.BAD_REQUEST
        )
      }

      // Generate a new version name
      val versionCount = ctx
        .selectCount()
        .from(ASSET_VERSION)
        .where(ASSET_VERSION.AID.eq(aid))
        .fetchOne(0, classOf[Int])

      val sanitizedVersionName = Option(versionName).filter(_.nonEmpty).getOrElse("")
      val newVersionName = if (sanitizedVersionName.isEmpty) {
        s"v${versionCount + 1}"
      } else {
        s"v${versionCount + 1} - $sanitizedVersionName"
      }

      // Create a commit in LakeFS
      val commit = withLakeFSErrorHandling {
        LakeFSStorageClient.createCommit(
          repoName = repositoryName,
          branch = "main",
          commitMessage = s"Created asset version: $newVersionName"
        )
      }

      if (commit == null || commit.getId == null) {
        throw new WebApplicationException(
          "Failed to create commit in LakeFS. Version creation aborted.",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }

      // Create a new asset version entry in the database
      val assetVersion = new AssetVersion()
      assetVersion.setAid(aid)
      assetVersion.setCreatorUid(uid)
      assetVersion.setName(newVersionName)
      assetVersion.setVersionHash(commit.getId) // Store LakeFS version hash

      val insertedVersion = ctx
        .insertInto(ASSET_VERSION)
        .set(ctx.newRecord(ASSET_VERSION, assetVersion))
        .returning()
        .fetchOne()
        .into(classOf[AssetVersion])

      // Retrieve committed file structure
      val fileNodes = withLakeFSErrorHandling {
        LakeFSStorageClient.retrieveObjectsOfVersion(repositoryName, commit.getId)
      }

      DashboardAssetVersion(
        insertedVersion,
        AssetFileNode
          .fromLakeFSRepositoryCommittedObjects(
            Map((resourceTypePrefix(asset.getType), user.getEmail, repoName, newVersionName) -> fileNodes)
          )
      )
    }
  }

  @DELETE
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}")
  def deleteAsset(@PathParam("aid") aid: Integer, @Auth user: SessionUser): Response = {
    val uid = user.getUid
    withTransaction(context) { ctx =>
      val assetDao = new AssetDao(ctx.configuration())
      val asset = getAssetByID(ctx, aid)
      if (!userOwnAsset(ctx, asset.getAid, uid)) {
        // throw the exception that user has no access to certain asset
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }
      try {
        LakeFSStorageClient.deleteRepo(asset.getRepositoryName)
      } catch {
        case e: Exception =>
          throw new WebApplicationException(
            s"Failed to delete an asset in LakeFS: ${e.getMessage}",
            e
          )
      }
      // delete the directory on S3
      if (
        S3StorageClient.directoryExists(StorageConfig.lakefsBucketName, asset.getRepositoryName)
      ) {
        S3StorageClient.deleteDirectory(StorageConfig.lakefsBucketName, asset.getRepositoryName)
      }

      // delete the asset from the DB
      assetDao.deleteById(asset.getAid)

      Response.ok().build()
    }
  }

  @POST
  @Consumes(Array(MediaType.APPLICATION_JSON))
  @Produces(Array(MediaType.APPLICATION_JSON))
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/update/description")
  def updateAssetDescription(
      modificator: AssetDescriptionModification,
      @Auth sessionUser: SessionUser
  ): Response = {
    withTransaction(context) { ctx =>
      val uid = sessionUser.getUid
      val assetDao = new AssetDao(ctx.configuration())
      val asset = getAssetByID(ctx, modificator.aid)
      if (!userHasWriteAccess(ctx, modificator.aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }

      asset.setDescription(modificator.description)
      assetDao.update(asset)
      Response.ok().build()
    }
  }

  @POST
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/upload")
  @Consumes(Array(MediaType.APPLICATION_OCTET_STREAM))
  def uploadOneFileToAsset(
      @PathParam("aid") aid: Integer,
      @QueryParam("filePath") encodedFilePath: String,
      @QueryParam("message") message: String,
      fileStream: InputStream,
      @Context headers: HttpHeaders,
      @Auth user: SessionUser
  ): Response = {
    // These variables are defined at the top so catch block can access them
    val uid = user.getUid
    var repoName: String = null
    var filePath: String = null
    var uploadId: String = null
    var physicalAddress: String = null

    try {
      withTransaction(context) { ctx =>
        if (!userHasWriteAccess(ctx, aid, uid))
          throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)

        val asset = getAssetByID(ctx, aid)
        repoName = asset.getRepositoryName
        filePath = URLDecoder.decode(encodedFilePath, StandardCharsets.UTF_8.name)

        // ---------- decide part-size & number-of-parts ----------
        val declaredLen = Option(headers.getHeaderString(HttpHeaders.CONTENT_LENGTH)).map(_.toLong)
        var partSize = StorageConfig.s3MultipartUploadPartSize

        declaredLen.foreach { ln =>
          val needed = ((ln + partSize - 1) / partSize).toInt
          if (needed > MAXIMUM_NUM_OF_MULTIPART_S3_PARTS)
            partSize = math.max(
              MINIMUM_NUM_OF_MULTIPART_S3_PART,
              ln / (MAXIMUM_NUM_OF_MULTIPART_S3_PARTS - 1)
            )
        }

        val expectedParts = declaredLen
          .map(ln =>
            ((ln + partSize - 1) / partSize).toInt + 1
          ) // “+1” for the last (possibly small) part
          .getOrElse(MAXIMUM_NUM_OF_MULTIPART_S3_PARTS)

        // ---------- ask LakeFS for presigned URLs ----------
        val presign = LakeFSStorageClient
          .initiatePresignedMultipartUploads(repoName, filePath, expectedParts)
        uploadId = presign.getUploadId
        val presignedUrls = presign.getPresignedUrls.asScala.iterator
        physicalAddress = presign.getPhysicalAddress

        // ---------- stream & upload parts ----------
        /*
        1. Reads the input stream in chunks of 'partSize' bytes by stacking them in a buffer
        2. Uploads each chunk (part) using a presigned URL
        3. Tracks each part number and ETag returned from S3
        4. After all parts are uploaded, completes the multipart upload
         */
        val buf = new Array[Byte](partSize.toInt)
        var buffered = 0
        var partNumber = 1
        val completedParts = ListBuffer[(Int, String)]()

        @inline def flush(): Unit = {
          if (buffered == 0) return
          if (!presignedUrls.hasNext)
            throw new WebApplicationException("Ran out of presigned part URLs – ask for more parts")

          val etag = put(buf, buffered, presignedUrls.next(), partNumber)
          completedParts += ((partNumber, etag))
          partNumber += 1
          buffered = 0
        }

        var read = fileStream.read(buf, buffered, buf.length - buffered)
        while (read != -1) {
          buffered += read
          if (buffered == buf.length) flush() // buffer full
          read = fileStream.read(buf, buffered, buf.length - buffered)
        }
        fileStream.close()
        flush()

        // ---------- complete upload ----------
        LakeFSStorageClient.completePresignedMultipartUploads(
          repoName,
          filePath,
          uploadId,
          completedParts.toList,
          physicalAddress
        )

        Response.ok(Map("message" -> s"Uploaded $filePath in ${completedParts.size} parts")).build()
      }
    } catch {
      case e: Exception =>
        if (repoName != null && filePath != null && uploadId != null && physicalAddress != null) {
          LakeFSStorageClient.abortPresignedMultipartUploads(
            repoName,
            filePath,
            uploadId,
            physicalAddress
          )
        }
        throw new WebApplicationException(
          s"Failed to upload file to asset: ${e.getMessage}",
          e
        )
    }
  }

  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/presign-download")
  def getPresignedUrl(
      @QueryParam("filePath") encodedUrl: String,
      @QueryParam("repositoryName") repositoryName: String,
      @QueryParam("commitHash") commitHash: String,
      @Auth user: SessionUser
  ): Response = {
    val uid = user.getUid
    generatePresignedResponse(encodedUrl, repositoryName, commitHash, uid)
  }

  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/presign-download-s3")
  def getPresignedUrlWithS3(
      @QueryParam("filePath") encodedUrl: String,
      @QueryParam("repositoryName") repositoryName: String,
      @QueryParam("commitHash") commitHash: String,
      @Auth user: SessionUser
  ): Response = {
    val uid = user.getUid
    generatePresignedResponse(encodedUrl, repositoryName, commitHash, uid)
  }

  @GET
  @Path("/public-presign-download")
  def getPublicPresignedUrl(
      @QueryParam("filePath") encodedUrl: String,
      @QueryParam("repositoryName") repositoryName: String,
      @QueryParam("commitHash") commitHash: String
  ): Response = {
    generatePresignedResponse(encodedUrl, repositoryName, commitHash, null)
  }

  @GET
  @Path("/public-presign-download-s3")
  def getPublicPresignedUrlWithS3(
      @QueryParam("filePath") encodedUrl: String,
      @QueryParam("repositoryName") repositoryName: String,
      @QueryParam("commitHash") commitHash: String
  ): Response = {
    generatePresignedResponse(encodedUrl, repositoryName, commitHash, null)
  }

  @DELETE
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/file")
  @Consumes(Array(MediaType.APPLICATION_JSON))
  def deleteAssetFile(
      @PathParam("aid") aid: Integer,
      @QueryParam("filePath") encodedFilePath: String,
      @Auth user: SessionUser
  ): Response = {
    val uid = user.getUid
    withTransaction(context) { ctx =>
      if (!userHasWriteAccess(ctx, aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }
      val repositoryName = getAssetByID(ctx, aid).getRepositoryName

      // Decode the file path
      val filePath = URLDecoder.decode(encodedFilePath, StandardCharsets.UTF_8.name())
      // Try to delete the file in LakeFS
      try {
        LakeFSStorageClient.deleteObject(repositoryName, filePath)
      } catch {
        case e: Exception =>
          throw new WebApplicationException(
            s"Failed to delete the file from repo in LakeFS: ${e.getMessage}"
          )
      }

      Response.ok().build()
    }
  }

  @POST
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/multipart-upload")
  @Consumes(Array(MediaType.APPLICATION_JSON))
  def multipartUpload(
      @QueryParam("type") operationType: String,
      @QueryParam("ownerEmail") ownerEmail: String,
      @QueryParam("name") assetName: String,
      @QueryParam("filePath") filePath: String,
      @QueryParam("fileSizeBytes") fileSizeBytes: Optional[java.lang.Long],
      @QueryParam("partSizeBytes") partSizeBytes: Optional[java.lang.Long],
      @QueryParam("restart") restart: Optional[java.lang.Boolean],
      @Auth user: SessionUser
  ): Response = {
    val uid = user.getUid
    val asset: Asset = getAssetBy(ownerEmail, assetName)

    operationType.toLowerCase match {
      case "list" => listMultipartUploads(asset.getAid, uid)
      case "init" =>
        initMultipartUpload(asset.getAid, filePath, fileSizeBytes, partSizeBytes, restart, uid)
      case "finish" => finishMultipartUpload(asset.getAid, filePath, uid)
      case "abort"  => abortMultipartUpload(asset.getAid, filePath, uid)
      case _ =>
        throw new BadRequestException("Invalid type parameter. Use 'init', 'finish', or 'abort'.")
    }
  }

  @POST
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Consumes(Array(MediaType.APPLICATION_OCTET_STREAM))
  @Path("/multipart-upload/part")
  def uploadPart(
      @QueryParam("ownerEmail") assetOwnerEmail: String,
      @QueryParam("name") assetName: String,
      @QueryParam("filePath") encodedFilePath: String,
      @QueryParam("partNumber") partNumber: Int,
      partStream: InputStream,
      @Context headers: HttpHeaders,
      @Auth user: SessionUser
  ): Response = {

    val uid = user.getUid
    val asset: Asset = getAssetBy(assetOwnerEmail, assetName)
    val aid = asset.getAid

    if (encodedFilePath == null || encodedFilePath.isEmpty)
      throw new BadRequestException("filePath is required")
    if (partNumber < 1)
      throw new BadRequestException("partNumber must be >= 1")

    val filePath = validateAndNormalizeFilePathOrThrow(
      URLDecoder.decode(encodedFilePath, StandardCharsets.UTF_8.name())
    )

    val contentLength =
      Option(headers.getHeaderString(HttpHeaders.CONTENT_LENGTH))
        .map(_.trim)
        .flatMap(s => Try(s.toLong).toOption)
        .filter(_ > 0)
        .getOrElse {
          throw new BadRequestException("Invalid/Missing Content-Length")
        }

    withTransaction(context) { ctx =>
      if (!userHasWriteAccess(ctx, aid, uid))
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)

      val session = ctx
        .selectFrom(ASSET_UPLOAD_SESSION)
        .where(
          ASSET_UPLOAD_SESSION.UID
            .eq(uid)
            .and(ASSET_UPLOAD_SESSION.AID.eq(aid))
            .and(ASSET_UPLOAD_SESSION.FILE_PATH.eq(filePath))
        )
        .fetchOne()

      if (session == null)
        throw new NotFoundException("Upload session not found. Call type=init first.")

      val expectedParts: Int = session.getNumPartsRequested
      val fileSizeBytesValue: Long = session.getFileSizeBytes
      val partSizeBytesValue: Long = session.getPartSizeBytes

      if (fileSizeBytesValue <= 0L) {
        throw new WebApplicationException(
          s"Upload session has an invalid file size of $fileSizeBytesValue. Restart the upload.",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }
      if (partSizeBytesValue <= 0L) {
        throw new WebApplicationException(
          s"Upload session has an invalid part size of $partSizeBytesValue. Restart the upload.",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }

      // lastPartSize = fileSize - partSize*(expectedParts-1)
      val nMinus1: Long = expectedParts.toLong - 1L
      if (nMinus1 < 0L) {
        throw new WebApplicationException(
          s"Upload session has an invalid number of requested parts of $expectedParts. Restart the upload.",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }
      if (nMinus1 > 0L && partSizeBytesValue > Long.MaxValue / nMinus1) {
        throw new WebApplicationException(
          "Overflow while computing last part size",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }
      val prefixBytes: Long = partSizeBytesValue * nMinus1
      if (prefixBytes > fileSizeBytesValue) {
        throw new WebApplicationException(
          s"Upload session is invalid: computed bytes before last part ($prefixBytes) exceed declared file size ($fileSizeBytesValue). Restart the upload.",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }
      val lastPartSize: Long = fileSizeBytesValue - prefixBytes
      if (lastPartSize <= 0L || lastPartSize > partSizeBytesValue) {
        throw new WebApplicationException(
          s"Upload session is invalid: computed last part size ($lastPartSize bytes) must be within 1..$partSizeBytesValue bytes. Restart the upload.",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }

      val allowedSize: Long =
        if (partNumber < expectedParts) partSizeBytesValue else lastPartSize

      if (partNumber > expectedParts) {
        throw new BadRequestException(
          s"$partNumber exceeds the requested parts on init: $expectedParts"
        )
      }

      if (partNumber < expectedParts && contentLength < MINIMUM_NUM_OF_MULTIPART_S3_PART) {
        throw new BadRequestException(
          s"Part $partNumber is too small ($contentLength bytes). " +
            s"All non-final parts must be >= $MINIMUM_NUM_OF_MULTIPART_S3_PART bytes."
        )
      }

      if (contentLength != allowedSize) {
        throw new BadRequestException(
          s"Invalid part size for partNumber=$partNumber. " +
            s"Expected Content-Length=$allowedSize, got $contentLength."
        )
      }

      val physicalAddr = Option(session.getPhysicalAddress).map(_.trim).getOrElse("")
      if (physicalAddr.isEmpty) {
        throw new WebApplicationException(
          "Upload session is missing physicalAddress. Restart the upload.",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }

      val uploadId = session.getUploadId
      val (bucket, key) =
        try LakeFSStorageClient.parsePhysicalAddress(physicalAddr)
        catch {
          case e: IllegalArgumentException =>
            throw new WebApplicationException(
              s"Upload session has invalid physicalAddress. Restart the upload. (${e.getMessage})",
              Response.Status.INTERNAL_SERVER_ERROR
            )
        }

      // Per-part lock: if another request is streaming the same part, fail fast.
      val partRow =
        try {
          ctx
            .selectFrom(ASSET_UPLOAD_SESSION_PART)
            .where(
              ASSET_UPLOAD_SESSION_PART.UPLOAD_ID
                .eq(uploadId)
                .and(ASSET_UPLOAD_SESSION_PART.PART_NUMBER.eq(partNumber))
            )
            .forUpdate()
            .noWait()
            .fetchOne()
        } catch {
          case e: DataAccessException
              if Option(e.getCause)
                .collect { case s: SQLException => s.getSQLState }
                .contains("55P03") =>
            throw new WebApplicationException(
              s"Part $partNumber is already being uploaded",
              Response.Status.CONFLICT
            )
        }

      if (partRow == null) {
        // Should not happen if init pre-created rows
        throw new WebApplicationException(
          s"Part row not initialized for part $partNumber. Restart the upload.",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }

      // Idempotency: if ETag already set, accept the retry quickly.
      val existing = Option(partRow.getEtag).map(_.trim).getOrElse("")
      if (existing.isEmpty) {
        // Stream to S3 while holding the part lock (prevents concurrent streams for same part)
        val response: UploadPartResponse =
          S3StorageClient.uploadPartWithRequest(
            bucket = bucket,
            key = key,
            uploadId = uploadId,
            partNumber = partNumber,
            inputStream = partStream,
            contentLength = Some(contentLength)
          )

        val etagClean = Option(response.eTag()).map(_.replace("\"", "")).map(_.trim).getOrElse("")
        if (etagClean.isEmpty) {
          throw new WebApplicationException(
            s"Missing ETag returned from S3 for part $partNumber",
            Response.Status.INTERNAL_SERVER_ERROR
          )
        }

        ctx
          .update(ASSET_UPLOAD_SESSION_PART)
          .set(ASSET_UPLOAD_SESSION_PART.ETAG, etagClean)
          .where(
            ASSET_UPLOAD_SESSION_PART.UPLOAD_ID
              .eq(uploadId)
              .and(ASSET_UPLOAD_SESSION_PART.PART_NUMBER.eq(partNumber))
          )
          .execute()
      }
      Response.ok().build()
    }
  }

  @POST
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/update/publicity")
  def toggleAssetPublicity(
      @PathParam("aid") aid: Integer,
      @Auth sessionUser: SessionUser
  ): Response = {
    withTransaction(context) { ctx =>
      val assetDao = new AssetDao(ctx.configuration())
      val uid = sessionUser.getUid

      if (!userHasWriteAccess(ctx, aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }

      val existedAsset = getAssetByID(ctx, aid)
      val newPublicStatus = !existedAsset.getIsPublic
      existedAsset.setIsPublic(newPublicStatus)

      assetDao.update(existedAsset)
      Response.ok().build()
    }
  }

  @POST
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/update/downloadable")
  def toggleAssetDownloadable(
      @PathParam("aid") aid: Integer,
      @Auth sessionUser: SessionUser
  ): Response = {
    withTransaction(context) { ctx =>
      val assetDao = new AssetDao(ctx.configuration())
      val uid = sessionUser.getUid

      if (!userOwnAsset(ctx, aid, uid)) {
        throw new ForbiddenException("Only asset owners can modify download permissions")
      }

      val existedAsset = getAssetByID(ctx, aid)
      val newDownloadableStatus = !existedAsset.getIsDownloadable

      existedAsset.setIsDownloadable(newDownloadableStatus)

      assetDao.update(existedAsset)
      Response.ok().build()
    }
  }

  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/diff")
  def getAssetDiff(
      @PathParam("aid") aid: Integer,
      @Auth user: SessionUser
  ): List[Diff] = {
    val uid = user.getUid
    withTransaction(context) { ctx =>
      if (!userHasReadAccess(ctx, aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }

      // Retrieve staged (uncommitted) changes from LakeFS
      val asset = getAssetByID(ctx, aid)
      val lakefsDiffs = withLakeFSErrorHandling {
        LakeFSStorageClient.retrieveUncommittedObjects(asset.getRepositoryName)
      }

      // Convert LakeFS Diff objects to our custom Diff case class
      lakefsDiffs.map(d =>
        new Diff(
          d.getPath,
          d.getPathType.getValue,
          d.getType.getValue,
          Option(d.getSizeBytes).map(_.longValue())
        )
      )
    }
  }

  @PUT
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/diff")
  @Consumes(Array(MediaType.APPLICATION_JSON))
  def resetAssetFileDiff(
      @PathParam("aid") aid: Integer,
      @QueryParam("filePath") encodedFilePath: String,
      @Auth user: SessionUser
  ): Response = {
    val uid = user.getUid
    withTransaction(context) { ctx =>
      if (!userHasWriteAccess(ctx, aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }
      val repositoryName = getAssetByID(ctx, aid).getRepositoryName

      // Decode the file path
      val filePath = URLDecoder.decode(encodedFilePath, StandardCharsets.UTF_8.name())
      // Try to reset the file change in LakeFS
      try {
        LakeFSStorageClient.resetObjectUploadOrDeletion(repositoryName, filePath)
      } catch {
        case e: Exception =>
          throw new WebApplicationException(
            s"Failed to reset the changes from repo in LakeFS: ${e.getMessage}"
          )
      }
      Response.ok().build()
    }
  }

  /**
    * This method returns a list of DashboardAsset objects that are accessible by current user.
    *
    * @param user the session user
    * @return list of user accessible DashboardAsset objects
    */
  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/list")
  def listAssets(
      @Auth user: SessionUser
  ): List[DashboardAsset] = {
    val uid = user.getUid
    withTransaction(context)(ctx => {
      var accessibleAssets: ListBuffer[DashboardAsset] = ListBuffer()
      // first fetch all assets user have explicit access to
      accessibleAssets = ListBuffer.from(
        ctx
          .select()
          .from(
            ASSET
              .leftJoin(ASSET_USER_ACCESS)
              .on(ASSET_USER_ACCESS.AID.eq(ASSET.AID))
              .leftJoin(USER)
              .on(USER.UID.eq(ASSET.OWNER_UID))
          )
          .where(ASSET_USER_ACCESS.UID.eq(uid))
          .fetch()
          .map(record => {
            val asset = record.into(ASSET).into(classOf[Asset])
            val assetAccess = record.into(ASSET_USER_ACCESS).into(classOf[AssetUserAccess])
            val ownerEmail = record.into(USER).getEmail
            DashboardAsset(
              isOwner = asset.getOwnerUid == uid,
              asset = asset,
              accessPrivilege = assetAccess.getPrivilege,
              ownerEmail = ownerEmail,
              size = 0
            )
          })
          .asScala
      )

      // then we fetch the public assets and merge it as a part of the result if not exist
      val publicAssets = ctx
        .select()
        .from(
          ASSET
            .leftJoin(USER)
            .on(USER.UID.eq(ASSET.OWNER_UID))
        )
        .where(ASSET.IS_PUBLIC.eq(true))
        .fetch()
        .map(record => {
          val asset = record.into(ASSET).into(classOf[Asset])
          val ownerEmail = record.into(USER).getEmail
          DashboardAsset(
            isOwner = false,
            asset = asset,
            accessPrivilege = PrivilegeEnum.READ,
            ownerEmail = ownerEmail,
            size = LakeFSStorageClient.retrieveRepositorySize(asset.getRepositoryName)
          )
        })
      publicAssets.forEach { publicAsset =>
        if (!accessibleAssets.exists(_.asset.getAid == publicAsset.asset.getAid)) {
          val dashboardAsset = DashboardAsset(
            isOwner = false,
            asset = publicAsset.asset,
            ownerEmail = publicAsset.ownerEmail,
            accessPrivilege = PrivilegeEnum.READ,
            size =
              LakeFSStorageClient.retrieveRepositorySize(publicAsset.asset.getRepositoryName)
          )
          accessibleAssets = accessibleAssets :+ dashboardAsset
        }
      }
      accessibleAssets.toList
    })
  }

  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/version/list")
  def getAssetVersionList(
      @PathParam("aid") aid: Integer,
      @Auth user: SessionUser
  ): List[AssetVersion] = {
    val uid = user.getUid
    withTransaction(context)(ctx => {
      val asset = getAssetByID(ctx, aid)
      if (!userHasReadAccess(ctx, asset.getAid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }
      fetchAssetVersions(ctx, asset.getAid)
    })
  }

  @GET
  @Path("/{name}/publicVersion/list")
  def getPublicAssetVersionList(
      @PathParam("name") aid: Integer
  ): List[AssetVersion] = {
    withTransaction(context)(ctx => {
      if (!isAssetPublic(ctx, aid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }
      fetchAssetVersions(ctx, aid)
    })
  }

  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/version/latest")
  def retrieveLatestAssetVersion(
      @PathParam("aid") aid: Integer,
      @Auth user: SessionUser
  ): DashboardAssetVersion = {
    val uid = user.getUid
    withTransaction(context)(ctx => {
      if (!userHasReadAccess(ctx, aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }
      val asset = getAssetByID(ctx, aid)
      val latestVersion = getLatestAssetVersion(ctx, aid).getOrElse(
        throw new NotFoundException(ERR_ASSET_VERSION_NOT_FOUND_MESSAGE)
      )

      val resourceTypeNode = AssetFileNode
        .fromLakeFSRepositoryCommittedObjects(
          Map(
            (resourceTypePrefix(asset.getType), user.getEmail, asset.getName, latestVersion.getName) -> LakeFSStorageClient
              .retrieveObjectsOfVersion(asset.getRepositoryName, latestVersion.getVersionHash)
          )
        )
        .head

      val ownerNode = resourceTypeNode.children.get.head

      DashboardAssetVersion(
        latestVersion,
        ownerNode.children.get
          .find(_.getName == asset.getName)
          .head
          .children
          .get
          .find(_.getName == latestVersion.getName)
          .head
          .children
          .get
      )
    })
  }

  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/versionZip")
  def getAssetVersionZip(
      @PathParam("aid") aid: Integer,
      @QueryParam("avid") avid: Integer, // Asset version ID, nullable
      @QueryParam("latest") latest: java.lang.Boolean, // Flag to get latest version, nullable
      @Auth user: SessionUser
  ): Response = {

    withTransaction(context) { ctx =>
      if ((avid != null && latest != null) || (avid == null && latest == null)) {
        throw new BadRequestException("Specify exactly one: avid=<ID> OR latest=true")
      }

      // Check read access and download permission
      val uid = user.getUid
      if (!userHasReadAccess(ctx, aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }

      // Retrieve asset and check download permission
      val asset = getAssetByID(ctx, aid)
      // Non-owners can download if asset is downloadable and they have read access
      if (!userOwnAsset(ctx, aid, uid) && !asset.getIsDownloadable) {
        throw new ForbiddenException("Asset download is not allowed")
      }

      // Determine which version to retrieve
      val assetVersion = if (avid != null) {
        getAssetVersionByID(ctx, avid)
      } else if (java.lang.Boolean.TRUE.equals(latest)) {
        getLatestAssetVersion(ctx, aid).getOrElse(
          throw new NotFoundException(ERR_ASSET_VERSION_NOT_FOUND_MESSAGE)
        )
      } else {
        throw new BadRequestException("Invalid parameters")
      }

      // Retrieve asset and version details
      val repoName = asset.getName
      val repositoryName = asset.getRepositoryName
      val versionHash = assetVersion.getVersionHash
      val objects = LakeFSStorageClient.retrieveObjectsOfVersion(repositoryName, versionHash)

      if (objects.isEmpty) {
        return Response
          .status(Response.Status.NOT_FOUND)
          .entity(s"No objects found in version $versionHash of asset $repositoryName")
          .build()
      }

      // StreamingOutput for ZIP download
      val streamingOutput = new StreamingOutput {
        override def write(outputStream: OutputStream): Unit = {
          val zipOut = new ZipOutputStream(outputStream)
          try {
            objects.foreach { obj =>
              val filePath = obj.getPath
              val file = LakeFSStorageClient.getFileFromRepo(repositoryName, versionHash, filePath)

              zipOut.putNextEntry(new ZipEntry(filePath))
              Files.copy(Paths.get(file.toURI), zipOut)
              zipOut.closeEntry()
            }
          } finally {
            zipOut.close()
          }
        }
      }

      val zipFilename = s"""attachment; filename="$repoName-${assetVersion.getName}.zip""""

      Response
        .ok(streamingOutput, "application/zip")
        .header("Content-Disposition", zipFilename)
        .build()
    }
  }

  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/version/{avid}/rootFileNodes")
  def retrieveAssetVersionRootFileNodes(
      @PathParam("aid") aid: Integer,
      @PathParam("avid") avid: Integer,
      @Auth user: SessionUser
  ): AssetVersionRootFileNodesResponse = {
    val uid = user.getUid
    withTransaction(context)(ctx => fetchAssetVersionRootFileNodes(ctx, aid, avid, Some(uid)))
  }

  @GET
  @Path("/{aid}/publicVersion/{avid}/rootFileNodes")
  def retrievePublicAssetVersionRootFileNodes(
      @PathParam("aid") aid: Integer,
      @PathParam("avid") avid: Integer
  ): AssetVersionRootFileNodesResponse = {
    withTransaction(context)(ctx => fetchAssetVersionRootFileNodes(ctx, aid, avid, None))
  }

  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}")
  def getAsset(
      @PathParam("aid") aid: Integer,
      @Auth user: SessionUser
  ): DashboardAsset = {
    val uid = user.getUid
    withTransaction(context)(ctx => getDashboardAsset(ctx, aid, Some(uid)))
  }

  @GET
  @Path("/public/{aid}")
  def getPublicAsset(
      @PathParam("aid") aid: Integer
  ): DashboardAsset = {
    withTransaction(context)(ctx => getDashboardAsset(ctx, aid, None))
  }

  /**
    * This method returns all owner user names of the asset that the user has access to
    *
    * @return OwnerName[]
    */
  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/user-asset-owners")
  def retrieveOwners(@Auth user: SessionUser): util.List[String] = {
    context
      .selectDistinct(USER.EMAIL)
      .from(USER)
      .join(ASSET)
      .on(ASSET.OWNER_UID.eq(USER.UID))
      .join(ASSET_USER_ACCESS)
      .on(ASSET_USER_ACCESS.AID.eq(ASSET.AID))
      .where(ASSET_USER_ACCESS.UID.eq(user.getUid))
      .fetchInto(classOf[String])
  }

  /**
    * Validates the asset name.
    *
    * Rules:
    * - Must be at least 1 character long.
    * - Only lowercase letters, numbers, underscores, and hyphens are allowed.
    * - Cannot start with a hyphen.
    *
    * @param name The asset name to validate.
    * @throws IllegalArgumentException if the name is invalid.
    */
  private def validateAssetName(name: String): Unit = {
    val assetNamePattern = "^[A-Za-z0-9_-]+$".r
    if (!assetNamePattern.matches(name)) {
      throw new IllegalArgumentException(
        s"Invalid asset name: '$name'. " +
          "Asset names must be at least 1 character long and " +
          "contain only lowercase letters, numbers, underscores, and hyphens, " +
          "and cannot start with a hyphen."
      )
    }
  }

  private def fetchAssetVersions(ctx: DSLContext, aid: Integer): List[AssetVersion] = {
    ctx
      .selectFrom(ASSET_VERSION)
      .where(ASSET_VERSION.AID.eq(aid))
      .orderBy(ASSET_VERSION.CREATION_TIME.desc()) // Change to .asc() for ascending order
      .fetchInto(classOf[AssetVersion])
      .asScala
      .toList
  }

  private def fetchAssetVersionRootFileNodes(
      ctx: DSLContext,
      aid: Integer,
      avid: Integer,
      uid: Option[Integer]
  ): AssetVersionRootFileNodesResponse = {
    val dashboardAsset = getDashboardAsset(ctx, aid, uid)
    val assetVersion = getAssetVersionByID(ctx, avid)
    val repoName = dashboardAsset.asset.getName
    val repositoryName = dashboardAsset.asset.getRepositoryName

    val resourceTypeNode = AssetFileNode
      .fromLakeFSRepositoryCommittedObjects(
        Map(
          (resourceTypePrefix(dashboardAsset.asset.getType), dashboardAsset.ownerEmail, repoName, assetVersion.getName) -> LakeFSStorageClient
            .retrieveObjectsOfVersion(repositoryName, assetVersion.getVersionHash)
        )
      )
      .head

    val ownerFileNode = resourceTypeNode.children.get.head

    AssetVersionRootFileNodesResponse(
      ownerFileNode.children.get
        .find(_.getName == repoName)
        .head
        .children
        .get
        .find(_.getName == assetVersion.getName)
        .head
        .children
        .get,
      AssetFileNode.calculateTotalSize(List(resourceTypeNode))
    )
  }

  private def generatePresignedResponse(
      encodedUrl: String,
      repositoryName: String,
      commitHash: String,
      uid: Integer
  ): Response = {
    resolveAssetAndPath(encodedUrl, repositoryName, commitHash, uid) match {
      case Left(errorResponse) =>
        errorResponse

      case Right((resolvedRepositoryName, resolvedCommitHash, resolvedFilePath)) =>
        val url = LakeFSStorageClient.getFilePresignedUrl(
          resolvedRepositoryName,
          resolvedCommitHash,
          resolvedFilePath
        )

        Response.ok(Map("presignedUrl" -> url)).build()
    }
  }

  private def resolveAssetAndPath(
      encodedUrl: String,
      repositoryName: String,
      commitHash: String,
      uid: Integer
  ): Either[Response, (String, String, String)] = {
    val decodedPathStr = URLDecoder.decode(encodedUrl, StandardCharsets.UTF_8.name())

    (Option(repositoryName), Option(commitHash)) match {
      case (Some(_), None) | (None, Some(_)) =>
        // Case 1: Only one parameter is provided (error case)
        Left(
          Response
            .status(Response.Status.BAD_REQUEST)
            .entity(
              "Both repositoryName and commitHash must be provided together, or neither should be provided."
            )
            .build()
        )

      case (Some(repositoryName), Some(commit)) =>
        // Case 2: repositoryName and commitHash are provided, validate access
        val response = withTransaction(context) { ctx =>
          val assetDao = new AssetDao(ctx.configuration())
          val assets = assetDao.fetchByRepositoryName(repositoryName).asScala.toList

          if (assets.isEmpty || !userHasReadAccess(ctx, assets.head.getAid, uid))
            throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)

          val asset = assets.head
          // Standard read access check only - download restrictions handled per endpoint
          // Non-download operations (viewing) should work for all public assets

          (repositoryName, commit, decodedPathStr)
        }
        Right(response)

      case (None, None) =>
        // Case 3: Neither repositoryName nor commitHash are provided, resolve normally
        val response = withTransaction(context) { ctx =>
          val fileUri = FileResolver.resolve(decodedPathStr)
          val document = DocumentFactory.openReadonlyDocument(fileUri).asInstanceOf[OnAsset]
          val assetDao = new AssetDao(ctx.configuration())
          val assets =
            assetDao.fetchByRepositoryName(document.getRepositoryName()).asScala.toList

          if (assets.isEmpty || !userHasReadAccess(ctx, assets.head.getAid, uid))
            throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)

          val asset = assets.head
          // Standard read access check only - download restrictions handled per endpoint
          // Non-download operations (viewing) should work for all public assets

          (
            document.getRepositoryName(),
            document.getVersionHash(),
            document.getFileRelativePath()
          )
        }
        Right(response)
    }
  }

  // === Multipart helpers ===

  private def getAssetBy(ownerEmail: String, assetName: String) = {
    val asset = context
      .select(ASSET.fields: _*)
      .from(ASSET)
      .leftJoin(USER)
      .on(USER.UID.eq(ASSET.OWNER_UID))
      .where(USER.EMAIL.eq(ownerEmail))
      .and(ASSET.NAME.eq(assetName))
      .fetchOneInto(classOf[Asset])
    if (asset == null) {
      throw new BadRequestException("Asset not found")
    }
    asset
  }

  private def listMultipartUploads(aid: Integer, requesterUid: Int): Response = {
    withTransaction(context) { ctx =>
      if (!userHasWriteAccess(ctx, aid, requesterUid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }

      val filePaths =
        ctx
          .selectDistinct(ASSET_UPLOAD_SESSION.FILE_PATH)
          .from(ASSET_UPLOAD_SESSION)
          .where(ASSET_UPLOAD_SESSION.AID.eq(aid))
          .and(
            DSL.condition(
              "created_at > current_timestamp - (? * interval '1 hour')",
              PHYSICAL_ADDRESS_EXPIRATION_TIME_HRS
            )
          )
          .orderBy(ASSET_UPLOAD_SESSION.FILE_PATH.asc())
          .fetch(ASSET_UPLOAD_SESSION.FILE_PATH)
          .asScala
          .toList

      Response.ok(Map("filePaths" -> filePaths.asJava)).build()
    }
  }

  private def initMultipartUpload(
      aid: Integer,
      encodedFilePath: String,
      fileSizeBytes: Optional[java.lang.Long],
      partSizeBytes: Optional[java.lang.Long],
      restart: Optional[java.lang.Boolean],
      uid: Integer
  ): Response = {

    withTransaction(context) { ctx =>
      if (!userHasWriteAccess(ctx, aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }

      val asset = getAssetByID(ctx, aid)
      val repositoryName = asset.getRepositoryName

      val filePath =
        validateAndNormalizeFilePathOrThrow(
          URLDecoder.decode(encodedFilePath, StandardCharsets.UTF_8.name())
        )

      if (fileSizeBytes == null || !fileSizeBytes.isPresent)
        throw new BadRequestException("fileSizeBytes is required for initialization")
      if (partSizeBytes == null || !partSizeBytes.isPresent)
        throw new BadRequestException("partSizeBytes is required for initialization")

      val fileSizeBytesValue: Long = fileSizeBytes.get.longValue()
      val partSizeBytesValue: Long = partSizeBytes.get.longValue()

      if (fileSizeBytesValue <= 0L) throw new BadRequestException("fileSizeBytes must be > 0")
      if (partSizeBytesValue <= 0L) throw new BadRequestException("partSizeBytes must be > 0")

      val totalMaxBytes: Long = singleFileUploadMaxBytes(ctx)
      if (totalMaxBytes <= 0L) {
        throw new WebApplicationException(
          "singleFileUploadMaxBytes must be > 0",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }
      if (fileSizeBytesValue > totalMaxBytes) {
        throw new BadRequestException(
          s"fileSizeBytes=$fileSizeBytesValue exceeds singleFileUploadMaxBytes=$totalMaxBytes"
        )
      }

      val addend: Long = partSizeBytesValue - 1L
      if (addend < 0L || fileSizeBytesValue > Long.MaxValue - addend) {
        throw new WebApplicationException(
          "Overflow while computing numParts",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }

      val numPartsLong: Long = (fileSizeBytesValue + addend) / partSizeBytesValue
      if (numPartsLong < 1L || numPartsLong > MAXIMUM_NUM_OF_MULTIPART_S3_PARTS.toLong) {
        throw new BadRequestException(
          s"Computed numParts=$numPartsLong is out of range 1..$MAXIMUM_NUM_OF_MULTIPART_S3_PARTS"
        )
      }
      val computedNumParts: Int = numPartsLong.toInt

      if (computedNumParts > 1 && partSizeBytesValue < MINIMUM_NUM_OF_MULTIPART_S3_PART) {
        throw new BadRequestException(
          s"partSizeBytes=$partSizeBytesValue is too small. " +
            s"All non-final parts must be >= $MINIMUM_NUM_OF_MULTIPART_S3_PART bytes."
        )
      }
      var session: AssetUploadSessionRecord = null
      var rows: Result[Record2[Integer, String]] = null
      try {
        session = ctx
          .selectFrom(ASSET_UPLOAD_SESSION)
          .where(
            ASSET_UPLOAD_SESSION.UID
              .eq(uid)
              .and(ASSET_UPLOAD_SESSION.AID.eq(aid))
              .and(ASSET_UPLOAD_SESSION.FILE_PATH.eq(filePath))
          )
          .forUpdate()
          .noWait()
          .fetchOne()
        if (session != null) {
          //Gain parts lock
          rows = ctx
            .select(ASSET_UPLOAD_SESSION_PART.PART_NUMBER, ASSET_UPLOAD_SESSION_PART.ETAG)
            .from(ASSET_UPLOAD_SESSION_PART)
            .where(ASSET_UPLOAD_SESSION_PART.UPLOAD_ID.eq(session.getUploadId))
            .forUpdate()
            .noWait()
            .fetch()
          val dbFileSize = session.getFileSizeBytes
          val dbPartSize = session.getPartSizeBytes
          val dbNumParts = session.getNumPartsRequested
          val createdAt: OffsetDateTime = session.getCreatedAt

          val isExpired =
            createdAt
              .plusHours(PHYSICAL_ADDRESS_EXPIRATION_TIME_HRS.toLong)
              .isBefore(OffsetDateTime.now(createdAt.getOffset)) // or OffsetDateTime.now()

          val conflictConfig =
            dbFileSize != fileSizeBytesValue ||
              dbPartSize != partSizeBytesValue ||
              dbNumParts != computedNumParts ||
              isExpired ||
              Option(restart).exists(_.orElse(false))

          if (conflictConfig) {
            // Parts will be deleted automatically (ON DELETE CASCADE)
            ctx
              .deleteFrom(ASSET_UPLOAD_SESSION)
              .where(ASSET_UPLOAD_SESSION.UPLOAD_ID.eq(session.getUploadId))
              .execute()

            try {
              LakeFSStorageClient.abortPresignedMultipartUploads(
                repositoryName,
                filePath,
                session.getUploadId,
                session.getPhysicalAddress
              )
            } catch { case _: Throwable => () }
            session = null
            rows = null
          }
        }
      } catch {
        case e: DataAccessException
            if Option(e.getCause)
              .collect { case s: SQLException => s.getSQLState }
              .contains("55P03") =>
          throw new WebApplicationException(
            "Another client is uploading this file",
            Response.Status.CONFLICT
          )
      }

      if (session == null) {
        val presign = withLakeFSErrorHandling {
          LakeFSStorageClient.initiatePresignedMultipartUploads(
            repositoryName,
            filePath,
            computedNumParts
          )
        }

        val uploadIdStr = presign.getUploadId
        val physicalAddr = presign.getPhysicalAddress

        try {
          val rowsInserted = ctx
            .insertInto(ASSET_UPLOAD_SESSION)
            .set(ASSET_UPLOAD_SESSION.FILE_PATH, filePath)
            .set(ASSET_UPLOAD_SESSION.AID, aid)
            .set(ASSET_UPLOAD_SESSION.UID, uid)
            .set(ASSET_UPLOAD_SESSION.UPLOAD_ID, uploadIdStr)
            .set(ASSET_UPLOAD_SESSION.PHYSICAL_ADDRESS, physicalAddr)
            .set(ASSET_UPLOAD_SESSION.NUM_PARTS_REQUESTED, Integer.valueOf(computedNumParts))
            .set(ASSET_UPLOAD_SESSION.FILE_SIZE_BYTES, java.lang.Long.valueOf(fileSizeBytesValue))
            .set(ASSET_UPLOAD_SESSION.PART_SIZE_BYTES, java.lang.Long.valueOf(partSizeBytesValue))
            .onDuplicateKeyIgnore()
            .execute()

          if (rowsInserted == 1) {
            val partNumberSeries =
              DSL.generateSeries(1, computedNumParts).asTable("gs", "partNumberField")
            val partNumberField = partNumberSeries.field("partNumberField", classOf[Integer])

            ctx
              .insertInto(
                ASSET_UPLOAD_SESSION_PART,
                ASSET_UPLOAD_SESSION_PART.UPLOAD_ID,
                ASSET_UPLOAD_SESSION_PART.PART_NUMBER,
                ASSET_UPLOAD_SESSION_PART.ETAG
              )
              .select(
                ctx
                  .select(
                    inl(uploadIdStr),
                    partNumberField,
                    inl("")
                  )
                  .from(partNumberSeries)
              )
              .execute()

            session = ctx
              .selectFrom(ASSET_UPLOAD_SESSION)
              .where(
                ASSET_UPLOAD_SESSION.UID
                  .eq(uid)
                  .and(ASSET_UPLOAD_SESSION.AID.eq(aid))
                  .and(ASSET_UPLOAD_SESSION.FILE_PATH.eq(filePath))
              )
              .fetchOne()
          } else {
            try {
              LakeFSStorageClient.abortPresignedMultipartUploads(
                repositoryName,
                filePath,
                uploadIdStr,
                physicalAddr
              )
            } catch { case _: Throwable => () }

            session = ctx
              .selectFrom(ASSET_UPLOAD_SESSION)
              .where(
                ASSET_UPLOAD_SESSION.UID
                  .eq(uid)
                  .and(ASSET_UPLOAD_SESSION.AID.eq(aid))
                  .and(ASSET_UPLOAD_SESSION.FILE_PATH.eq(filePath))
              )
              .fetchOne()
          }
        } catch {
          case e: Exception =>
            try {
              LakeFSStorageClient.abortPresignedMultipartUploads(
                repositoryName,
                filePath,
                uploadIdStr,
                physicalAddr
              )
            } catch { case _: Throwable => () }
            throw e
        }
      }

      if (session == null) {
        throw new WebApplicationException(
          "Failed to create or locate upload session",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }

      val dbNumParts = session.getNumPartsRequested

      val uploadId = session.getUploadId
      val nParts = dbNumParts

      // CHANGED: lock rows with NOWAIT; if any row is locked by another uploader -> 409
      if (rows == null) {
        rows =
          try {
            ctx
              .select(ASSET_UPLOAD_SESSION_PART.PART_NUMBER, ASSET_UPLOAD_SESSION_PART.ETAG)
              .from(ASSET_UPLOAD_SESSION_PART)
              .where(ASSET_UPLOAD_SESSION_PART.UPLOAD_ID.eq(uploadId))
              .forUpdate()
              .noWait()
              .fetch()
          } catch {
            case e: DataAccessException
                if Option(e.getCause)
                  .collect { case s: SQLException => s.getSQLState }
                  .contains("55P03") =>
              throw new WebApplicationException(
                "Another client is uploading parts for this file",
                Response.Status.CONFLICT
              )
          }
      }

      // CHANGED: compute missingParts + completedPartsCount from the SAME query result
      val missingParts = rows.asScala
        .filter(r =>
          Option(r.get(ASSET_UPLOAD_SESSION_PART.ETAG)).map(_.trim).getOrElse("").isEmpty
        )
        .map(r => r.get(ASSET_UPLOAD_SESSION_PART.PART_NUMBER).intValue())
        .toList

      val completedPartsCount = nParts - missingParts.size

      Response
        .ok(
          Map(
            "missingParts" -> missingParts.asJava,
            "completedPartsCount" -> Integer.valueOf(completedPartsCount)
          )
        )
        .build()
    }
  }

  private def finishMultipartUpload(
      aid: Integer,
      encodedFilePath: String,
      uid: Int
  ): Response = {

    val filePath = validateAndNormalizeFilePathOrThrow(
      URLDecoder.decode(encodedFilePath, StandardCharsets.UTF_8.name())
    )

    withTransaction(context) { ctx =>
      if (!userHasWriteAccess(ctx, aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }

      val asset = getAssetByID(ctx, aid)

      // Lock the session so abort/finish don't race each other
      val session =
        try {
          ctx
            .selectFrom(ASSET_UPLOAD_SESSION)
            .where(
              ASSET_UPLOAD_SESSION.UID
                .eq(uid)
                .and(ASSET_UPLOAD_SESSION.AID.eq(aid))
                .and(ASSET_UPLOAD_SESSION.FILE_PATH.eq(filePath))
            )
            .forUpdate()
            .noWait()
            .fetchOne()
        } catch {
          case e: DataAccessException
              if Option(e.getCause)
                .collect { case s: SQLException => s.getSQLState }
                .contains("55P03") =>
            throw new WebApplicationException(
              "Upload is already being finalized/aborted",
              Response.Status.CONFLICT
            )
        }

      if (session == null) {
        throw new NotFoundException("Upload session not found or already finalized")
      }

      val uploadId = session.getUploadId
      val expectedParts = session.getNumPartsRequested

      val physicalAddr = Option(session.getPhysicalAddress).map(_.trim).getOrElse("")
      if (physicalAddr.isEmpty) {
        throw new WebApplicationException(
          "Upload session is missing physicalAddress. Restart the upload.",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }

      val total = DSL.count()
      val done =
        DSL
          .count()
          .filterWhere(ASSET_UPLOAD_SESSION_PART.ETAG.ne(""))
          .as("done")

      val agg = ctx
        .select(total.as("total"), done)
        .from(ASSET_UPLOAD_SESSION_PART)
        .where(ASSET_UPLOAD_SESSION_PART.UPLOAD_ID.eq(uploadId))
        .fetchOne()

      val totalCnt = agg.get("total", classOf[java.lang.Integer]).intValue()
      val doneCnt = agg.get("done", classOf[java.lang.Integer]).intValue()

      if (totalCnt != expectedParts) {
        throw new WebApplicationException(
          s"Part table mismatch: expected $expectedParts rows but found $totalCnt. Restart the upload.",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }

      if (doneCnt != expectedParts) {
        val missing = ctx
          .select(ASSET_UPLOAD_SESSION_PART.PART_NUMBER)
          .from(ASSET_UPLOAD_SESSION_PART)
          .where(
            ASSET_UPLOAD_SESSION_PART.UPLOAD_ID
              .eq(uploadId)
              .and(ASSET_UPLOAD_SESSION_PART.ETAG.eq(""))
          )
          .orderBy(ASSET_UPLOAD_SESSION_PART.PART_NUMBER.asc())
          .limit(50)
          .fetch(ASSET_UPLOAD_SESSION_PART.PART_NUMBER)
          .asScala
          .toList

        throw new WebApplicationException(
          s"Upload incomplete. Some missing ETags for parts are: ${missing.mkString(",")}",
          Response.Status.CONFLICT
        )
      }

      // Build partsList in order
      val partsList: List[(Int, String)] =
        ctx
          .select(ASSET_UPLOAD_SESSION_PART.PART_NUMBER, ASSET_UPLOAD_SESSION_PART.ETAG)
          .from(ASSET_UPLOAD_SESSION_PART)
          .where(ASSET_UPLOAD_SESSION_PART.UPLOAD_ID.eq(uploadId))
          .orderBy(ASSET_UPLOAD_SESSION_PART.PART_NUMBER.asc())
          .fetch()
          .asScala
          .map(r =>
            (
              r.get(ASSET_UPLOAD_SESSION_PART.PART_NUMBER).intValue(),
              r.get(ASSET_UPLOAD_SESSION_PART.ETAG)
            )
          )
          .toList

      val objectStats = withLakeFSErrorHandling {
        LakeFSStorageClient.completePresignedMultipartUploads(
          asset.getRepositoryName,
          filePath,
          uploadId,
          partsList,
          physicalAddr
        )
      }

      // FINAL SERVER-SIDE SIZE CHECK (do not rely on init)
      val actualSizeBytes =
        Option(objectStats.getSizeBytes).map(_.longValue()).getOrElse(-1L)

      if (actualSizeBytes <= 0L) {
        throw new WebApplicationException(
          "lakeFS did not return sizeBytes for completed multipart upload",
          Response.Status.INTERNAL_SERVER_ERROR
        )
      }

      val maxBytes = singleFileUploadMaxBytes(ctx)
      val tooLarge = actualSizeBytes > maxBytes

      if (tooLarge) {
        try {
          LakeFSStorageClient.resetObjectUploadOrDeletion(asset.getRepositoryName, filePath)
        } catch {
          case _: Throwable => ()
        }
      }

      // always cleanup session
      ctx
        .deleteFrom(ASSET_UPLOAD_SESSION)
        .where(
          ASSET_UPLOAD_SESSION.UID
            .eq(uid)
            .and(ASSET_UPLOAD_SESSION.AID.eq(aid))
            .and(ASSET_UPLOAD_SESSION.FILE_PATH.eq(filePath))
        )
        .execute()

      if (tooLarge) {
        throw new WebApplicationException(
          s"Upload exceeded max size: actualSizeBytes=$actualSizeBytes maxBytes=$maxBytes",
          Response.Status.REQUEST_ENTITY_TOO_LARGE
        )
      }

      Response
        .ok(
          Map(
            "message" -> "Multipart upload completed successfully",
            "filePath" -> objectStats.getPath
          )
        )
        .build()
    }
  }

  private def abortMultipartUpload(
      aid: Integer,
      encodedFilePath: String,
      uid: Int
  ): Response = {

    val filePath = validateAndNormalizeFilePathOrThrow(
      URLDecoder.decode(encodedFilePath, StandardCharsets.UTF_8.name())
    )

    val (repoName, uploadId, physicalAddr) = withTransaction(context) { ctx =>
      if (!userHasWriteAccess(ctx, aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }

      val asset = getAssetByID(ctx, aid)

      val session =
        try {
          ctx
            .selectFrom(ASSET_UPLOAD_SESSION)
            .where(
              ASSET_UPLOAD_SESSION.UID
                .eq(uid)
                .and(ASSET_UPLOAD_SESSION.AID.eq(aid))
                .and(ASSET_UPLOAD_SESSION.FILE_PATH.eq(filePath))
            )
            .forUpdate()
            .noWait()
            .fetchOne()
        } catch {
          case e: DataAccessException
              if Option(e.getCause)
                .collect { case s: SQLException => s.getSQLState }
                .contains("55P03") =>
            throw new WebApplicationException(
              "Upload is already being finalized/aborted",
              Response.Status.CONFLICT
            )
        }

      if (session == null) {
        throw new NotFoundException("Upload session not found or already finalized")
      }

      val physicalAddr = Option(session.getPhysicalAddress).map(_.trim).getOrElse("")

      // Delete session; parts removed via ON DELETE CASCADE
      ctx
        .deleteFrom(ASSET_UPLOAD_SESSION)
        .where(
          ASSET_UPLOAD_SESSION.UID
            .eq(uid)
            .and(ASSET_UPLOAD_SESSION.AID.eq(aid))
            .and(ASSET_UPLOAD_SESSION.FILE_PATH.eq(filePath))
        )
        .execute()

      (asset.getRepositoryName, session.getUploadId, physicalAddr)
    }

    withLakeFSErrorHandling {
      LakeFSStorageClient.abortPresignedMultipartUploads(repoName, filePath, uploadId, physicalAddr)
    }

    Response.ok(Map("message" -> "Multipart upload aborted successfully")).build()
  }

  /**
    * Updates the cover image for an asset.
    *
    * @param aid Asset ID
    * @param request Cover image request containing the relative file path
    * @param sessionUser Authenticated user session
    * @return Response with updated cover image path
    *
    * Expected coverImage format: "version/folder/image.jpg" (relative to asset root)
    */
  @POST
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Path("/{aid}/update/cover")
  @Consumes(Array(MediaType.APPLICATION_JSON))
  def updateAssetCoverImage(
      @PathParam("aid") aid: Integer,
      request: CoverImageRequest,
      @Auth sessionUser: SessionUser
  ): Response = {
    withTransaction(context) { ctx =>
      val uid = sessionUser.getUid
      val asset = getAssetByID(ctx, aid)
      if (!userHasWriteAccess(ctx, aid, uid)) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }

      if (request.coverImage == null || request.coverImage.trim.isEmpty) {
        throw new BadRequestException("Cover image path is required")
      }

      val normalized = AssetResource.validateAndNormalizeFilePathOrThrow(request.coverImage)

      val extension = FilenameUtils.getExtension(normalized)
      if (extension == null || !ALLOWED_IMAGE_EXTENSIONS.contains(s".$extension".toLowerCase)) {
        throw new BadRequestException("Invalid file type")
      }

      val owner = getOwner(ctx, aid)
      val document = DocumentFactory
        .openReadonlyDocument(
          FileResolver.resolve(s"${owner.getEmail}/${asset.getName}/$normalized")
        )
        .asInstanceOf[OnAsset]

      val fileSize = LakeFSStorageClient.getFileSize(
        document.getRepositoryName(),
        document.getVersionHash(),
        document.getFileRelativePath()
      )

      if (fileSize > COVER_IMAGE_SIZE_LIMIT_BYTES) {
        throw new BadRequestException(
          s"Cover image must be less than ${COVER_IMAGE_SIZE_LIMIT_BYTES / (1024 * 1024)} MB"
        )
      }

      asset.setCoverImage(normalized)
      new AssetDao(ctx.configuration()).update(asset)
      Response.ok(Map("coverImage" -> normalized)).build()
    }
  }

  /**
    * Get the cover image for an asset.
    * Returns a 307 redirect to the presigned S3 URL.
    *
    * @param aid Asset ID
    * @return 307 Temporary Redirect to cover image
    */
  @GET
  @Path("/{aid}/cover")
  def getAssetCover(
      @PathParam("aid") aid: Integer,
      @Auth sessionUser: Optional[SessionUser]
  ): Response = {
    withTransaction(context) { ctx =>
      val asset = getAssetByID(ctx, aid)

      val requesterUid = if (sessionUser.isPresent) Some(sessionUser.get().getUid) else None

      if (requesterUid.isEmpty && !asset.getIsPublic) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      } else if (requesterUid.exists(uid => !userHasReadAccess(ctx, aid, uid))) {
        throw new ForbiddenException(ERR_USER_HAS_NO_ACCESS_TO_ASSET_MESSAGE)
      }

      val coverImage = Option(asset.getCoverImage).getOrElse(
        throw new NotFoundException("No cover image")
      )

      val owner = getOwner(ctx, aid)
      val fullPath = s"${owner.getEmail}/${asset.getName}/$coverImage"

      val document = DocumentFactory
        .openReadonlyDocument(FileResolver.resolve(fullPath))
        .asInstanceOf[OnAsset]

      val presignedUrl = LakeFSStorageClient.getFilePresignedUrl(
        document.getRepositoryName(),
        document.getVersionHash(),
        document.getFileRelativePath()
      )

      Response.temporaryRedirect(new URI(presignedUrl)).build()
    }
  }
}
