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

import org.apache.commons.vfs2.FileNotFoundException
import org.apache.texera.dao.SqlServer
import org.apache.texera.dao.SqlServer.withTransaction
import org.apache.texera.dao.jooq.generated.tables.Asset.ASSET
import org.apache.texera.dao.jooq.generated.tables.AssetVersion.ASSET_VERSION
import org.apache.texera.dao.jooq.generated.tables.User.USER
import org.apache.texera.dao.jooq.generated.enums.AssetTypeEnum
import org.apache.texera.dao.jooq.generated.tables.pojos.{Asset, AssetVersion}

import java.net.{URI, URLEncoder}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import scala.jdk.CollectionConverters.IteratorHasAsScala
import scala.util.{Success, Try}

/**
  * Unified object for resolving both VFS resources and local/asset files.
  */
object FileResolver {

  val ASSET_FILE_URI_SCHEME = "asset"

  /**
    * Resolves a given fileName to either a file on the local file system or an asset file.
    *
    * @param fileName the name of the file to resolve.
    * @throws FileNotFoundException if the file cannot be resolved.
    * @return A URI pointing to the resolved file.
    */
  def resolve(fileName: String): URI = {
    if (isFileResolved(fileName)) {
      return new URI(fileName)
    }
    val resolvers: Seq[String => URI] = Seq(localResolveFunc, assetResolveFunc)

    // Try each resolver function in sequence
    resolvers
      .map(resolver => Try(resolver(fileName)))
      .collectFirst {
        case Success(output) => output
      }
      .getOrElse(throw new FileNotFoundException(fileName))
  }

  /**
    * Attempts to resolve a local file path.
    * @throws FileNotFoundException if the local file does not exist
    * @param fileName the name of the file to check
    */
  private def localResolveFunc(fileName: String): URI = {
    val filePath = Paths.get(fileName)
    if (!Files.exists(filePath)) {
      throw new FileNotFoundException(s"Local file $fileName does not exist")
    }
    filePath.toUri
  }

  /**
    * Parses an asset file path and extracts its components.
    * Expected format: /resourceType/ownerEmail/repoName/versionName/fileRelativePath
    *   e.g. /datasets/bob@texera.com/twitterDataset/v1/california/irvine/tw1.csv
    *
    * @param fileName The file path to parse
    * @return Some((resourceType, ownerEmail, repoName, versionName, fileRelativePath)) if valid, None otherwise
    */
  private def parseAssetFilePath(
      fileName: String
  ): Option[(String, String, String, String, Array[String])] = {
    val filePath = Paths.get(fileName)
    val pathSegments = (0 until filePath.getNameCount).map(filePath.getName(_).toString).toArray

    if (pathSegments.length < 5) {
      return None
    }

    val resourceType = pathSegments(0)
    val ownerEmail = pathSegments(1)
    val repoName = pathSegments(2)
    val versionName = pathSegments(3)
    val fileRelativePathSegments = pathSegments.drop(4)

    Some((resourceType, ownerEmail, repoName, versionName, fileRelativePathSegments))
  }

  /**
    * Maps a resource type prefix string to the corresponding AssetTypeEnum.
    */
  private def resolveResourceType(resourceType: String): AssetTypeEnum = {
    resourceType match {
      case "datasets" => AssetTypeEnum.dataset
      case "models"   => AssetTypeEnum.model
      case _ =>
        throw new FileNotFoundException(s"Unknown resource type: $resourceType")
    }
  }

  /**
    * Attempts to resolve a given fileName to a URI.
    *
    * The fileName format should be: /resourceType/ownerEmail/repoName/versionName/fileRelativePath
    *   e.g. /datasets/bob@texera.com/twitterDataset/v1/california/irvine/tw1.csv
    * The output asset URI format is: {ASSET_FILE_URI_SCHEME}:///{repositoryName}/{versionHash}/fileRelativePath
    *   e.g. {ASSET_FILE_URI_SCHEME}:///asset-15/adeq233td/some/dir/file.txt
    *
    * @param fileName the name of the file to attempt resolving as an AssetFileDocument
    * @return A URI pointing to the resolved file.
    * @throws FileNotFoundException if the asset file does not exist or cannot be created
    */
  private def assetResolveFunc(fileName: String): URI = {
    val (resourceType, ownerEmail, repoName, versionName, fileRelativePathSegments) =
      parseAssetFilePath(fileName).getOrElse(
        throw new FileNotFoundException(s"Asset file $fileName not found.")
      )

    val assetType = resolveResourceType(resourceType)

    val fileRelativePath =
      Paths.get(fileRelativePathSegments.head, fileRelativePathSegments.tail: _*)

    // fetch the asset and version from DB to get asset ID and version hash
    val (asset, assetVersion) =
      withTransaction(
        SqlServer
          .getInstance()
          .createDSLContext()
      ) { ctx =>
        // fetch the asset from DB
        val asset = ctx
          .select(ASSET.fields: _*)
          .from(ASSET)
          .leftJoin(USER)
          .on(USER.UID.eq(ASSET.OWNER_UID))
          .where(USER.EMAIL.eq(ownerEmail))
          .and(ASSET.NAME.eq(repoName))
          .and(ASSET.TYPE.eq(assetType))
          .fetchOneInto(classOf[Asset])

        // fetch the asset version from DB
        val assetVersion = ctx
          .selectFrom(ASSET_VERSION)
          .where(ASSET_VERSION.AID.eq(asset.getAid))
          .and(ASSET_VERSION.NAME.eq(versionName))
          .fetchOneInto(classOf[AssetVersion])

        if (asset == null || assetVersion == null) {
          throw new FileNotFoundException(s"Asset file $fileName not found.")
        }
        (asset, assetVersion)
      }

    // Convert each segment of fileRelativePath to an encoded String
    val encodedFileRelativePath = fileRelativePath
      .iterator()
      .asScala
      .map { segment =>
        URLEncoder.encode(segment.toString, StandardCharsets.UTF_8)
      }
      .toArray

    // Prepend repository name and versionHash to the encoded path segments
    val allPathSegments = Array(
      asset.getRepositoryName,
      assetVersion.getVersionHash
    ) ++ encodedFileRelativePath

    // Build the format /{repositoryName}/{versionHash}/{fileRelativePath}, both Linux and Windows use forward slash as the splitter
    val uriSplitter = "/"
    val encodedPath = uriSplitter + allPathSegments.mkString(uriSplitter)

    try {
      new URI(ASSET_FILE_URI_SCHEME, "", encodedPath, null)
    } catch {
      case e: Exception =>
        throw new FileNotFoundException(s"Asset file $fileName not found.")
    }
  }

  /**
    * Checks if a given file path has a valid scheme.
    *
    * @param filePath The file path to check.
    * @return `true` if the file path contains a valid scheme, `false` otherwise.
    */
  def isFileResolved(filePath: String): Boolean = {
    try {
      val uri = new URI(filePath)
      uri.getScheme != null && uri.getScheme.nonEmpty
    } catch {
      case _: Exception => false // Invalid URI format
    }
  }

  /**
    * Parses an asset file path to extract resource type, owner email and repository name.
    * Expected format: /resourceType/ownerEmail/repoName/versionName/fileRelativePath
    *
    * @param path The file path from operator properties
    * @return Some((resourceType, ownerEmail, repoName)) if path is valid, None otherwise
    */
  def parseAssetOwnerAndName(path: String): Option[(String, String, String)] = {
    if (path == null) {
      return None
    }
    parseAssetFilePath(path).map {
      case (resourceType, ownerEmail, repoName, _, _) => (resourceType, ownerEmail, repoName)
    }
  }
}