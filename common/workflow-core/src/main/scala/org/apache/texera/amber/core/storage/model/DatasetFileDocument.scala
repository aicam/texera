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

package org.apache.texera.amber.core.storage.model

import com.typesafe.scalalogging.LazyLogging
import org.apache.texera.amber.config.EnvironmentalVariable
import org.apache.texera.amber.core.storage.UserJwtTokenProvider
import org.apache.texera.amber.core.storage.model.DatasetFileDocument.{
  fileServiceGetPresignURLEndpoint,
  fileServiceListDirectoryObjectsEndpoint,
  userJwtToken
}
import org.apache.texera.amber.core.storage.util.LakeFSStorageClient
import org.apache.texera.amber.core.storage.util.dataset.GitVersionControlLocalFileStorage

import java.io.{File, FileOutputStream, InputStream}
import java.net._
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.util.zip.{ZipEntry, ZipOutputStream}
import scala.jdk.CollectionConverters.IteratorHasAsScala

object DatasetFileDocument {
  // The JWT presented to the FileService to read a file. It is the issuing user's per-execution
  // token, bound to the worker's DP thread (see UserJwtTokenProvider); it falls back to the
  // USER_JWT_TOKEN environment variable, and may be empty in local dev / non-CU setups.
  def userJwtToken: String = UserJwtTokenProvider.currentToken

  // The endpoint of getting presigned url from the file service, also stored in the environment vars.
  lazy val fileServiceGetPresignURLEndpoint: String =
    sys.env
      .getOrElse(
        EnvironmentalVariable.ENV_FILE_SERVICE_GET_PRESIGNED_URL_ENDPOINT,
        "http://localhost:9092/api/dataset/presign-download"
      )
      .trim

  // The endpoint for listing directory objects from the file service.
  lazy val fileServiceListDirectoryObjectsEndpoint: String =
    sys.env
      .getOrElse(
        EnvironmentalVariable.ENV_FILE_SERVICE_LIST_DIRECTORY_OBJECTS_ENDPOINT,
        "http://localhost:9092/api/dataset/list-directory-objects"
      )
      .trim
}

private[storage] class DatasetFileDocument(uri: URI, isDirectory: Boolean = false)
    extends VirtualDocument[Nothing]
    with OnDataset
    with LazyLogging {
  // Utility function to parse and decode URI segments into individual components
  private def parseUri(uri: URI): (String, String, Path) = {
    val segments = Paths.get(uri.getPath).iterator().asScala.map(_.toString).toArray
    if (!isDirectory && segments.length < 3)
      throw new IllegalArgumentException("URI format is incorrect")

    // parse uri to dataset components
    val repositoryName = segments(0)
    val datasetVersionHash = URLDecoder.decode(segments(1), StandardCharsets.UTF_8)
    if (isDirectory) {
      return (repositoryName, datasetVersionHash, Paths.get(""))
    }
    val decodedRelativeSegments =
      segments.drop(2).map(part => URLDecoder.decode(part, StandardCharsets.UTF_8))
    val fileRelativePath = Paths.get(decodedRelativeSegments.head, decodedRelativeSegments.tail: _*)

    (repositoryName, datasetVersionHash, fileRelativePath)
  }

  // Extract components from URI using the utility function
  private val (repositoryName, datasetVersionHash, fileRelativePath) = parseUri(uri)

  private var tempFile: Option[File] = None

  override def getURI: URI = uri

  override def asInputStream(): InputStream = {

    def fallbackToLakeFS(exception: Throwable): InputStream = {
      logger.warn(s"${exception.getMessage}. Falling back to LakeFS direct file fetch.", exception)
      val file = LakeFSStorageClient.getFileFromRepo(
        getRepositoryName(),
        getVersionHash(),
        getFileRelativePath()
      )
      Files.newInputStream(file.toPath)
    }

    if (userJwtToken.isEmpty) {
      try {
        val presignUrl = LakeFSStorageClient.getFilePresignedUrl(
          getRepositoryName(),
          getVersionHash(),
          getFileRelativePath()
        )
        new URL(presignUrl).openStream()
      } catch {
        case e: Exception =>
          fallbackToLakeFS(e)
      }
    } else {
      val presignRequestUrl =
        s"$fileServiceGetPresignURLEndpoint?repositoryName=${getRepositoryName()}&commitHash=${getVersionHash()}&filePath=${URLEncoder
          .encode(getFileRelativePath(), StandardCharsets.UTF_8.name())}"

      val connection = new URL(presignRequestUrl).openConnection().asInstanceOf[HttpURLConnection]
      connection.setRequestMethod("GET")
      connection.setRequestProperty("Authorization", s"Bearer $userJwtToken")

      try {
        if (connection.getResponseCode != HttpURLConnection.HTTP_OK) {
          throw new RuntimeException(
            s"Failed to retrieve presigned URL: HTTP ${connection.getResponseCode}"
          )
        }

        // Read response body as a string
        val responseBody =
          new String(connection.getInputStream.readAllBytes(), StandardCharsets.UTF_8)

        // Extract presigned URL from JSON response
        val presignedUrl = responseBody
          .split("\"presignedUrl\"\\s*:\\s*\"")(1)
          .split("\"")(0)

        new URL(presignedUrl).openStream()
      } catch {
        case e: Exception =>
          fallbackToLakeFS(e)
      } finally {
        connection.disconnect()
      }
    }
  }

  override def asFile(): File = {
    tempFile match {
      case Some(file) => file
      case None =>
        if (isDirectory) {
          val tempZipPath = Files.createTempFile("versionedDirectory", ".zip")
          val zipOutputStream = new ZipOutputStream(new FileOutputStream(tempZipPath.toFile))

          try {
            addDirectoryToZip(
              zipOutputStream,
              "",
              getRepositoryName(),
              getVersionHash(),
              fileRelativePath
            )
          } finally {
            zipOutputStream.close()
          }

          val file = tempZipPath.toFile
          tempFile = Some(file)
          file
        } else {
          val tempFilePath = Files.createTempFile("versionedFile", ".tmp")
          val tempFileStream = new FileOutputStream(tempFilePath.toFile)
          val inputStream = asInputStream()

          val buffer = new Array[Byte](1024)

          Iterator
            .continually(inputStream.read(buffer))
            .takeWhile(_ != -1)
            .foreach(tempFileStream.write(buffer, 0, _))

          inputStream.close()
          tempFileStream.close()

          val file = tempFilePath.toFile
          tempFile = Some(file)
          file
        }
    }
  }

  override def clear(): Unit = {
    // first remove the temporary file
    tempFile match {
      case Some(file) => Files.delete(file.toPath)
      case None       => // Do nothing
    }
    lazy val datasetsRootPath =
      Path
        .of(sys.env.getOrElse("TEXERA_HOME", "."))
        .resolve("amber")
        .resolve("user-resources")
        .resolve("datasets")

    def getDatasetPath(did: Integer): Path = {
      datasetsRootPath.resolve(did.toString)
    }

    // then remove the dataset file
    GitVersionControlLocalFileStorage.removeFileFromRepo(
      getDatasetPath(0),
      getDatasetPath(0).resolve(fileRelativePath)
    )
  }

  override def getRepositoryName(): String = repositoryName

  override def getVersionHash(): String = datasetVersionHash

  override def getFileRelativePath(): String = fileRelativePath.toString

  private def addDirectoryToZip(
      zipOutputStream: ZipOutputStream,
      basePath: String,
      datasetName: String,
      versionHash: String,
      directoryPath: Path
  ): Unit = {
    try {
      val allObjects = if (userJwtToken.nonEmpty) {
        getDirectoryObjectsViaFileService(datasetName, versionHash)
      } else {
        LakeFSStorageClient.retrieveObjectsOfVersion(datasetName, versionHash)
      }

      val directoryPathStr = directoryPath.toString.replace("\\", "/")

      val objectsInDirectory = allObjects.filter { obj =>
        val objPath = obj.getPath
        if (directoryPathStr.isEmpty) {
          true
        } else {
          objPath.startsWith(directoryPathStr + "/") || objPath == directoryPathStr
        }
      }

      objectsInDirectory.foreach { obj =>
        val objPath = obj.getPath
        val relativePath = if (directoryPathStr.isEmpty) {
          if (basePath.isEmpty) objPath else s"$basePath/$objPath"
        } else {
          val filePathWithinDirectory = objPath.substring(directoryPathStr.length).stripPrefix("/")
          if (basePath.isEmpty) filePathWithinDirectory else s"$basePath/$filePathWithinDirectory"
        }

        if (relativePath.nonEmpty) {
          val zipEntry = new ZipEntry(relativePath)
          zipOutputStream.putNextEntry(zipEntry)

          val fileInputStream = getFileInputStreamFromLakeFS(datasetName, versionHash, objPath)
          val buffer = new Array[Byte](1024)

          try {
            Iterator
              .continually(fileInputStream.read(buffer))
              .takeWhile(_ != -1)
              .foreach(zipOutputStream.write(buffer, 0, _))
          } finally {
            fileInputStream.close()
          }

          zipOutputStream.closeEntry()
        }
      }
    } catch {
      case e: Exception =>
        logger.warn(
          s"Error adding directory to zip via primary method: ${e.getMessage}. Trying fallback.",
          e
        )
        addDirectoryToZipFallback(zipOutputStream, basePath, datasetName, versionHash, directoryPath)
    }
  }

  private def getDirectoryObjectsViaFileService(
      datasetName: String,
      versionHash: String
  ): List[io.lakefs.clients.sdk.model.ObjectStats] = {
    val requestUrl =
      s"$fileServiceListDirectoryObjectsEndpoint?datasetName=${URLEncoder.encode(datasetName, StandardCharsets.UTF_8.name())}&commitHash=${URLEncoder
        .encode(versionHash, StandardCharsets.UTF_8.name())}"

    val connection = new URL(requestUrl).openConnection().asInstanceOf[HttpURLConnection]
    connection.setRequestMethod("GET")
    connection.setRequestProperty("Authorization", s"Bearer $userJwtToken")

    try {
      if (connection.getResponseCode != HttpURLConnection.HTTP_OK) {
        throw new RuntimeException(
          s"Failed to list directory objects: HTTP ${connection.getResponseCode}"
        )
      }

      val responseBody =
        new String(connection.getInputStream.readAllBytes(), StandardCharsets.UTF_8)

      val objectPattern = """\{"path"\s*:\s*"([^"]+)"\s*,\s*"sizeBytes"\s*:\s*(\d+)\}""".r

      objectPattern.findAllMatchIn(responseBody).toList.map { matchObj =>
        val path = matchObj.group(1)
        val sizeBytes = matchObj.group(2).toLong
        val objectStats = new io.lakefs.clients.sdk.model.ObjectStats()
        objectStats.setPath(path)
        objectStats.setSizeBytes(sizeBytes)
        objectStats
      }
    } catch {
      case e: Exception =>
        logger.warn(
          s"Failed to get directory objects via FileService: ${e.getMessage}. Falling back to direct LakeFS.",
          e
        )
        LakeFSStorageClient.retrieveObjectsOfVersion(datasetName, versionHash)
    } finally {
      connection.disconnect()
    }
  }

  private def addDirectoryToZipFallback(
      zipOutputStream: ZipOutputStream,
      basePath: String,
      datasetName: String,
      versionHash: String,
      directoryPath: Path
  ): Unit = {
    lazy val datasetsRootPath =
      Path
        .of(sys.env.getOrElse("TEXERA_HOME", "."))
        .resolve("amber")
        .resolve("user-resources")
        .resolve("datasets")
    val datasetPath = datasetsRootPath.resolve("0")
    val fullDirectoryPath = datasetPath.resolve(directoryPath)

    if (Files.exists(fullDirectoryPath) && Files.isDirectory(fullDirectoryPath)) {
      Files.walk(fullDirectoryPath).forEach { filePath =>
        if (!Files.isDirectory(filePath)) {
          val zipRelativePath = if (basePath.isEmpty) {
            directoryPath.relativize(datasetPath.relativize(filePath)).toString.replace("\\", "/")
          } else {
            s"$basePath/${directoryPath.relativize(datasetPath.relativize(filePath)).toString.replace("\\", "/")}"
          }

          val zipEntry = new ZipEntry(zipRelativePath)
          zipOutputStream.putNextEntry(zipEntry)

          val fileInputStream =
            GitVersionControlLocalFileStorage.retrieveFileContentOfVersionAsInputStream(
              datasetPath,
              versionHash,
              filePath
            )

          val buffer = new Array[Byte](1024)
          try {
            Iterator
              .continually(fileInputStream.read(buffer))
              .takeWhile(_ != -1)
              .foreach(zipOutputStream.write(buffer, 0, _))
          } finally {
            fileInputStream.close()
          }

          zipOutputStream.closeEntry()
        }
      }
    } else {
      throw new RuntimeException(s"Failed to create zip file for directory: ${directoryPath}")
    }
  }

  private def getFileInputStreamFromLakeFS(
      datasetName: String,
      versionHash: String,
      filePath: String
  ): InputStream = {
    if (userJwtToken.isEmpty) {
      val presignUrl = LakeFSStorageClient.getFilePresignedUrl(datasetName, versionHash, filePath)
      new URL(presignUrl).openStream()
    } else {
      val presignRequestUrl =
        s"$fileServiceGetPresignURLEndpoint?repositoryName=${datasetName}&commitHash=${versionHash}&filePath=${URLEncoder
          .encode(filePath, StandardCharsets.UTF_8.name())}"

      val connection = new URL(presignRequestUrl).openConnection().asInstanceOf[HttpURLConnection]
      connection.setRequestMethod("GET")
      connection.setRequestProperty("Authorization", s"Bearer $userJwtToken")

      if (connection.getResponseCode != HttpURLConnection.HTTP_OK) {
        throw new RuntimeException(
          s"Failed to retrieve presigned URL: HTTP ${connection.getResponseCode}"
        )
      }

      val responseBody =
        new String(connection.getInputStream.readAllBytes(), StandardCharsets.UTF_8)
      val presignedUrl = responseBody.split("\"presignedUrl\"\\s*:\\s*\"")(1).split("\"")(0)

      connection.disconnect()
      new URL(presignedUrl).openStream()
    }
  }
}
