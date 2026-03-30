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

package org.apache.texera.amber.storage

import org.apache.texera.amber.core.storage.FileResolver
import org.apache.commons.vfs2.FileNotFoundException
import org.apache.texera.dao.MockTexeraDB
import org.apache.texera.dao.jooq.generated.enums.{AssetTypeEnum, UserRoleEnum}
import org.apache.texera.dao.jooq.generated.tables.daos.{AssetDao, AssetVersionDao, UserDao}
import org.apache.texera.dao.jooq.generated.tables.pojos.{Asset, AssetVersion, User}
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.{BeforeAndAfterAll, BeforeAndAfterEach}

import java.nio.file.Paths

class FileResolverSpec
    extends AnyFlatSpec
    with BeforeAndAfterAll
    with BeforeAndAfterEach
    with MockTexeraDB {

  private val testUser: User = {
    val user = new User
    user.setUid(Integer.valueOf(1))
    user.setName("test_user")
    user.setRole(UserRoleEnum.ADMIN)
    user.setPassword("123")
    user.setEmail("test_user@test.com")
    user
  }

  private val testAsset: Asset = {
    val asset = new Asset
    asset.setAid(Integer.valueOf(1))
    asset.setName("test_dataset")
    asset.setType(AssetTypeEnum.dataset)
    asset.setRepositoryName("test_dataset")
    asset.setDescription("dataset for test")
    asset.setIsPublic(true)
    asset.setOwnerUid(Integer.valueOf(1))
    asset
  }

  private val testAssetVersion1: AssetVersion = {
    val assetVersion = new AssetVersion
    assetVersion.setAid(Integer.valueOf(1))
    assetVersion.setName("v1")
    assetVersion.setAvid(Integer.valueOf(1))
    assetVersion.setCreatorUid(Integer.valueOf(1))
    assetVersion.setVersionHash("97fd4c2a755b69b7c66d322eab40b7e5c2ad5d10")
    assetVersion
  }

  private val testAssetVersion2: AssetVersion = {
    val assetVersion = new AssetVersion
    assetVersion.setAid(Integer.valueOf(1))
    assetVersion.setName("v2")
    assetVersion.setAvid(Integer.valueOf(2))
    assetVersion.setCreatorUid(Integer.valueOf(1))
    assetVersion.setVersionHash("37966c92cb3a8bee1f9d8e21937aa8faa5e48513")
    assetVersion
  }

  private val localCsvFilePath = "common/workflow-core/src/test/resources/country_sales_small.csv"

  private val datasetACsvFilePath = "/datasets/test_user@test.com/test_dataset/v2/directory/a.csv"

  private val dataset1TxtFilePath = "/datasets/test_user@test.com/test_dataset/v1/1.txt"

  override protected def beforeAll(): Unit = {
    initializeDBAndReplaceDSLContext()

    // add test user
    val userDao = new UserDao(getDSLContext.configuration())
    userDao.insert(testUser)

    // add test asset
    val assetDao = new AssetDao(getDSLContext.configuration())
    assetDao.insert(testAsset)

    // add test asset versions
    val assetVersionDao = new AssetVersionDao(getDSLContext.configuration())
    assetVersionDao.insert(testAssetVersion1)
    assetVersionDao.insert(testAssetVersion2)
  }

  "FileResolver" should "resolve local file correctly" in {
    val localUri = FileResolver.resolve(localCsvFilePath)

    assert(localUri == Paths.get(localCsvFilePath).toUri)
  }

  "FileResolver" should "resolve asset file correctly" in {
    val datasetACsvUri = FileResolver.resolve(datasetACsvFilePath)
    val dataset1TxtUri = FileResolver.resolve(dataset1TxtFilePath)

    assert(
      datasetACsvUri.toString == f"${FileResolver.ASSET_FILE_URI_SCHEME}:///${testAsset.getRepositoryName}/${testAssetVersion2.getVersionHash}/directory/a.csv"
    )
    assert(
      dataset1TxtUri.toString == f"${FileResolver.ASSET_FILE_URI_SCHEME}:///${testAsset.getRepositoryName}/${testAssetVersion1.getVersionHash}/1.txt"
    )
  }

  "FileResolver" should "throw not found exception" in {
    assertThrows[FileNotFoundException] {
      FileResolver.resolve("some/random/path")
    }
  }

  override protected def afterAll(): Unit = {
    shutdownDB()
  }

}