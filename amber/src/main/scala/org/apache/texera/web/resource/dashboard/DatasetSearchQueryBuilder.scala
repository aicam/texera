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

package org.apache.texera.web.resource.dashboard

import com.typesafe.scalalogging.LazyLogging
import org.apache.texera.amber.core.storage.util.LakeFSStorageClient
import org.apache.texera.dao.jooq.generated.Tables.{ASSET, ASSET_USER_ACCESS}
import org.apache.texera.dao.jooq.generated.enums.PrivilegeEnum
import org.apache.texera.dao.jooq.generated.tables.User.USER
import org.apache.texera.dao.jooq.generated.tables.pojos.{Asset, User}
import org.apache.texera.web.resource.dashboard.DashboardResource.DashboardClickableFileEntry
import org.apache.texera.web.resource.dashboard.FulltextSearchQueryUtils.{
  getContainsFilter,
  getDateFilter,
  getFullTextSearchFilter
}
import org.apache.texera.web.resource.dashboard.user.dataset.AssetResource.DashboardAsset
import org.jooq.impl.DSL
import org.jooq.{Condition, GroupField, Record, TableLike}

import scala.jdk.CollectionConverters.CollectionHasAsScala

object DatasetSearchQueryBuilder extends SearchQueryBuilder with LazyLogging {
  override protected val mappedResourceSchema: UnifiedResourceSchema = UnifiedResourceSchema(
    resourceType = DSL.inline(SearchQueryBuilder.DATASET_RESOURCE_TYPE),
    name = ASSET.NAME,
    description = ASSET.DESCRIPTION,
    creationTime = ASSET.CREATION_TIME,
    ownerId = ASSET.OWNER_UID,
    did = ASSET.AID,
    repositoryName = ASSET.REPOSITORY_NAME,
    isDatasetPublic = ASSET.IS_PUBLIC,
    isDatasetDownloadable = ASSET.IS_DOWNLOADABLE,
    datasetUserAccess = ASSET_USER_ACCESS.PRIVILEGE
  )

  /*
   * constructs the FROM clause for querying datasets with specific access controls.
   *
   * Parameter:
   * - uid: Integer - Represents the unique identifier of the current user.
   *  - uid is 'null' if the user is not logged in or performing a public search.
   *  - Otherwise, `uid` holds the identifier for the logged-in user.
   * - includePublic - Boolean - Specifies whether to include public datasets in the result.
   */
  override protected def constructFromClause(
      uid: Integer,
      params: DashboardResource.SearchQueryParams,
      includePublic: Boolean = false
  ): TableLike[_] = {
    val baseJoin = ASSET
      .leftJoin(ASSET_USER_ACCESS)
      .on(ASSET_USER_ACCESS.AID.eq(ASSET.AID))
      .leftJoin(USER)
      .on(USER.UID.eq(ASSET.OWNER_UID))

    // Default condition starts as true, ensuring all datasets are selected initially.
    var condition: Condition = DSL.trueCondition()

    if (uid == null) {
      // If `uid` is null, the user is not logged in or performing a public search
      // We only select datasets marked as public
      condition = ASSET.IS_PUBLIC.eq(true)
    } else {
      // When `uid` is present, we add a condition to only include datasets with direct user access.
      val userAccessCondition = ASSET_USER_ACCESS.UID.eq(uid)

      if (includePublic) {
        // If `includePublic` is true, we extend visibility to public datasets as well.
        condition = userAccessCondition.or(ASSET.IS_PUBLIC.eq(true))
      } else {
        condition = userAccessCondition
      }
    }
    baseJoin.where(condition)
  }

  override protected def constructWhereClause(
      uid: Integer,
      params: DashboardResource.SearchQueryParams
  ): Condition = {
    val splitKeywords = params.keywords.asScala
      .flatMap(_.split("[+\\-()<>~*@\"]"))
      .filter(_.nonEmpty)
      .toSeq

    getDateFilter(
      params.creationStartDate,
      params.creationEndDate,
      ASSET.CREATION_TIME
    )
      .and(getContainsFilter(params.datasetIds, ASSET.AID))
      .and(
        getFullTextSearchFilter(splitKeywords, List(ASSET.NAME, ASSET.DESCRIPTION))
      )
  }

  override protected def getGroupByFields: Seq[GroupField] = {
    Seq.empty
  }

  override protected def toEntryImpl(
      uid: Integer,
      record: Record
  ): DashboardResource.DashboardClickableFileEntry = {
    val asset = record.into(ASSET).into(classOf[Asset])
    val owner = record.into(USER).into(classOf[User])
    var size = 0L

    try {
      size = LakeFSStorageClient.retrieveRepositorySize(asset.getRepositoryName)
    } catch {
      case e: io.lakefs.clients.sdk.ApiException =>
        // Treat all LakeFS ApiException as mismatch (repository not found, being deleted, or any fatal error)
        logger.error(
          s"LakeFS ApiException for dataset repository '${asset.getRepositoryName}': ${e.getMessage}",
          e
        )
        return null
    }

    val dd = DashboardAsset(
      asset,
      owner.getEmail,
      record.get(ASSET_USER_ACCESS.PRIVILEGE, classOf[PrivilegeEnum]),
      asset.getOwnerUid == uid,
      size
    )
    DashboardClickableFileEntry(
      resourceType = SearchQueryBuilder.DATASET_RESOURCE_TYPE,
      asset = Some(dd)
    )
  }
}

class DatasetSearchQueryBuilder {}
