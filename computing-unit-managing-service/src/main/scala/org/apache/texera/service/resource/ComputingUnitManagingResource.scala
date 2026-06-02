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
import io.fabric8.kubernetes.api.model.Quantity
import io.fabric8.kubernetes.client.KubernetesClientException
import jakarta.annotation.security.RolesAllowed
import jakarta.ws.rs._
import jakarta.ws.rs.core.{MediaType, Response}
import org.apache.texera.amber.config.{EnvironmentalVariable, StorageConfig}
import org.apache.commons.lang3.StringUtils
import org.apache.texera.auth.JwtAuth.{TOKEN_EXPIRE_TIME_IN_MINUTES, jwtClaims}
import org.apache.texera.auth.{JwtAuth, SessionUser}
import org.apache.texera.config.KubernetesConfig.{
  cpuLimitOptions,
  gpuLimitOptions,
  maxNumOfRunningComputingUnitsPerUser,
  memoryLimitOptions
}
import org.apache.texera.config.{AwsEc2Config, ComputingUnitConfig, KubernetesConfig}
import org.apache.texera.dao.SqlServer
import org.apache.texera.dao.SqlServer.withTransaction
import org.apache.texera.dao.jooq.generated.enums.{PrivilegeEnum, WorkflowComputingUnitTypeEnum}
import org.apache.texera.dao.jooq.generated.tables.daos.{
  ComputingUnitUserAccessDao,
  UserDao,
  WorkflowComputingUnitDao
}
import org.apache.texera.dao.jooq.generated.tables.pojos.WorkflowComputingUnit
import org.apache.texera.service.resource.ComputingUnitManagingResource._
import org.apache.texera.service.resource.ComputingUnitState._
import org.apache.texera.service.util.{
  AwsEc2Client,
  ComputingUnitManagingServiceException,
  InsufficientComputingUnitQuota,
  KubernetesClient
}
import org.jooq.{DSLContext, EnumType}
import play.api.libs.json._

import java.sql.Timestamp
import scala.annotation.unused
import scala.jdk.CollectionConverters.CollectionHasAsScala

object ComputingUnitManagingResource {
  // JDK 17 module-access flags required by the CU JVM at runtime: Apache Arrow
  // (ArrowSource and friends) needs java.base/java.nio opened or MemoryUtil fails
  // to initialize; Pekko/Kryo need the others. Mirrors the repo .jvmopts. Without
  // these the CU JVM crashes on the first Arrow operator (works on JDK 11, not 17).
  private val jvmAddOpens: String = Seq(
    "java.base/java.lang",
    "java.base/java.lang.invoke",
    "java.base/java.util",
    "java.base/java.util.concurrent.atomic",
    "java.base/sun.nio.ch",
    "java.base/java.nio",
    "java.base/jdk.internal.misc"
  ).map(m => s"--add-opens=$m=ALL-UNNAMED").mkString(" ")

  private def context: DSLContext =
    SqlServer
      .getInstance()
      .createDSLContext()

  private def icebergEnvironmentVariables: Map[String, Any] = {
    val base = Map[String, Any](
      EnvironmentalVariable.ENV_ICEBERG_CATALOG_TYPE -> StorageConfig.icebergCatalogType
    )
    StorageConfig.icebergCatalogType match {
      case "rest" =>
        base ++ Map(
          EnvironmentalVariable.ENV_ICEBERG_CATALOG_REST_URI -> StorageConfig.icebergRESTCatalogUri,
          EnvironmentalVariable.ENV_ICEBERG_CATALOG_REST_WAREHOUSE_NAME -> StorageConfig.icebergRESTCatalogWarehouseName
        )
      case "postgres" =>
        base ++ Map(
          EnvironmentalVariable.ENV_ICEBERG_CATALOG_POSTGRES_URI_WITHOUT_SCHEME -> StorageConfig.icebergPostgresCatalogUriWithoutScheme,
          EnvironmentalVariable.ENV_ICEBERG_CATALOG_POSTGRES_USERNAME -> StorageConfig.icebergPostgresCatalogUsername,
          EnvironmentalVariable.ENV_ICEBERG_CATALOG_POSTGRES_PASSWORD -> StorageConfig.icebergPostgresCatalogPassword
        )
      case _ => base
    }
  }

  // Environment variables passed to the created computing unit(pod)
  private lazy val computingUnitEnvironmentVariables: Map[String, Any] =
    icebergEnvironmentVariables ++ Map(
      // Variables for saving the metadata of the results, i.e. URIs of results/stats
      EnvironmentalVariable.ENV_JDBC_URL -> StorageConfig.jdbcUrl,
      EnvironmentalVariable.ENV_JDBC_USERNAME -> StorageConfig.jdbcUsername,
      EnvironmentalVariable.ENV_JDBC_PASSWORD -> StorageConfig.jdbcPassword,
      // Variables for reading files & exporting results
      // LakeFS endpoint is passed to CU to make CU work in dev mode(using localhost & using default LakeFS credentials)
      // LakeFS credentials should NOT be passed to CU
      EnvironmentalVariable.ENV_LAKEFS_ENDPOINT -> StorageConfig.lakefsEndpoint,
      // S3 variables are passed to CU for R UDF large binary support
      EnvironmentalVariable.ENV_S3_ENDPOINT -> StorageConfig.s3Endpoint,
      EnvironmentalVariable.ENV_S3_REGION -> StorageConfig.s3Region,
      EnvironmentalVariable.ENV_S3_AUTH_USERNAME -> StorageConfig.s3Username,
      EnvironmentalVariable.ENV_S3_AUTH_PASSWORD -> StorageConfig.s3Password,
      EnvironmentalVariable.ENV_FILE_SERVICE_GET_PRESIGNED_URL_ENDPOINT -> EnvironmentalVariable
        .get(EnvironmentalVariable.ENV_FILE_SERVICE_GET_PRESIGNED_URL_ENDPOINT)
        .get,
      EnvironmentalVariable.ENV_FILE_SERVICE_UPLOAD_ONE_FILE_TO_DATASET_ENDPOINT -> EnvironmentalVariable
        .get(EnvironmentalVariable.ENV_FILE_SERVICE_UPLOAD_ONE_FILE_TO_DATASET_ENDPOINT)
        .get,
      // Variables for amber setting
      // TODO: use AmberConfig for the following items. Currently AmberConfig is only accessible in workflow-executing-service
      EnvironmentalVariable.ENV_SCHEDULE_GENERATOR_ENABLE_COST_BASED_SCHEDULE_GENERATOR -> EnvironmentalVariable
        .get(EnvironmentalVariable.ENV_SCHEDULE_GENERATOR_ENABLE_COST_BASED_SCHEDULE_GENERATOR)
        .get,
      EnvironmentalVariable.ENV_USER_SYS_ENABLED -> EnvironmentalVariable
        .get(EnvironmentalVariable.ENV_USER_SYS_ENABLED)
        .get,
      EnvironmentalVariable.ENV_MAX_WORKFLOW_WEBSOCKET_REQUEST_PAYLOAD_SIZE_KB -> EnvironmentalVariable
        .get(EnvironmentalVariable.ENV_MAX_WORKFLOW_WEBSOCKET_REQUEST_PAYLOAD_SIZE_KB)
        .get,
      EnvironmentalVariable.ENV_AUTH_JWT_SECRET -> EnvironmentalVariable
        .get(EnvironmentalVariable.ENV_AUTH_JWT_SECRET)
        .get
    )

  case class WorkflowComputingUnitCreationParams(
      name: String,
      unitType: String,
      cpuLimit: String,
      memoryLimit: String,
      gpuLimit: String,
      jvmMemorySize: String,
      shmSize: String,
      uri: Option[String] = None,
      awsAccessKeyId: Option[String] = None,
      awsSecretAccessKey: Option[String] = None,
      awsRegion: Option[String] = None,
      awsInstanceType: Option[String] = None
  )

  case class WorkflowComputingUnitTerminateParams(
      awsAccessKeyId: Option[String] = None,
      awsSecretAccessKey: Option[String] = None
  )

  case class WorkflowComputingUnitResourceLimit(
      cpuLimit: String,
      memoryLimit: String,
      gpuLimit: String
  )

  case class WorkflowComputingUnitMetrics(
      cpuUsage: String,
      memoryUsage: String
  )

  case class DashboardWorkflowComputingUnit(
      computingUnit: WorkflowComputingUnit,
      status: String,
      metrics: WorkflowComputingUnitMetrics,
      isOwner: Boolean,
      accessPrivilege: EnumType,
      ownerGoogleAvatar: String,
      ownerName: String
  )

  case class ComputingUnitLimitOptionsResponse(
      cpuLimitOptions: List[String],
      memoryLimitOptions: List[String],
      gpuLimitOptions: List[String],
      warmPoolCapacity: Int
  )

  case class ComputingUnitTypesResponse(
      typeOptions: List[String]
  )

  /**
    * Builds a cloud-init bash script that the new AWS EC2 runs on first boot.
    * It installs containerd, pulls the CU master image, writes an env file,
    * and starts a systemd unit (`cu-master.service`) that launches the CU
    * container via `ctr run --net-host` with all the env vars.
    *
    * The env map is serialized into a KEY=VALUE file consumed by a small
    * wrapper script — systemd's Environment directive would lose the ability
    * to pass vars through to `ctr run`, so a wrapper is the cleanest option.
    */
  private[resource] def buildAwsCuUserData(
      image: String,
      port: Int,
      env: Map[String, String]
  ): String = {
    val envFileContents =
      env
        .map {
          case (k, v) =>
            // Values with newlines or single quotes would break the env file;
            // the CU master's vars are endpoints/flags that do not contain them.
            val escaped = v.replace("\\", "\\\\").replace("\n", "\\n")
            s"$k=$escaped"
        }
        .mkString("\n")

    s"""#!/bin/bash
       |set -eux
       |exec >/var/log/cu-bootstrap.log 2>&1
       |
       |# 1) Ensure containerd is installed and running (pre-installed on AL2023 but safe to re-run)
       |dnf install -y containerd >/dev/null 2>&1 || yum install -y containerd >/dev/null 2>&1 || true
       |systemctl enable --now containerd
       |
       |# 2) Pull the CU master OCI image via containerd
       |IMG='$image'
       |for i in 1 2 3 4 5; do
       |  ctr image pull "$$IMG" && break
       |  sleep 10
       |done
       |
       |# 3) Write env file (consumed by the wrapper script below)
       |mkdir -p /etc/cu-master
       |cat > /etc/cu-master/env <<'TEXERA_CU_ENV_EOF'
       |$envFileContents
       |TEXERA_CU_ENV_EOF
       |chmod 600 /etc/cu-master/env
       |
       |# 4) Wrapper script that translates env file lines into `ctr run --env` flags
       |cat > /usr/local/bin/cu-master-run <<'CU_WRAPPER_EOF'
       |#!/bin/bash
       |set -eu
       |IMG='__IMG__'
       |/usr/bin/ctr task kill --signal SIGKILL cu-master >/dev/null 2>&1 || true
       |/usr/bin/ctr container rm cu-master >/dev/null 2>&1 || true
       |ARGS=()
       |while IFS= read -r line; do
       |  [ -z "$$line" ] && continue
       |  case "$$line" in \\#*) continue;; esac
       |  ARGS+=(--env "$$line")
       |done < /etc/cu-master/env
       |exec /usr/bin/ctr run --rm --net-host "$${ARGS[@]}" "$$IMG" cu-master
       |CU_WRAPPER_EOF
       |sed -i "s|__IMG__|$$IMG|g" /usr/local/bin/cu-master-run
       |chmod +x /usr/local/bin/cu-master-run
       |
       |# 5) systemd unit that keeps the CU master alive
       |cat > /etc/systemd/system/cu-master.service <<'CU_UNIT_EOF'
       |[Unit]
       |Description=Texera Computing Unit Master
       |After=containerd.service network-online.target
       |Requires=containerd.service
       |
       |[Service]
       |Type=simple
       |ExecStart=/usr/local/bin/cu-master-run
       |Restart=always
       |RestartSec=5
       |
       |[Install]
       |WantedBy=multi-user.target
       |CU_UNIT_EOF
       |
       |systemctl daemon-reload
       |systemctl enable --now cu-master.service
       |""".stripMargin
  }
}

@Produces(Array(MediaType.APPLICATION_JSON))
@Path("/computing-unit")
class ComputingUnitManagingResource {

  private def getComputingUnitByCuid(ctx: DSLContext, cuid: Int): WorkflowComputingUnit = {
    val wcDao = new WorkflowComputingUnitDao(ctx.configuration())
    val unit = wcDao.fetchOneByCuid(cuid)

    if (unit == null) {
      throw new NotFoundException(s"Computing unit with cuid=$cuid does not exist.")
    }
    unit
  }

  private def userOwnComputingUnit(ctx: DSLContext, cuid: Integer, uid: Integer): Boolean = {
    getComputingUnitByCuid(ctx, cuid).getUid == uid
  }

  private def getSupportedComputingUnitTypes: List[String] = {
    val allTypes = WorkflowComputingUnitTypeEnum.values().map(_.getLiteral).toList
    allTypes.filter {
      case "local"      => ComputingUnitConfig.localComputingUnitEnabled
      case "kubernetes" => KubernetesConfig.kubernetesComputingUnitEnabled
      case "aws"        => AwsEc2Config.awsEc2Enabled
      case _            => false // Any unknown types are disabled by default
    }
  }

  private def getComputingUnitStatus(unit: WorkflowComputingUnit): ComputingUnitState = {
    unit.getType match {
      // ── Local CUs are always "running" ──────────────────────────────
      case WorkflowComputingUnitTypeEnum.local =>
        Running

      // ── Kubernetes CUs – only explicit "Running" counts as running ─
      case WorkflowComputingUnitTypeEnum.kubernetes =>
        val phaseOpt = KubernetesClient
          .getPodByName(KubernetesClient.generatePodName(unit.getCuid))
          .map(_.getStatus.getPhase)

        if (phaseOpt.contains("Running")) Running else Pending

      // ── AWS CUs are treated as running (no credentials to check) ───
      case WorkflowComputingUnitTypeEnum.aws =>
        Running

      // ── Any other (unknown) type is treated as pending ──────────────
      case _ =>
        Pending
    }
  }

  private def getComputingUnitMetrics(unit: WorkflowComputingUnit): WorkflowComputingUnitMetrics = {
    unit.getType match {
      case WorkflowComputingUnitTypeEnum.local =>
        WorkflowComputingUnitMetrics("NaN", "NaN")
      case WorkflowComputingUnitTypeEnum.kubernetes =>
        val metrics = KubernetesClient.getPodMetrics(unit.getCuid)
        WorkflowComputingUnitMetrics(
          metrics.getOrElse("cpu", ""),
          metrics.getOrElse("memory", "")
        )
      case WorkflowComputingUnitTypeEnum.aws =>
        WorkflowComputingUnitMetrics("NaN", "NaN")
      case _ =>
        WorkflowComputingUnitMetrics("NaN", "NaN")
    }
  }

  private def getComputingUnitResourceLimit(
      unit: WorkflowComputingUnit
  ): WorkflowComputingUnitResourceLimit = {
    unit.getType match {
      case WorkflowComputingUnitTypeEnum.local =>
        WorkflowComputingUnitResourceLimit("NaN", "NaN", "NaN")
      case WorkflowComputingUnitTypeEnum.kubernetes =>
        val podLimits: Map[String, String] = KubernetesClient.getPodLimits(unit.getCuid)

        // Get GPU value by finding the exact configured resource key
        val gpuValue = podLimits.getOrElse(KubernetesConfig.gpuResourceKey, "0")

        WorkflowComputingUnitResourceLimit(
          podLimits("cpu"),
          podLimits("memory"),
          gpuValue
        )
      case WorkflowComputingUnitTypeEnum.aws =>
        WorkflowComputingUnitResourceLimit("NaN", "NaN", "NaN")
      case _ =>
        WorkflowComputingUnitResourceLimit("NaN", "NaN", "NaN")
    }
  }

  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Produces(Array(MediaType.APPLICATION_JSON))
  @Path("/limits")
  def getComputingUnitLimitOptions(
      @Auth @unused user: SessionUser
  ): ComputingUnitLimitOptionsResponse = {
    ComputingUnitLimitOptionsResponse(
      cpuLimitOptions,
      memoryLimitOptions,
      gpuLimitOptions,
      KubernetesConfig.warmPoolCapacity
    )
  }

  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Produces(Array(MediaType.APPLICATION_JSON))
  @Path("/types")
  def getComputingUnitTypes(
      @Auth @unused user: SessionUser
  ): ComputingUnitTypesResponse = ComputingUnitTypesResponse(getSupportedComputingUnitTypes)

  /**
    * Create a new pod for the given user ID.
    *
    * @param param The parameters containing the user ID.
    * @return The created pod or an error response.
    */
  @POST
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Consumes(Array(MediaType.APPLICATION_JSON))
  @Produces(Array(MediaType.APPLICATION_JSON))
  @Path("/create")
  def createWorkflowComputingUnit(
      param: WorkflowComputingUnitCreationParams,
      @Auth user: SessionUser
  ): DashboardWorkflowComputingUnit = {
    if (param.name.trim.isEmpty) {
      throw new ForbiddenException("Computing unit name cannot be empty.")
    }

    // Validate the unit type
    val cuType: WorkflowComputingUnitTypeEnum =
      WorkflowComputingUnitTypeEnum.lookupLiteral(param.unitType)

    // Validate that the type itself is supported
    if (!getSupportedComputingUnitTypes.contains(param.unitType))
      throw new ForbiddenException(
        s"Unit type '${param.unitType}' is not allowed. Valid options: " +
          getSupportedComputingUnitTypes.mkString(", ")
      )

    // For Kubernetes computing units, validate resource limits
    cuType match {

      // Kubernetes-specific checks
      case WorkflowComputingUnitTypeEnum.kubernetes =>
        if (!cpuLimitOptions.contains(param.cpuLimit))
          throw new ForbiddenException(
            s"CPU quantity '${param.cpuLimit}' is not allowed. " +
              s"Valid options: ${cpuLimitOptions.mkString(", ")}"
          )
        if (!memoryLimitOptions.contains(param.memoryLimit))
          throw new ForbiddenException(
            s"Memory quantity '${param.memoryLimit}' is not allowed. " +
              s"Valid options: ${memoryLimitOptions.mkString(", ")}"
          )
        if (!gpuLimitOptions.contains(param.gpuLimit))
          throw new ForbiddenException(
            s"GPU quantity '${param.gpuLimit}' is not allowed. " +
              s"Valid options: ${gpuLimitOptions.mkString(", ")}"
          )

        // Check if the shared-memory size is the valid size representation
        val shmQuantity =
          try {
            Quantity.parse(param.shmSize)
          } catch {
            case _: IllegalArgumentException =>
              throw new ForbiddenException(
                s"Shared-memory size '${param.shmSize}' is not a valid Kubernetes quantity " +
                  s"(examples: 64Mi, 2Gi)."
              )
          }

        val memQuantity = Quantity.parse(param.memoryLimit)

        // ensure /dev/shm upper bound ≤ container memory limit
        if (shmQuantity.compareTo(memQuantity) > 0)
          throw new ForbiddenException(
            s"Shared-memory size (${param.shmSize}) cannot exceed the total memory limit " +
              s"(${param.memoryLimit})."
          )

        // JVM heap ≤ total memory
        val jvmGB = param.jvmMemorySize.replaceAll("[^0-9]", "").toInt
        val memGB =
          if (param.memoryLimit.endsWith("Gi")) param.memoryLimit.replaceAll("[^0-9]", "").toInt
          else if (param.memoryLimit.endsWith("Mi"))
            param.memoryLimit.replaceAll("[^0-9]", "").toInt / 1024
          else param.memoryLimit.replaceAll("[^0-9]", "").toInt

        if (jvmGB > memGB)
          throw new ForbiddenException(
            s"JVM memory size (${param.jvmMemorySize}) cannot exceed the " +
              s"total memory limit (${param.memoryLimit})."
          )

      // Local-specific checks
      case WorkflowComputingUnitTypeEnum.local =>
        if (param.uri.forall(_.trim.isEmpty))
          throw new ForbiddenException("URI is required for local computing units")

      // AWS-specific checks
      case WorkflowComputingUnitTypeEnum.aws =>
        if (param.awsAccessKeyId.forall(_.trim.isEmpty))
          throw new ForbiddenException("AWS Access Key ID is required for AWS computing units")
        if (param.awsSecretAccessKey.forall(_.trim.isEmpty))
          throw new ForbiddenException("AWS Secret Access Key is required for AWS computing units")
        val instanceType = param.awsInstanceType.getOrElse("")
        if (instanceType.trim.isEmpty)
          throw new ForbiddenException("Instance type is required for AWS computing units")
        if (!AwsEc2Config.instanceTypeOptions.contains(instanceType))
          throw new ForbiddenException(
            s"Instance type '$instanceType' is not allowed. " +
              s"Valid options: ${AwsEc2Config.instanceTypeOptions.mkString(", ")}"
          )

      // Anything else (shouldn't happen if you keep supported types in sync)
      case _ =>
        throw new ForbiddenException(s"Unsupported computing-unit type: ${param.unitType}")
    }

    withTransaction(context) { ctx =>
      val wcDao = new WorkflowComputingUnitDao(ctx.configuration())

      val units = wcDao
        .fetchByUid(user.getUid)
        .asScala
        .filter(_.getTerminateTime == null) // Filter out terminated units

      if (units.size >= maxNumOfRunningComputingUnitsPerUser) {
        throw InsufficientComputingUnitQuota(maxNumOfRunningComputingUnitsPerUser)
      }

      val resourceJson: String = cuType match {
        // ── Kubernetes CU ───────────────────────────────────────
        case WorkflowComputingUnitTypeEnum.kubernetes =>
          Json.stringify(
            Json.obj(
              "cpuLimit" -> param.cpuLimit,
              "memoryLimit" -> param.memoryLimit,
              "gpuLimit" -> param.gpuLimit,
              "jvmMemorySize" -> param.jvmMemorySize,
              "shmSize" -> param.shmSize,
              "nodeAddresses" -> Json.arr() // filled in later
            )
          )

        // ── Local CU ─────────────────────────────────────────────
        case WorkflowComputingUnitTypeEnum.local =>
          Json.stringify(
            Json.obj(
              "cpuLimit" -> "NaN",
              "memoryLimit" -> "NaN",
              "gpuLimit" -> "NaN",
              "jvmMemorySize" -> "NaN",
              "shmSize" -> "NaN",
              // user-supplied URI goes straight in
              "nodeAddresses" -> Json.arr(param.uri.get)
            )
          )

        // ── AWS EC2 CU ──────────────────────────────────────────
        // NOTE: credentials are NOT stored in the resource JSON
        case WorkflowComputingUnitTypeEnum.aws =>
          Json.stringify(
            Json.obj(
              "cpuLimit" -> "NaN",
              "memoryLimit" -> "NaN",
              "gpuLimit" -> "NaN",
              "jvmMemorySize" -> "NaN",
              "shmSize" -> "NaN",
              "instanceType" -> JsString(param.awsInstanceType.get),
              "region" -> JsString(param.awsRegion.getOrElse(AwsEc2Config.defaultRegion)),
              "instanceId" -> JsString(""), // filled in after launch
              "nodeAddresses" -> Json.arr()
            )
          )
        case _ => "{}"
      }

      val computingUnit = new WorkflowComputingUnit()
      val userToken = JwtAuth.jwtToken(jwtClaims(user.user, TOKEN_EXPIRE_TIME_IN_MINUTES))
      computingUnit.setUid(user.getUid)
      computingUnit.setName(param.name)
      computingUnit.setCreationTime(new Timestamp(System.currentTimeMillis()))
      computingUnit.setType(WorkflowComputingUnitTypeEnum.lookupLiteral(param.unitType))
      computingUnit.setResource(resourceJson)

      // Set URI during initial insert
      cuType match {
        case WorkflowComputingUnitTypeEnum.local =>
          computingUnit.setUri(param.uri.get)
        case _ =>
          computingUnit.setUri("") // placeholder, updated after resource creation
      }

      wcDao.insert(computingUnit)

      val userDao = new UserDao(ctx.configuration())
      val ownerUser = Option(userDao.fetchOneByUid(user.getUid))
      val ownerGoogleAvatar: String =
        ownerUser.flatMap(u => Option(u.getGoogleAvatar).filter(_.nonEmpty)).orNull
      val ownerUsername: String =
        ownerUser.flatMap(u => Option(u.getName).filter(_.nonEmpty)).orNull

      // Retrieve generated cuid
      val cuid = ctx.lastID().intValue()
      val insertedUnit = wcDao.fetchOneByCuid(cuid)

      if (cuType == WorkflowComputingUnitTypeEnum.kubernetes && insertedUnit != null) {
        // 1. Update the DB with the URI
        insertedUnit.setUri(KubernetesClient.generatePodURI(cuid))

        val updatedResource: JsObject =
          Json
            .parse(insertedUnit.getResource)
            .as[JsObject] ++
            Json.obj("nodeAddresses" -> Json.arr(insertedUnit.getUri))

        insertedUnit.setResource(Json.stringify(updatedResource))
        wcDao.update(insertedUnit)

        // 2. Launch the pod as CU
        try {
          KubernetesClient.createPod(
            cuid,
            param.cpuLimit,
            param.memoryLimit,
            param.gpuLimit,
            computingUnitEnvironmentVariables ++ Map(
              EnvironmentalVariable.ENV_USER_JWT_TOKEN -> userToken,
              EnvironmentalVariable.ENV_JAVA_OPTS -> s"$jvmAddOpens -Xmx${param.jvmMemorySize}"
            ),
            Some(param.shmSize)
          )

        } catch {
          case e: KubernetesClientException =>
            throw ComputingUnitManagingServiceException.fromKubernetes(e)

          case t: Throwable =>
            throw t
        }
      }

      // ── AWS EC2 launch ──────────────────────────────────────────
      if (cuType == WorkflowComputingUnitTypeEnum.aws && insertedUnit != null) {
        val awsRegion = param.awsRegion.getOrElse(AwsEc2Config.defaultRegion)
        try {
          val cuEnv = computingUnitEnvironmentVariables ++ Map(
            EnvironmentalVariable.ENV_USER_JWT_TOKEN -> userToken,
            EnvironmentalVariable.ENV_JAVA_OPTS -> s"$jvmAddOpens -Xmx2g"
          )

          // The k8s-internal DNS names in cuEnv aren't reachable from a remote
          // EC2. Rewrite them to the texera host's public address. The manager
          // deployment sets TEXERA_PUBLIC_HOST to expose this.
          val publicHost = sys.env
            .get("TEXERA_PUBLIC_HOST")
            .map(_.trim)
            .filter(_.nonEmpty)
            .getOrElse("")
          if (publicHost.isEmpty) {
            throw new ForbiddenException(
              "TEXERA_PUBLIC_HOST is not set on the manager — cannot build reachable " +
                "endpoints for a remote AWS CU."
            )
          }
          val publicCuEnv: Map[String, String] = cuEnv.map {
            case (k, v) =>
              val s = v.toString
              val pub = s
                .replace("texera-postgresql:5432", s"$publicHost:5432")
                .replace("texera-minio:9000", s"$publicHost:9000")
                .replace("texera-lakefs.texera-dev:8000", s"$publicHost:8000")
                .replace("texera-lakefs:8000", s"$publicHost:8000")
                .replace("http://file-service-svc:9092", s"http://$publicHost")
              k -> pub
          }

          val userData = buildAwsCuUserData(
            image = sys.env
              .getOrElse(
                "AWS_EC2_CU_IMAGE",
                "docker.io/alirisheh876/computing-unit-master:remote-cu-amd64"
              ),
            port = AwsEc2Config.computingUnitPort,
            env = publicCuEnv
          )

          val instanceId = AwsEc2Client.createInstance(
            accessKeyId = param.awsAccessKeyId.get,
            secretAccessKey = param.awsSecretAccessKey.get,
            region = awsRegion,
            instanceType = param.awsInstanceType.get,
            userData = Some(userData)
          )

          // Wait for the public IP (EC2 assigns it after the instance enters "pending->running").
          val publicIp = AwsEc2Client
            .waitForPublicIp(
              param.awsAccessKeyId.get,
              param.awsSecretAccessKey.get,
              awsRegion,
              instanceId
            )
            .getOrElse("")

          val uri =
            if (publicIp.nonEmpty) s"$publicIp:${AwsEc2Config.computingUnitPort}"
            else ""

          insertedUnit.setUri(uri)

          val updatedResource: JsObject =
            Json
              .parse(insertedUnit.getResource)
              .as[JsObject] ++
              Json.obj(
                "instanceId" -> instanceId,
                "nodeAddresses" -> Json.arr(uri)
              )

          insertedUnit.setResource(Json.stringify(updatedResource))
          wcDao.update(insertedUnit)

        } catch {
          case t: Throwable =>
            // Clean up DB entry on failure
            insertedUnit.setTerminateTime(new Timestamp(System.currentTimeMillis()))
            wcDao.update(insertedUnit)
            throw new ForbiddenException(
              s"Failed to create AWS EC2 instance: ${t.getMessage}"
            )
        }
      }

      DashboardWorkflowComputingUnit(
        insertedUnit,
        getComputingUnitStatus(insertedUnit).toString,
        getComputingUnitMetrics(insertedUnit),
        isOwner = true,
        accessPrivilege = PrivilegeEnum.WRITE,
        ownerGoogleAvatar,
        ownerUsername
      )
    }
  }

  /**
    * List all computing units created by the current user.
    *
    * @return A list of computing units that are not terminated.
    */
  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Consumes(Array(MediaType.APPLICATION_JSON))
  @Produces(Array(MediaType.APPLICATION_JSON))
  @Path("")
  def listComputingUnits(
      @Auth user: SessionUser
  ): List[DashboardWorkflowComputingUnit] = {
    withTransaction(context) { ctx =>
      val computingUnitDao = new WorkflowComputingUnitDao(ctx.configuration())
      val uid = user.getUid

      // Always fetch units owned by the user
      val ownedUnits = computingUnitDao.fetchByUid(uid).asScala.toList

      // Conditionally fetch shared units based on the config flag
      val (sharedUnits, sharedUnitInfo) =
        if (ComputingUnitConfig.sharingComputingUnitEnabled) {
          val computingUnitUserAccessDao = new ComputingUnitUserAccessDao(ctx.configuration())
          val info = computingUnitUserAccessDao
            .fetchByUid(uid)
            .asScala
            .map(access => access.getCuid -> access.getPrivilege)
            .toMap
          val sharedCuids = info.keys.toList.map(Integer.valueOf(_))

          val units = if (sharedCuids.isEmpty) {
            List()
          } else {
            computingUnitDao.fetchByCuid(sharedCuids: _*).asScala.toList
          }
          (units, info)
        } else {
          // If sharing is disabled, return empty collections
          (List.empty[WorkflowComputingUnit], Map.empty[Integer, PrivilegeEnum])
        }

      val allUnits = ownedUnits ++ sharedUnits
      val ownerUids: List[Integer] = allUnits.map(_.getUid).distinct
      val userDao = new UserDao(ctx.configuration())
      val ownerInfoMap: Map[Integer, (String, String)] =
        userDao
          .fetchByUid(ownerUids: _*)
          .asScala
          .map { u =>
            val avatar = Option(u.getGoogleAvatar).filter(_.nonEmpty).orNull
            val name = Option(u.getName).filter(_.nonEmpty).orNull
            u.getUid -> (avatar, name)
          }
          .toMap

      // If a Kubernetes pod has already disappeared (e.g., manually deleted or TTL
      // GC-ed by the cluster), we treat the corresponding computing unit as
      // terminated from the system's point of view. Here we eagerly update its
      // terminateTime in the database **before** we build the response list so
      // that subsequent API calls will no longer return this unit.
      allUnits.foreach { unit =>
        // Only check pod existence for Kubernetes units (AWS units can't be
        // checked without credentials, local units don't have pods)
        if (
          unit.getType == WorkflowComputingUnitTypeEnum.kubernetes &&
          !KubernetesClient.podExists(unit.getCuid)
        ) {
          unit.setTerminateTime(new Timestamp(System.currentTimeMillis()))
          computingUnitDao.update(unit)
        }
      }

      // For shared units, we need to check the access privilege which are saved in different table
      // to streamline the process, we combine owned units with default WRITE privilege and use sharedUnitInfo
      // to get the privilege for shared units.
      (ownedUnits.map(u => (u, PrivilegeEnum.WRITE)) ++ sharedUnits.map(u =>
        (u, sharedUnitInfo(u.getCuid))
      ))
        .distinctBy { case (unit, _) => unit.getCuid }
        .filter { case (unit, _) => unit.getTerminateTime == null }
        .filter {
          case (unit, _) =>
            unit.getType match {
              case WorkflowComputingUnitTypeEnum.kubernetes =>
                KubernetesClient.podExists(unit.getCuid)
              case _ => true
            }
        }
        .map {
          case (unit, privilege) =>
            DashboardWorkflowComputingUnit(
              computingUnit = unit,
              isOwner = unit.getUid.equals(uid),
              accessPrivilege = privilege,
              status = getComputingUnitStatus(unit).toString,
              metrics = getComputingUnitMetrics(unit),
              ownerGoogleAvatar = ownerInfoMap.getOrElse(unit.getUid, (null, null))._1,
              ownerName = ownerInfoMap.getOrElse(unit.getUid, (null, null))._2
            )
        }
    }
  }

  /**
    * Return a fully populated [[org.apache.texera.service.resource.ComputingUnitManagingResource.DashboardWorkflowComputingUnit]] for the
    * specified `cuid`, identical to one row produced by /list.
    *
    * @param cuid the ID of the computing-unit to fetch
    */
  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Produces(Array(MediaType.APPLICATION_JSON))
  @Path("/{cuid}")
  def getComputingUnitInfo(
      @PathParam("cuid") cuid: Integer,
      @Auth user: SessionUser
  ): DashboardWorkflowComputingUnit = {

    val unit = getComputingUnitByCuid(context, cuid)
    val userDao = new UserDao(context.configuration())
    val ownerUser = Option(userDao.fetchOneByUid(unit.getUid))
    val ownerGoogleAvatar: String =
      ownerUser.flatMap(u => Option(u.getGoogleAvatar).filter(_.nonEmpty)).orNull
    val ownerUsername: String =
      ownerUser.flatMap(u => Option(u.getName).filter(_.nonEmpty)).orNull

    DashboardWorkflowComputingUnit(
      computingUnit = unit,
      status = getComputingUnitStatus(unit).toString,
      metrics = getComputingUnitMetrics(unit),
      isOwner = unit.getUid.equals(user.getUid),
      accessPrivilege = {
        val cuAccessDao = new ComputingUnitUserAccessDao(context.configuration())
        val access = cuAccessDao
          .fetchByUid(user.getUid)
          .asScala
          .find(access => access.getCuid.equals(cuid))

        if (access.isDefined) {
          access.get.getPrivilege
        } else if (unit.getUid.equals(user.getUid)) {
          PrivilegeEnum.WRITE
        } else {
          // Default privilege for non-owners without explicit access
          PrivilegeEnum.NONE
        }
      },
      ownerGoogleAvatar,
      ownerUsername
    )
  }

  /**
    * Terminate the computing unit's pod based on the pod URI.
    *
    * @return A response indicating success or failure.
    */
  @DELETE
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Consumes(Array(MediaType.APPLICATION_JSON))
  @Produces(Array(MediaType.APPLICATION_JSON))
  @Path("/{cuid}/terminate")
  def terminateComputingUnit(
      @PathParam("cuid") cuid: Integer,
      @Auth user: SessionUser,
      param: WorkflowComputingUnitTerminateParams
  ): Response = {
    if (!userOwnComputingUnit(context, cuid, user.getUid)) {
      return Response
        .status(Response.Status.BAD_REQUEST)
        .entity(s"User has no access to the computing unit")
        .build()
    }

    // If successful, update the database
    withTransaction(context) { ctx =>
      val cuDao = new WorkflowComputingUnitDao(ctx.configuration())
      val unit = getComputingUnitByCuid(ctx, cuid)

      unit.getType match {
        case WorkflowComputingUnitTypeEnum.kubernetes =>
          KubernetesClient.deletePod(cuid)

        case WorkflowComputingUnitTypeEnum.aws =>
          // AWS requires credentials to terminate the instance
          if (param == null || param.awsAccessKeyId.forall(_.trim.isEmpty) ||
              param.awsSecretAccessKey.forall(_.trim.isEmpty)) {
            throw new ForbiddenException(
              "AWS credentials are required to terminate an AWS computing unit"
            )
          }
          val resourceJson = Json.parse(unit.getResource)
          val instanceId = (resourceJson \ "instanceId").as[String]
          val region = (resourceJson \ "region").as[String]

          if (instanceId.nonEmpty) {
            AwsEc2Client.terminateInstance(
              param.awsAccessKeyId.get,
              param.awsSecretAccessKey.get,
              region,
              instanceId
            )
          }

        case _ => // local and others: no infrastructure to tear down
      }

      unit.setTerminateTime(new Timestamp(System.currentTimeMillis()))
      cuDao.update(unit)
    }
    Response.ok().build()
  }

  /**
    * Rename a computing unit.
    *
    * @param cuid The computing unit ID.
    * @param name The new name for the computing unit.
    * @param user The authenticated user.
    * @return A response indicating success or failure.
    */
  @PUT
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Consumes(Array(MediaType.APPLICATION_JSON))
  @Produces(Array(MediaType.APPLICATION_JSON))
  @Path("/{cuid}/rename/{name}")
  def renameComputingUnit(
      @PathParam("cuid") cuid: Integer,
      @PathParam("name") name: String,
      @Auth user: SessionUser
  ): Response = {
    // Verify ownership or write access
    if (
      !userOwnComputingUnit(context, cuid, user.getUid) &&
      !ComputingUnitAccessResource.hasWriteAccess(cuid, user.getUid)
    ) {
      return Response
        .status(Response.Status.FORBIDDEN)
        .entity("User does not have permission to rename this computing unit")
        .build()
    }

    // Validate name
    if (StringUtils.isBlank(name)) {
      return Response
        .status(Response.Status.BAD_REQUEST)
        .entity("Computing unit name cannot be empty or blank")
        .build()
    }

    withTransaction(context) { ctx =>
      val cuDao = new WorkflowComputingUnitDao(ctx.configuration())
      val unit = getComputingUnitByCuid(ctx, cuid)

      try {
        unit.setName(name)
        cuDao.update(unit)
      } catch {
        case e: Exception =>
          return Response
            .status(Response.Status.INTERNAL_SERVER_ERROR)
            .entity(e.getMessage)
            .build()
      }
    }

    Response.ok().build()
  }

  /**
    * Retrieves the CPU and memory metrics for a computing unit identified by its `cuid`.
    *
    * @param cuid The computing unit ID.
    * @return A `WorkflowComputingUnitMetrics` object with CPU and memory usage data.
    */
  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Produces(Array(MediaType.APPLICATION_JSON))
  @Path("/{cuid}/metrics")
  def getComputingUnitMetricsEndpoint(
      @PathParam("cuid") cuid: String,
      @Auth user: SessionUser
  ): WorkflowComputingUnitMetrics = {
    if (!userOwnComputingUnit(context, cuid.toInt, user.getUid)) {
      throw new BadRequestException("User has no access to the computing unit")
    }
    val computingUnit = getComputingUnitByCuid(context, cuid.toInt)
    getComputingUnitMetrics(computingUnit)
  }

  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Produces(Array(MediaType.APPLICATION_JSON))
  @Path("/{cuid}/limits")
  def getComputingUnitResourceLimit(
      @PathParam("cuid") cuid: String,
      @Auth user: SessionUser
  ): WorkflowComputingUnitResourceLimit = {
    if (!userOwnComputingUnit(context, cuid.toInt, user.getUid)) {
      throw new BadRequestException("User has no access to the computing unit")
    }
    val computingUnit = getComputingUnitByCuid(context, cuid.toInt)
    getComputingUnitResourceLimit(computingUnit)
  }

  // Drives the create-CU modal's progressive view. Returns a coarse phase
  // ("Submitted" → "Scheduling" → "Starting"/"Pulling" → "Initializing" →
  // "Ready"/"Failed") plus a human-readable message. The frontend polls this
  // until phase == Ready (or Failed) and then waits for its WS to connect.
  @GET
  @RolesAllowed(Array("REGULAR", "ADMIN"))
  @Produces(Array(MediaType.APPLICATION_JSON))
  @Path("/{cuid}/creation-status")
  def getCreationStatus(
      @PathParam("cuid") cuid: Integer,
      @Auth user: SessionUser
  ): Map[String, String] = {
    if (!userOwnComputingUnit(context, cuid, user.getUid)) {
      throw new BadRequestException("User has no access to the computing unit")
    }
    val unit = getComputingUnitByCuid(context, cuid)
    unit.getType match {
      case WorkflowComputingUnitTypeEnum.kubernetes =>
        val (phase, message) = KubernetesClient.getCreationPhase(cuid)
        Map("phase" -> phase, "message" -> message)
      case WorkflowComputingUnitTypeEnum.local =>
        Map("phase" -> "Ready", "message" -> "Local computing unit")
      case WorkflowComputingUnitTypeEnum.aws =>
        Map(
          "phase" -> "Ready",
          "message" -> "AWS EC2 launch complete (instance state not polled here)"
        )
      case _ =>
        Map("phase" -> "Submitted", "message" -> "Unknown computing-unit type")
    }
  }
}
