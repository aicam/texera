package edu.uci.ics.texera.auth.util

import edu.uci.ics.texera.dao.SqlServer
import edu.uci.ics.texera.dao.jooq.generated.enums.PrivilegeEnum
import edu.uci.ics.texera.dao.jooq.generated.tables.daos.{ComputingUnitUserAccessDao, WorkflowComputingUnitDao}
import ComputingUnitAccess._
import org.jooq.DSLContext

import scala.jdk.CollectionConverters._


object ComputingUnitAccess {
  private lazy val context: DSLContext = SqlServer
    .getInstance()
    .createDSLContext()
}

class ComputingUnitAccess {

  def getComputingUnitAccess(cuid: Integer, uid: Integer): PrivilegeEnum = {
    val workflowComputingUnitDao = new WorkflowComputingUnitDao(context.configuration())
    val unit = workflowComputingUnitDao.fetchOneByCuid(cuid)

    if (unit.getUid.equals(uid)) {
      return PrivilegeEnum.WRITE // owner has write access
    }

    val computingUnitUserAccessDao = new ComputingUnitUserAccessDao(context.configuration())
    val accessList = computingUnitUserAccessDao
      .fetchByUid(uid)
      .asScala
      .find(_.getCuid.equals(cuid))

    accessList match {
      case Some(access) => access.getPrivilege
      case None => PrivilegeEnum.NONE
    }
  }
}
