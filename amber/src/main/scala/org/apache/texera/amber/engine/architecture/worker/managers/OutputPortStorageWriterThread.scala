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

package org.apache.texera.amber.engine.architecture.worker.managers

import com.google.common.collect.Queues
import org.apache.texera.amber.core.storage.model.BufferedItemWriter
import org.apache.texera.amber.core.tuple.Tuple
import org.apache.texera.common.config.StorageConfig

import java.util.concurrent.{LinkedBlockingQueue, TimeUnit}
import scala.util.control.NonFatal

sealed trait TerminateSignal
case object PortStorageWriterTerminateSignal extends TerminateSignal

/**
  * Writes a port's tuples to storage. A partly filled buffer is flushed once it has waited
  * `commitIntervalMs`, so a slow producer's rows reach readers that follow the port live.
  */
class OutputPortStorageWriterThread(
    bufferedItemWriter: BufferedItemWriter[Tuple],
    commitIntervalMs: Long = StorageConfig.icebergTableCommitIntervalMs.toLong
) extends Thread {

  val queue: LinkedBlockingQueue[Either[Tuple, TerminateSignal]] =
    Queues.newLinkedBlockingQueue[Either[Tuple, TerminateSignal]]()

  // Captured failure from put-one or close() so the worker DP thread can
  // re-throw and let the coordinator's pekko supervisor surface a FatalError
  // to the client. Without this, the writer thread dies silently and the
  // worker keeps reporting normal port completion to the coordinator while
  // results are missing or stale, leading to e2e timeouts that hide the
  // real cause.
  @volatile private var failure: Option[Throwable] = None
  def getFailure: Option[Throwable] = failure

  override def run(): Unit = {
    try {
      var internalStop = false
      var oldestUnflushedAt: Option[Long] = None
      while (!internalStop) {
        val waitMs = oldestUnflushedAt
          .map(at => math.max(0L, at + commitIntervalMs - System.currentTimeMillis()))
          .getOrElse(Long.MaxValue)
        Option(queue.poll(waitMs, TimeUnit.MILLISECONDS)) match {
          case Some(Left(tuple)) =>
            bufferedItemWriter.putOne(tuple)
            if (oldestUnflushedAt.isEmpty) oldestUnflushedAt = Some(System.currentTimeMillis())
          case Some(Right(_)) => internalStop = true
          case None =>
            bufferedItemWriter.flush()
            oldestUnflushedAt = None
        }
      }
    } catch {
      case NonFatal(e) => failure = Some(e)
    } finally {
      // close() runs even when the loop threw, so a putOne failure does
      // not leak the underlying writer's file handles. If both legs fail,
      // attach close()'s exception as suppressed on the original.
      try bufferedItemWriter.close()
      catch {
        case NonFatal(e) =>
          failure match {
            case Some(orig) => orig.addSuppressed(e)
            case None       => failure = Some(e)
          }
      }
    }
  }
}
