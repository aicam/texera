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

package org.apache.texera.amber.operator.source.shared

import org.apache.texera.amber.core.executor.SourceOperatorExecutor
import org.apache.texera.amber.core.storage.SharedOutputs
import org.apache.texera.amber.core.tuple.{Tuple, TupleLike}
import org.apache.texera.amber.util.JSONUtils.objectMapper

class SharedOutputSourceOpExec(descString: String) extends SourceOperatorExecutor {
  private val desc: SharedOutputSourceOpDesc =
    objectMapper.readValue(descString, classOf[SharedOutputSourceOpDesc])
  private val pollIntervalMs = 1000L

  /**
    * While the producer runs and no new row has arrived, yields null, which the engine skips:
    * the worker keeps answering control messages (pause, stats) between polls.
    */
  override def produceTuple(): Iterator[TupleLike] = {
    val shared = SharedOutputs
      .find(desc.sharedOutput)
      .getOrElse(throw new IllegalArgumentException(s"No output is shared as '${desc.sharedOutput}'"))
    val result = SharedOutputs
      .latestResult(shared)
      .getOrElse(throw new IllegalStateException(s"'${desc.sharedOutput}' has no result yet"))
    val document = SharedOutputs.open(result)

    new Iterator[TupleLike] {
      private var rows: Iterator[Tuple] = document.get()
      private var read = 0
      // Read before each fetch, so the fetch after it turns false sees every row the producer wrote.
      private var producing = desc.follow && result.producing
      private var finished = false

      override def hasNext: Boolean = rows.hasNext || !finished

      override def next(): TupleLike =
        if (rows.hasNext) {
          read += 1
          rows.next()
        } else if (!producing) {
          finished = true
          null
        } else {
          Thread.sleep(pollIntervalMs)
          producing = SharedOutputs.isProducing(result.executionId)
          rows = document.getAfter(read)
          null
        }
    }
  }
}
