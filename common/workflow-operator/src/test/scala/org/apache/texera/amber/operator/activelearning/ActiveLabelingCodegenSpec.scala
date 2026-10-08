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

package org.apache.texera.amber.operator.activelearning

import org.apache.texera.amber.util.JSONUtils.objectMapper
import org.scalatest.flatspec.AnyFlatSpec

class ActiveLabelingCodegenSpec extends AnyFlatSpec {
  private def decoded(code: String): String =
    """self\.decode_python_template\('([^']*)'\)""".r.replaceAllIn(
      code,
      m => "'" + new String(java.util.Base64.getDecoder.decode(m.group(1)), "UTF-8") + "'"
    )

  "TrainSegmenterOpDesc" should "train on the collected cohort with every resource name" in {
    val op = new TrainSegmenterOpDesc()
    val code = decoded(op.generatePythonCode())
    assert(code.contains("train(self.cohort, 'brain-mri', 'brain-masks', 'brain-mri-gt', 'brain-unet'"), code)
    assert(code.contains("300, 16, 200, True)"), code)
  }

  it should "train from scratch when warm start is off" in {
    val op = new TrainSegmenterOpDesc()
    op.warmStart = false
    assert(decoded(op.generatePythonCode()).contains("200, False)"))
  }

  it should "keep resource names set through JSON" in {
    val op = objectMapper.readValue(
      """{"operatorType":"TrainSegmenter","operatorID":"t","scansDataset":"s","labelsDataset":"l","truthDataset":"g","modelName":"m","maxEpochs":3,"batchSize":2,"validationSize":5}""",
      classOf[org.apache.texera.amber.operator.LogicalOp]
    )
    val code = decoded(op.asInstanceOf[TrainSegmenterOpDesc].generatePythonCode())
    assert(code.contains("train(self.cohort, 's', 'l', 'g', 'm'"), code)
  }

  "ReviewAndCorrectOpDesc" should "render the annotator mode and resource names" in {
    val op = new ReviewAndCorrectOpDesc()
    op.simulated = true
    val code = decoded(op.generatePythonCode())
    assert(code.contains("review(tuple_.as_dict(), 'brain-masks', 'brain-review-queue', 'brain-mri-gt'"), code)
    assert(code.contains("'simulated'"), code)
  }

  "SuggestCasesOpDesc" should "build a Suggester with every resource name and the ranking" in {
    val op = new SuggestCasesOpDesc()
    op.ranking = "random"
    val code = decoded(op.generatePythonCode())
    assert(code.contains("Suggester('brain-mri', 'brain-masks', 'brain-review-queue', 'brain-unet'"), code)
    assert(code.contains("8, 6, 600, 200, 'random')"), code)
  }
}
