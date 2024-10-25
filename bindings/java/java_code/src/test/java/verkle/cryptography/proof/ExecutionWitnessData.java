/*
 * Copyright Besu Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
package verkle.cryptography.proof;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class ExecutionWitnessData {

  @JsonProperty("header")
  public Header header;

  @JsonProperty("executionWitness")
  public ExecutionWitness executionWitness;

  static class Header {

    @JsonProperty("blockNumber")
    public String blockNumber;

    @JsonProperty("parentHash")
    public String parentHash;

    @JsonProperty("stateRoot")
    public String stateRoot;
  }

  static class ExecutionWitness {

    @JsonProperty("stateDiff")
    public List<StateDiff> stateDiff;

    @JsonProperty("verkleProof")
    public VerkleProof verkleProof;
  }

  static class StateDiff {

    @JsonProperty("stem")
    public String stem;

    @JsonProperty("suffixDiffs")
    public List<SuffixDiff> suffixDiffs;
  }

  static class SuffixDiff {

    @JsonProperty("suffix")
    public int suffix;

    @JsonProperty("currentValue")
    public String currentValue;

    @JsonProperty("newValue")
    public String newValue;
  }

  static class VerkleProof {

    @JsonProperty("otherStems")
    public List<String> otherStems;

    @JsonProperty("depthExtensionPresent")
    public String depthExtensionPresent;

    @JsonProperty("commitmentsByPath")
    public List<String> commitmentsByPath;

    @JsonProperty("d")
    public String d;

    @JsonProperty("ipaProof")
    public IpaProof ipaProof;
  }

  static class IpaProof {

    @JsonProperty("cl")
    public List<String> cl;

    @JsonProperty("cr")
    public List<String> cr;

    @JsonProperty("finalEvaluation")
    public String finalEvaluation;
  }
}
