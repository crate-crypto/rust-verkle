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

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import verkle.cryptography.LibIpaMultipoint;

public class VerifyProofTest {

  private static final ObjectMapper objectMapper = new ObjectMapper();

  static {
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  public static Stream<Arguments> getParameters() {
    return Stream.of(
        Arguments.of(
            "/valid_block_1.json",
            "0x1fbf85345a3cbba9a6d44f991b721e55620a22397c2a93ee8d5011136ac300ee",
            true),
        Arguments.of(
            "/valid_block_72.json",
            "0x64e1a647f42e5c2e3c434531ccf529e1b3e93363a40db9fc8eec81f492123510",
            true),
        Arguments.of(
            "/invalid_block_72.json",
            "0x64e1a647f42e5c2e3c434531ccf529e1b3e93363a40db9fc8eec81f492123510",
            false),
        Arguments.of(
            "/valid_block_73.json",
            "0x18d1dfcc6ccc6f34d14af48a865895bf34bde7f3571d9ba24a4b98122841048c",
            true),
        Arguments.of(
            "/invalid_block_73.json",
            "0x18d1dfcc6ccc6f34d14af48a865895bf34bde7f3571d9ba24a4b98122841048c",
            false));
  }

  @ParameterizedTest(name = "{index}: {0}")
  @MethodSource("getParameters")
  public void TestVerifyPreStateRoot(
      final String fileName, final String preStateRoot, final boolean isValid) throws IOException {
    final InputStream inputStream = VerifyProofTest.class.getResourceAsStream(fileName);
    final ExecutionWitnessData executionWitnessData =
        objectMapper.readValue(inputStream, new TypeReference<>() {});
    final Bytes prestateRoot = Bytes.fromHexString(preStateRoot);
    assertThat(verifyPreState(executionWitnessData, prestateRoot)).isEqualTo(isValid);
  }

  private boolean verifyPreState(
      final ExecutionWitnessData executionWitnessData, final Bytes preStateRoot) {
    final List<byte[]> allStemsKeys = new ArrayList<>();
    final List<byte[]> allCurrentValues = new ArrayList<>();
    executionWitnessData.executionWitness.stateDiff.forEach(
        stateDiff -> {
          Bytes stem = Bytes.fromHexString(stateDiff.stem);
          stateDiff.suffixDiffs.forEach(
              suffixDiff -> {
                allStemsKeys.add(
                    Bytes.concatenate(stem, Bytes.of(suffixDiff.suffix)).toArrayUnsafe());
                allCurrentValues.add(
                    ((suffixDiff.currentValue == null)
                            ? Bytes.EMPTY
                            : Bytes.fromHexString(suffixDiff.currentValue))
                        .toArrayUnsafe());
              });
        });
    final byte[][] commitmentsByPath =
        toArray(executionWitnessData.executionWitness.verkleProof.commitmentsByPath);
    final byte[][] allCl = toArray(executionWitnessData.executionWitness.verkleProof.ipaProof.cl);
    final byte[][] allCr = toArray(executionWitnessData.executionWitness.verkleProof.ipaProof.cr);
    final byte[][] allOtherStems =
        toArray(executionWitnessData.executionWitness.verkleProof.otherStems);
    final byte[] d =
        Bytes.fromHexString(executionWitnessData.executionWitness.verkleProof.d).toArrayUnsafe();
    final byte[] depthExtensionPresent =
        Bytes.fromHexString(executionWitnessData.executionWitness.verkleProof.depthExtensionPresent)
            .toArrayUnsafe();
    final byte[] finalEvaluation =
        Bytes.fromHexString(
                executionWitnessData.executionWitness.verkleProof.ipaProof.finalEvaluation)
            .toArrayUnsafe();

    return LibIpaMultipoint.verifyPreStateRoot(
        allStemsKeys.toArray(byte[][]::new),
        allCurrentValues.toArray(byte[][]::new),
        commitmentsByPath,
        allCl,
        allCr,
        allOtherStems,
        d,
        depthExtensionPresent,
        finalEvaluation,
        preStateRoot.toArrayUnsafe());
  }

  private byte[][] toArray(final List<String> elt) {
    return elt.stream().map(Bytes::fromHexString).map(Bytes::toArrayUnsafe).toArray(byte[][]::new);
  }
}
