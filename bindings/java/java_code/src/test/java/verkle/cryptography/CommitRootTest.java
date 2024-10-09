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
package verkle.cryptography;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import verkle.cryptography.LibIpaMultipoint;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class CommitRootTest {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static List<TestData> JsonData() throws IOException {
        InputStream inputStream = PedersenCommitmentTest.class.getResourceAsStream("/commit_root_test.json");
        return objectMapper.readValue(inputStream, new TypeReference<List<TestData>>() {
        });
    }

    static class TestData {
        public ArrayList<String> frs;
        public String expected;
    }

    @ParameterizedTest
    @MethodSource("JsonData")
    public void TestPolynomialCommitments(TestData testData) {
        List<Bytes> FrBytes = new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            Bytes32 value = Bytes32.fromHexString(testData.frs.get(i));
            FrBytes.add(value.reverse());
        }
        byte[] input = Bytes.concatenate(FrBytes).toArray();
        Bytes32 result = Bytes32.wrap(LibIpaMultipoint.commitAsCompressed(input));
        Bytes32 expected = Bytes32.fromHexString(testData.expected);
        assertThat(result).isEqualTo(expected);
    }
}
