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

// import com.sun.jna.Native;

// import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Java interface to ipa-multipoint, a rust library that supports computing polynomial commitments.
 *
 * The library relies on the bandersnatch curve described at https://eprint.iacr.org/2021/1152.pdf.
 *
 */
public class LibIpaMultipoint {

  @SuppressWarnings("WeakerAccess")
  private static volatile boolean ENABLED;

  private static final Object libraryLock = new Object();

  static {
    ensureLibraryLoaded();
  }

  /**
   * Commit to a vector of values.
   *
   * @param values vector of serialised scalars to commit to.
   * @return uncompressed serialised commitment.
   */
  public static native byte[] commit(byte[] values);

  /**
   * Commit to a vector of values and compress commitment.
   *
   * @param values vector of serialised scalars to commit to.
   * @return compressed serialised commitment.
   */
  public static native byte[] commitAsCompressed(byte[] values);

  /**
   * Update a commitment with a sparse vector.
   *
   * @param commitment uncompressed serialised commitment.
   * @param indices indices in value vector to update.
   * @param oldValues old serialised scalars to update.
   * @param newValues new serialised scalars.
   * @return uncompressed serialised commitment.
   */
  public static native byte[] updateSparse(byte[] commitment, byte[] indices, byte[] oldValues, byte[] newValues);

  /**
   * Compresses a commitment.
   *
   * Converts a serialised commitment from uncompressed to compressed form.
   *
   * @param commitment uncompressed serialised commitment.
   * @return compressed serialised commitment.
   */
  public static native byte[] compress(byte[] commitment);

  /**
   * Compresses many commitments.
   *
   * Converts a serialised commitment from uncompressed to compressed form.
   *
   * @param commitments uncompressed serialised commitments.
   * @return compressed serialised commitments.
   */
  public static native byte[] compressMany(byte[] commitments);

  /**
   * Convert a commitment to its corresponding scalar.
   *
   * @param commitment uncompressed serialised commitment
   * @return serialised scalar
   */
  public static native byte[] hash(byte[] commitment);

  /**
   * Map a vector of commitments to its corresponding vector of scalars.
   *
   * The vectorised version is highly optimised, making use of Montgoméry's batch
   * inversion trick.
   *
   * @param commitments uncompressed serialised commitments
   * @return serialised scalars
   */
  public static native byte[] hashMany(byte[] commitments);

  /**
   * Verifies the Verkle proof against the specified pre-state root
   * <p>
   * This method interfaces with a native Rust implementation to verify a Verkle proof
   * against the specified pre-state root.
   * </p>
   *
   * @param keys accessed or modified keys
   * @param currentValues current values associated with the keys.
   * @param commitmentsByPath commitments along the path in the Verkle trie.
   * @param cl left commitments in the IPA proof.
   * @param cr right commitments in the IPA proof.
   * @param otherStems others stems that are present.
   * @param d aggregated commitment to the polynomial D in the IPA proof.
   * @param depthsExtensionPresentStems depths and extension presence for each stem.
   * @param finalEvaluation final evaluation point in the IPA proof.
   * @param prestateRoot root of the prestate to be verified against.
   * @return true if prestate root is correct
   */
  public static native boolean verifyPreStateRoot(byte[][] keys,
                                                  byte[][] currentValues,
                                                  byte[][] commitmentsByPath,
                                                  byte[][] cl,
                                                  byte[][] cr,
                                                  byte[][] otherStems,
                                                  byte[] d,
                                                  byte[] depthsExtensionPresentStems,
                                                  byte[] finalEvaluation,
                                                  byte[] prestateRoot);

    // TODO:Replace the code below with jna.Native
                                          
    private static final String LIBRARY_NAME = "java_verkle_cryptography";

    private static String getNormalizedArchitecture() {
      String osArch = System.getProperty("os.arch").toLowerCase();
      if (osArch.equals("x86_64") || osArch.equals("amd64")) {
        return "x86_64";
      } else if (osArch.equals("aarch64") || osArch.equals("arm64")) {
        return "aarch64";
      } else {
        return osArch;
      }
    }
    
    private static void ensureLibraryLoaded() {
      if (!ENABLED) {
        synchronized (libraryLock) {
          if (!ENABLED) {
            loadNativeLibrary();
            ENABLED = true;
          }
        }
      }
    }

    /** Loads the appropriate native library based on your platform. */
    private static void loadNativeLibrary() {
      String PLATFORM_NATIVE_LIBRARY_NAME = System.mapLibraryName(LIBRARY_NAME);

        String osName = System.getProperty("os.name").toLowerCase();
        String osArch = getNormalizedArchitecture();
        String libraryResourcePath = null;

        if (osName.contains("win")) {
            if (osArch.contains("x86_64")) {
                libraryResourcePath = "/x86_64-pc-windows-gnu/" + PLATFORM_NATIVE_LIBRARY_NAME;
            } else if (osArch.contains("x86")) {
                // We do not support 32 bit windows
            } else if (osArch.contains("aarch64")) {
                // We currently do not support arm on windows
            }
        } else if (osName.contains("mac")) {
            if (osArch.contains("x86_64")) {
                libraryResourcePath = "/x86_64-apple-darwin/" + PLATFORM_NATIVE_LIBRARY_NAME;
              } else if (osArch.contains("aarch64")) {
                libraryResourcePath = "/aarch64-apple-darwin/" + PLATFORM_NATIVE_LIBRARY_NAME;
            }
        } else if (osName.contains("linux")) {
            if (osArch.contains("x86_64")) {
                libraryResourcePath = "/x86_64-unknown-linux-gnu/" + PLATFORM_NATIVE_LIBRARY_NAME;
            } else if (osArch.contains("aarch64")) {
                libraryResourcePath = "/aarch64-unknown-linux-gnu/" + PLATFORM_NATIVE_LIBRARY_NAME;
            }
        }

        if (libraryResourcePath == null) {
          throw new UnsupportedOperationException("Unsupported OS or architecture: " + osName + ", " + osArch);
        }

        InputStream libraryResource = LibIpaMultipoint.class.getResourceAsStream(libraryResourcePath);

        if (libraryResource == null) {
            try {
                System.loadLibrary(LIBRARY_NAME);
            } catch (UnsatisfiedLinkError __) {
                String exceptionMessage =
                        String.format(
                                "Couldn't load native library (%s). It wasn't available at %s or the library path.",
                                LIBRARY_NAME, libraryResourcePath);
                throw new RuntimeException(exceptionMessage);
            }
          } else {
            try {
                Path tempDir = Files.createTempDirectory(LIBRARY_NAME + "@");
                tempDir.toFile().deleteOnExit();
                Path tempDll = tempDir.resolve(PLATFORM_NATIVE_LIBRARY_NAME);
                tempDll.toFile().deleteOnExit();
                Files.copy(libraryResource, tempDll, StandardCopyOption.REPLACE_EXISTING);
                libraryResource.close();
                System.load(tempDll.toString());
            } catch (IOException ex) {
                throw new UncheckedIOException(ex);
            }
        }
    }

}
