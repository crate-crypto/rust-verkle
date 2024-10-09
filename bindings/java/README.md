# Java

## Overview

This directory contains the bindings for the java gradle project. There are two sub directories, `java_code` and `rust_code`.

- `rust_code` contains the FFI code that will be called by the Java code.

It also contains code in the `build.rs` file that generates a C file which will indicate what the function signatures for these rust methods should look like based on the Java methods defined in `java_code`.

- `java_code` contains the java code that will interface with the compiled rust code in `rust_code` and expose an API allowing java packages to execute DAS related methods.

## Building

There are two steps to building:

- Building the dynamic library
- Building the java code

### Building the dynamic library

These easiest way to build the dynamic library, is to call `scripts/compile.sh`. This is located at the root of the directory. Calling this script will compile the necessary code for your platform and copy the dynamic library into the relevant directory in `java_code`. This is the `resources` folder.

Once the script has been called, one can view the code in `java_code` as being self-contained.

### Building the Java code

Once the dynamic library has been built and copied into `java_code`, the instructions to build the java codebase follows a regular gradle project:

```
./gradlew build
```

## Testing

Given that we have successfully built the dynamic lib. To test, we can run:

```
/gradlew test
```

## Publishing

The `.scripts/compile.sh` script will compile for your particular platform, however the released package will contain
dynamic libraries for all relevant platforms, making the `JAR` file _universal_ in theory.

## Supported Platforms

We currently support:

- Windows x86_64
- Linux (x86_64 and arm64)
- Mac (x86_64 and arm64)
