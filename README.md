# CPPU
CPPU is a highly portable, user space CPU emulator written in C++

The plan is to emulate enough CPU instructions for a given CPU platform (e.g. x86-64) to execute any executable in user space.
Syscalls are forwarded to a C++ backend which implements certain kernel functionality directly to allow the executable to run in a complete sandbox.

# Features
- Support for x86-64
- Support for basic Linux64 syscalls
- Support to load ELF binaries directly (e.g. execute an binary as `cppu mybinary`)
  - Initially, support only statically linked x86-64 Linux binaries

## Future Features
The following features are not planned but may exist in the future
- dynamic library loading support
- multi-threading
- other CPU architectures

# Motivation
The main goal is not to have a high-performance environment but an educational, easily portable way to execute binaries on any platform without a runtime environment.

# License

cppu is distributed under the MIT
[license](https://github.com/matthiasstraka/cppu/blob/main/LICENSE).
