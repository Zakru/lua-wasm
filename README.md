# Lua-WASM

This project is a [WebAssembly](https://webassembly.org) 1.0 runtime
implementation in pure Lua. The project is still a work in progress, and should
not be relied upon yet.

Additionally, the project aims to be usable in [CC:
Tweaked](https://tweaked.cc/), and therefore will ultimately not target any
official Lua version, but rather CC: Tweaked's JLua-based (Lua 5.2-compliant)
runtime with backported features from 5.3.

## List of implemented features

* Reading of WebAssembly's type, import, function, memory, export, code and data
  sections (and skipping others)
* Initialization of active data segments
* Execution of enough instructions to run a hello world program and an addition
  program
  * Supports proper function stacks, with locals, arguments and returns
  * The stack is implemented using recursive calls and block-specific stacks
  * Can print to the console using a user-provided imported function
  * Exported functions can be called from Lua like an ordinary function

## Seeing it in action

This project currently targets a Lua runtime of version 5.3. To compile the
hello world module, ensure that you have installed Rust and the
`wasm32-unknown-unknown` target. Use one of the following commands to compile a
module into a `.wasm` binary.

```sh
rustc --target wasm32-unknown-unknown hello.rs
rustc -C opt-level=3 --target wasm32-unknown-unknown hello.rs # Compile with optimizations
```

Then, assuming you are in the same directory with the compiled `.wasm` module
and the corresponding example Lua script, run the script.

## Does this mean I can create optimized programs in another language and run them blazingly fast in Lua?

lol no

To elaborate, this implementation is subject to the overhead of your Lua
runtime, and your WebAssembly code is subject to the overhead of this
implementation. That means your code runs on my code running on Lua code.
Emulation tends to be exponentially slow the more layers you add on top of each
other, and so your code will probably run slower than the equivalent Lua code.
But hey, at least you can program in any language that compiles to WebAssembly.
I think the novelty outweighs the cost — especially in the final target of
Minecraft computers, where novelty is practically the driving force — many times
over.

## Future goals

* Implement all [WASM 1.0
  instructions](https://webassembly.github.io/spec/core/binary/instructions.html)
* Create a separate project containing utilities for usage with CC: Tweaked,
  including
  * A program loader
  * A shell capable of/patches to existing software to enable executing WASM
    programs as commands
  * A partial and/or extended implementation of
    [WASI](https://github.com/WebAssembly/WASI/blob/main/Proposals.md)
  * Note that the projects are intended to be separate such that the code of
    this project contains no references to CC.
* Look into compiling WebAssembly into Lua code. Static solutions such as
  [wasm2lua](https://github.com/SwadicalRag/wasm2lua) exist.
  * Pros of a static approach over luawasm
    * No runtime required. Compilation of the Lua code is done at build time and
      therefore the end user can run the code seamlessly.
    * End user doesn't need to be aware of the extra steps
  * Cons of a static approach ("Cope with sunken cost fallacy after finding
    wasm2lua")
    * (wasm2lua-specific) Documentation is lacking (Target Lua version unclear,
      how imports are used). Requires Node.js.
    * Takes another build step
    * Does not fit the use case where a user wants to run arbitrary WebAssembly
      from Lua
    * Sandboxing is more difficult
  * Whereas luawasm requires the end user to have the runtime, wasm2lua moves
    this burden to the developer's side, although this assumption breaks if the
    user wants to integrate other pre-existing WebAssembly to the program.
  * Whether dynamic or static, compilation to Lua would undeniably speed up
    execution.
