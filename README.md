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
* Initialization of one active data segment
* Execution of enough instructions to run a hello world program and an addition
  program
  * Supports proper function stacks, with locals, arguments and returns
  * The stack is implemented very literally from the specification
  * Prints to the console using a user-provided import function
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
