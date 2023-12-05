local luawasm = require "luawasm"

local instance = luawasm.instantiate("add.wasm", {})

print("1 + 2 = " .. instance.exports.add(1, 2))
