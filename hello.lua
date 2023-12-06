local luawasm = require "luawasm"

local instance

local importDefs = {
  env = {
    print = function(addr, len)
      print(instance:loadString(addr, len))
    end,
  },
}

instance = luawasm.instantiate("hello.wasm", importDefs)

instance.exports.main()
