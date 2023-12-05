local luawasm = require "luawasm"

local instance

local importFuncDefs = {
  env = {
    print = function(addr, len)
      print(instance.loadString(addr, len))
    end,
  },
}

instance = luawasm.instantiate("hello.wasm", importFuncDefs)

instance.exports.main()
