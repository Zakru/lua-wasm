local luawasm = require "luawasm"

local importFuncDefs = {
  env = {
    print = function(addr, len)
      print(loadString(addr, len))
    end,
  },
}

local instance = luawasm.instantiate("hello.wasm", importFuncDefs)

instance.exports.main()
