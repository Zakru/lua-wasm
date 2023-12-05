print("LuaWASM")

-- LUAWASM_DEBUG_ON = true

local function debug(...)
  if LUAWASM_DEBUG_ON then
    print(...)
  end
end

local luawasm = {}

function luawasm.instantiate(path, importFuncDefs)
  local f = io.open(path, "rb")

  local data, other = f:read("*all")
  f:close()
  print("Data length " .. string.len(data))

  local function createCursor(start)
    local cursor = start or 1

    local t = {}

    function t.readByte()
      local b = string.byte(data, cursor)
      if b == nil then
        error("Expected another byte at " .. cursor .. ", length " .. string.len(data))
      end
      cursor = cursor + 1
      return b
    end

    function t.readU32()
      local i = 0
      local off = 0
      while true do
        local b = t.readByte()
        i = bit32.bor(i, bit32.lshift(bit32.band(b, 0x7f), off))

        if bit32.band(b, 0x80) == 0 then return i end

        off = off + 7
      end
    end

    function t.readS32()
      local i = 0
      local off = 0
      while true do
        local b = t.readByte()
        i = bit32.bor(i, bit32.lshift(bit32.band(b, 0x7f), off))

        off = off + 7

        if bit32.band(b, 0x80) == 0 then
          if off > 32 then
            off = 32
          end
          return bit32.arshift(bit32.lshift(i, 32-off), 32-off)
        end
      end
    end

    function t.readName()
      local len = t.readU32()
      local name = string.sub(data, cursor, cursor+len-1)
      t.skipBytes(len)
      return name
    end

    function t.skipBytes(n)
      cursor = cursor + n
    end

    function t.expect(expected)
      local len = string.len(expected)
      local actual = string.sub(data, cursor, cursor+len-1)
      if actual ~= expected then
        error("Got unexpected data: " .. actual)
      end
      t.skipBytes(len)
    end

    function t.getCursor()
      return cursor
    end

    function t.setCursor(c)
      cursor = c
    end

    return t
  end

  local c = createCursor()

  c.expect("\0asm\1\0\0\0")

  local memories = {}
  local memInst = {}
  local funcTypes = {}
  local importFuncs = {}
  local funcs = {}
  local funcsType = {}
  local exportFuncs = {}
  local datas = {}

  local function loadString(addr, len)
    local chars = {}
    for i=1,len do
      chars[i] = string.char(memInst[1][addr+i])
    end
    return table.concat(chars)
  end

  while c.getCursor() <= string.len(data) do
    local secType = c.readByte()
    print("Section type " .. secType)
    local l = c.readU32()
    print("Section length " .. l)

    if secType == 1 then
      for typei=1,c.readU32() do
        c.expect("\x60")
        local argc = c.readU32()
        c.skipBytes(argc)
        local retc = c.readU32()
        c.skipBytes(retc)
        table.insert(funcTypes, { args=argc, returns=retc })
      end
    elseif secType == 2 then
      for importi=1,c.readU32() do
        local mod = c.readName()
        local name = c.readName()
        local imtype = c.readByte()
        local imidx = c.readU32()
        print("import", name, imtype, imidx)
        if imtype == 0 then
          table.insert(importFuncs, { mod=mod, name=name, funcType=imidx })
        end
      end
    elseif secType == 3 then
      for funci=1,c.readU32() do
        local typei = c.readU32()
        table.insert(funcsType, typei)
      end
    elseif secType == 5 then
      for memi=1,c.readU32() do
        local hasmax = c.readByte()
        local min = c.readU32()
        local max = nil
        if hasmax ~= 0 then
          max = c.readU32()
        end
        table.insert(memories, { min=min, max=max })
        local init = {}
        for i=1,min*0x10000 do
          init[i] = 0
        end
        table.insert(memInst, init)
        print("Mem " .. memi - 1, min, max)
      end
    elseif secType == 7 then
      for exporti=1,c.readU32() do
        local name = c.readName()
        local extype = c.readByte()
        local exidx = c.readU32()
        print("export", name, extype, exidx)
        if extype == 0 then
          exportFuncs[name] = exidx
        end
      end
    elseif secType == 10 then
      -- Code section
      local codeCount = c.readU32()
      for codei=1,codeCount do
        local codeLen = c.readU32()
        local codeEnd = c.getCursor() + codeLen
        print(codeEnd)

        -- Skip locals
        local localsCount = c.readU32()
        for localsi=1,localsCount do
          c.readU32() -- number of repeats
          c.readByte() -- valtype
        end

        -- Record start of function code
        table.insert(funcs, c.getCursor())

        c.setCursor(codeEnd)
      end
    elseif secType == 11 then
      local dataEnd = c.getCursor() + l
      -- Data section
      local dataCount = c.readU32()
      for datai=1,dataCount do
        local bits = c.readU32()
        if bits == 0 then
          table.insert(datas, c.getCursor())
        else
          error("Non-active-zero-page data segments unsupported")
        end
      end
      c.setCursor(dataEnd)
    else
      if secType ~= 0 then print("UNIMPLEMENTED") end
      c.skipBytes(l)
    end
  end

  local function execute(c, returns, ...)
    local stack = {}
    -- The spec defines that conceptually the last frame on the stack is the current frame,
    -- but we
    local currentFrame = setmetatable({ returns=returns, returnAddr=nil, locals={...} }, { frame = true })

    local function push(v)
      stack[#stack + 1] = v
    end

    local function pop()
      local v = stack[#stack]
      stack[#stack] = nil
      return v
    end

    local function popn(n)
      local start = #stack - n
      local vs = {}
      for i=1,n do
        vs[i] = stack[start+i]
        stack[start+i] = nil
      end
      return vs
    end

    local function pushn(vs)
      local start = #stack
      for i,v in ipairs(vs) do
        stack[start+i] = v
      end
    end

    local function pushFrame(args, returns)
      local newFrame = setmetatable({ returns=returns, returnAddr=c.getCursor(), locals=popn(args) }, { frame = true })
      stack[#stack + 1] = currentFrame
      currentFrame = newFrame
    end

    local function popFrame()
      currentFrame = stack[#stack]
      stack[#stack] = nil
    end

    local function isFrame()
      if type(stack[#stack]) ~= "table" then return false end
      mt = getmetatable(stack[#stack])
      return mt ~= nil and mt.frame == true
    end

    while true do
      local nextInstr = c.readByte()

      if nextInstr == 0x0B then
        debug("Implicit return")
        local returns = popn(currentFrame.returns)
        if currentFrame.returnAddr == nil then
          return table.unpack(returns)
        end
        c.setCursor(currentFrame.returnAddr)
        popFrame()
        pushn(returns)
      elseif nextInstr == 0x0F then
        debug("Return")
        local returns = popn(currentFrame.returns)
        if currentFrame.returnAddr == nil then
          return table.unpack(returns)
        end
        c.setCursor(currentFrame.returnAddr)
        while not isFrame() do
          pop()
        end
        popFrame()
        pushn(returns)
      elseif nextInstr == 0x10 then
        local imm = c.readU32()
        debug("Call function " .. imm)
        if imm < #importFuncs then
          local func = importFuncs[imm + 1]
          local ftype = funcTypes[func.funcType + 1]
          debug(string.format("Imported function %s.%s (%d -> %d)", func.mod, func.name, ftype.args, ftype.returns))
          importFuncDefs[func.mod][func.name](table.unpack(popn(ftype.args)))
        else
          local funci = imm - #importFuncs
          local func = funcs[funci + 1]
          local ftype = funcTypes[funcsType[funci + 1] + 1]
          debug(string.format("%d -> %d", ftype.args, ftype.returns))
          pushFrame(ftype.args, ftype.returns)
          c.setCursor(func)
        end
      elseif nextInstr == 0x1A then
        debug("Drop")
        pop()
      elseif nextInstr == 0x20 then
        local imm = c.readU32()
        debug("Push from local " .. imm)
        push(currentFrame.locals[imm+1])
      elseif nextInstr == 0x21 then
        local imm = c.readU32()
        debug("Pop to local " .. imm)
        currentFrame.locals[imm+1] = pop()
      elseif nextInstr == 0x41 then
        local imm = c.readS32()
        debug("Push immediate i32 " .. imm)
        push(imm)
      elseif nextInstr == 0x6A then
        local b, a = pop(), pop()
        local sum = bit32.band(a + b, 0xffffffff)
        debug(string.format("Add i32 %d + %d = %d", a, b, sum))
        push(sum)
      else
        error("Unknown instruction: " .. string.format("%02X", nextInstr))
      end
    end
  end

  for di,data in ipairs(datas) do
    local c = createCursor(data)
    local offset = execute(c, 1)
    local len = c.readU32()
    local mem = memInst[0+1]
    for i=1,len do
      mem[offset+i] = c.readByte()
    end
  end

  local wrappedExports = {}

  for k,v in pairs(exportFuncs) do
    local funci = v
    local codei = funci - #importFuncs + 1
    local ftype = funcTypes[funcsType[codei]+1]
    wrappedExports[k] = function(...)
      return execute(createCursor(funcs[codei]), ftype.returns, ...)
    end
  end

  return {
    exports=wrappedExports,
    loadString=loadString
  }
end

return luawasm
