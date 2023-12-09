print("LuaWASM")

local EXTERN_FUNC   = 0x00
local EXTERN_TABLE  = 0x01
local EXTERN_MEM    = 0x02
local EXTERN_GLOBAL = 0x03

local REFTYPE_FUNC   = 0x70
local REFTYPE_EXTERN = 0x6F

local VALTYPE_I32 = 0x7F
local VALTYPE_I64 = 0x7E
local VALTYPE_F32 = 0x7D
local VALTYPE_F64 = 0x7C

local VECTYPE_V128 = 0x7B

local ELEM_KIND_FUNC = 0x00

local function debugn(...)
  if LUAWASM_DEBUG_ON then
    io.write(...)
  end
end

local function debug(...)
  if LUAWASM_DEBUG_ON then
    print(...)
  end
end

local function createCursor(data, start)
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

  function t.peekByte()
    local b = string.byte(data, cursor)
    if b == nil then
      error("Expected another byte at " .. cursor .. ", length " .. string.len(data))
    end
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

  function t.readS64()
    local low = 0
    local high = 0
    local off = 0
    while true do
      local b = t.readByte()
      low = bit32.bor(low, bit32.lshift(bit32.band(b, 0x7f), off))
      high = bit32.bor(high, bit32.lshift(bit32.band(b, 0x7f), off-32))

      off = off + 7

      if bit32.band(b, 0x80) == 0 then
        if off < 32 then
          low = bit32.arshift(bit32.lshift(low, 32-off), 32-off)
          if bit32.band(low, 0x80000000) ~= 0 then
            high = 0xffffffff
          end
        elseif off < 64 then
          high = bit32.arshift(bit32.lshift(high, 64-off), 64-off)
        end
        return low + 0x100000000 * high
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

local moduleIndex = {}
local moduleMt = { __index=moduleIndex }

function moduleIndex:debugDump()
  for i,export in ipairs(self.exports) do
    if export.exportType == EXTERN_FUNC then
      print(export.name)
      for i1,instr in ipairs(self.funcs[1].expr) do
        print(table.unpack(instr))
      end
    end
  end
end

local instanceIndex = {}
local instanceMt = { __index=instanceIndex }

function moduleIndex:instantiate(importDefs)
  local inst = setmetatable({}, instanceMt)

  inst.module = self

  inst.funcs = {}

  for i,import in ipairs(self.imports or {}) do
    if importDefs == nil or importDefs[import.modName] == nil or importDefs[import.modName][import.name] == nil then
      error("Import not defined: " .. import.modName .. "." .. import.name)
    end
    local importDef = importDefs[import.modName][import.name]

    if import.importType == EXTERN_FUNC then
      if type(importDef) ~= "function" then
        error(string.format("Import for `%s.%s` is of incorrect type (got %s, expected function)", import.modName, import.name, type(importDef)))
      end
      table.insert(inst.funcs, { funcType=self.types[import.desc+1], funcKind="host", code=importDef })
    else
      error("Unimplemented import: " .. import.importType)
    end
  end

  for f,func in ipairs(self.funcs) do
    table.insert(inst.funcs, { funcType=self.types[func.funcType+1], funcKind="inst", code=func })
  end

  inst.memories = {}
  for m,memory in ipairs(self.memories) do
    local memoryInst = {}
    for i=1,memory.min*0x10000 do
      memoryInst[i] = 0
    end
    inst.memories[m] = memoryInst
  end

  inst.globals = {}
  for g,glob in ipairs(self.globals or {}) do
    table.insert(inst.globals, inst:evaluate(glob.init, 1, 0))
  end

  for d,data in ipairs(self.datas or {}) do
    if data.mode == "active" then
      local offset = inst:evaluate(data.activeInit.offset, 1, 0)
      local memInst = inst.memories[data.activeInit.memIndex+1]
      for i=1,string.len(data.init) do
        memInst[offset+i] = string.byte(data.init, i)
      end
    end
  end

  inst.exports = {}
  for i,export in ipairs(self.exports) do
    if export.exportType == EXTERN_FUNC then
      local exportDef = inst.funcs[export.index+1]
      if exportDef.funcKind == "host" then
        inst.exports[export.name] = exportDef.code
      elseif exportDef.funcKind == "inst" then
        inst.exports[export.name] = function(...)
          return inst:evaluate(exportDef.code.expr, #exportDef.funcType.returns, #exportDef.funcType.args, ...)
        end
      end
    else
      print("Unimplemented export: " .. export.exportType)
    end
  end

  return inst
end

function instanceIndex:loadString(addr, len)
  local chars = {}
  for i=1,len do
    chars[i] = string.char(self.memories[1][addr+i])
  end
  return table.concat(chars)
end

function instanceIndex:evaluate(instrSeq, returns, args, ...)
  local argsList = {...}
  local locals = {}
  for i=1,args do
    locals[i] = argsList[i]
  end

  -- instrSeq: instruction sequence of continuation
  -- instrPos: position of continuation in sequence
  -- returns: arity of the label
  -- stack: stack of the label
  local labels = {}
  local stack = {}
  local seq = instrSeq
  local pos = 1

  local function push(v)
    stack[#stack + 1] = v
  end

  local function pop()
    if #stack == 0 then
      error("Stack underflow")
    end
    local v = stack[#stack]
    stack[#stack] = nil
    return v
  end

  local function popn(n)
    if #stack < n then
      error("Stack underflow")
    end
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

  local function blockTypeArity(blockType)
    if blockType.typeKind == "empty" then
      return 0, 0
    elseif blockType.typeKind == "inline" then
      return 0, 1
    elseif blockType.typeKind == "func" then
      local funcType = self.module.types[blockType.funcType+1]
      return #funcType.args, #funcType.returns
    end
    error("Block type " .. blockType.typeKind)
  end

  local function doBlock(instrSeq, argc, returnc, labelPos)
    local args = popn(argc)
    labels[#labels+1] = { instrSeq=seq, instrPos=labelPos or pos, stack=stack, returns=returnc }
    stack = {}
    pushn(args)
    seq = instrSeq
    pos = 1
  end

  local function gotoLabel(labelIndex)
    local actualIndex = #labels-labelIndex
    if actualIndex < 0 then
      error("Label underflow")
    elseif actualIndex == 0 then
      -- Function label
      return true
    end
    local label = labels[actualIndex]
    for i=actualIndex,#labels do
      labels[i] = nil
    end
    local returns = popn(label.returns)
    stack = label.stack
    seq = label.instrSeq
    pos = label.instrPos
    pushn(returns)
  end

  while pos <= #seq do
    local instr = seq[pos]
    pos = pos + 1
    local opcode = instr[1]

    if opcode == 0x02 then
      debugn("Block ")
      local argc, returnc = blockTypeArity(instr[2])
      debug(string.format("%d -> %d", argc, returnc))
      doBlock(instr[3], argc, returnc)
    elseif opcode == 0x0D then
      debug("Branch " .. instr[2])
      if gotoLabel(instr[2]) then
        -- Function label, return
        local returns = popn(returns)
        return table.unpack(returns)
      end
    elseif opcode == 0x0F then
      debug("Return")
      local returns = popn(returns)
      return table.unpack(returns)
    elseif opcode == 0x10 then
      debug("Call function " .. instr[2])
      local func = self.funcs[instr[2] + 1]
      local args = popn(#func.funcType.args)

      if func.funcKind == "host" then
        pushn({func.code(table.unpack(args))})
      elseif func.funcKind == "inst" then
        pushn({self:evaluate(func.code.expr, #func.funcType.returns, #func.funcType.args, table.unpack(args))})
      end
    elseif opcode == 0x1A then
      debug("Drop")
      pop()
    elseif opcode == 0x20 then
      debug("Push from local " .. instr[2])
      push(locals[instr[2]+1])
    elseif opcode == 0x21 then
      debug("Pop to local " .. instr[2])
      locals[instr[2]+1] = pop()
    elseif opcode == 0x22 then
      debug("Copy to local " .. instr[2])
      locals[instr[2]+1] = stack[#stack]
    elseif opcode == 0x23 then
      debug("Push from global " .. instr[2])
      push(self.globals[instr[2]+1])
    elseif opcode == 0x24 then
      debug("Pop to global " .. instr[2])
      self.globals[instr[2]+1] = pop()
    elseif opcode == 0x37 then
      debug(string.format("Store i64 (align %d offset %08X)", 2^instr[2], instr[3]))
      local v = pop()
      local i = pop()
      local addr = instr[3] + i
      if addr + 8 > #self.memories[1] then
        error(string.format("Memory address out of bounds (size %08X, address was %08X)", #self.memories[i], addr))
      end
      for i=1,4 do
        self.memories[addr+i] = bit32.band(bit32.rshift(v, (i-1)*8), 0xff)
      end
      local high = math.floor((v - bit32.band(v, 0xffffffff)) / 0x100000000)
      for i=1,4 do
        self.memories[addr+4+i] = bit32.band(bit32.rshift(high, (i-1)*8), 0xff)
      end
    elseif opcode == 0x41 then
      debug("Push immediate i32 " .. instr[2])
      push(instr[2])
    elseif opcode == 0x42 then
      debug("Push immediate i64 " .. instr[2])
      push(instr[2])
    elseif opcode == 0x4B then
      debugn("Compare u32 ")
      local b, a = pop(), pop()
      local res
      if a > b then
        res = 1
      else
        res = 0
      end
      debug(string.format("%d > %d = %d", a, b, res))
      push(res)
    elseif opcode == 0x6A then
      debugn("Add i32 ")
      local b, a = pop(), pop()
      local sum = bit32.band(a + b, 0xffffffff)
      debug(string.format("%d + %d = %d", a, b, sum))
      push(sum)
    elseif opcode == 0x6B then
      debugn("Subtract i32 ")
      local b, a = pop(), pop()
      local diff = bit32.band(a - b, 0xffffffff)
      debug(string.format("%d - %d = %d", a, b, diff))
      push(diff)
    else
      error("Unimplemented instruction: " .. string.format("%02X", opcode))
    end
  end

  debug("Implicit return")

  local returns = popn(returns)
  return table.unpack(returns)
end

local luawasm = {}

function luawasm.load(path)
  local f = io.open(path, "rb")
  local data = f:read("*all")
  f:close()

  local c = createCursor(data)

  c.expect("\0asm\1\0\0\0")

  local mod = {}
  mod.custom = {}

  local function createSection(name, init)
    if mod[name] ~= nil then
      error("Duplicate definition for section " .. name)
    end

    mod[name] = init
    return init
  end

  local function readLimits()
    local hasMax = c.readByte()
    local min = c.readU32()
    local max = nil
    if hasMax ~= 0 then
      max = c.readU32()
    end
    return { min=min, max=max }
  end

  local function readTableType()
    local refType = c.readByte()
    local limits = readLimits()
    return { refType=refType, limits=limits }
  end

  local function readGlobalType()
    local valType = c.readByte()
    local mut = c.readByte() ~= 0
    return { valType=valType, mut=mut }
  end

  local function readBlockType()
    local typeByte = c.peekByte()
    if bit32.band(typeByte, 0x80) ~= 0 then
      return { typeKind="func", funcType=c.readU32() }
    else
      local valType = c.readByte()
      if valType == 0x40 then
        return { typeKind="empty" }
      else
        return { typeKind="inline", valType=valType }
      end
    end
  end

  local function readMemArg()
    return c.readU32(), c.readU32()
  end

  local function readInstrSeq()
    local instr = {}
    while true do
      local opcode = c.readByte()

      if opcode == 0x0B or opcode == 0x05 then
        return instr, opcode
      elseif opcode == 0x00 or opcode == 0x01 or opcode == 0x0F or opcode == 0xD1 or opcode == 0x1A or opcode == 0x1B or opcode >= 0x45 and opcode <= 0xC4 then
        table.insert(instr, { opcode })
      elseif opcode == 0x02 or opcode == 0x03 then
        local blockType = readBlockType()

        local block, stop = readInstrSeq()
        if stop ~= 0x0B then
          error(string.format("Block did not end in 0x0B. Instead, it ended in 0x%02X", stop))
        end

        table.insert(instr, { opcode, blockType, block })
      elseif opcode == 0x04 then
        local blockType = readBlockType()

        local ifBlock, stop = readInstrSeq()
        local elseBlock
        if stop == 0x05 then
          local stop
          elseBlock, stop = readInstrSeq()
          if stop ~= 0x0B then
            error(string.format("Else block did not end in 0x0B. Instead, it ended in 0x%02X", stop))
          end
        elseif stop ~= 0x0B then
          error(string.format("If block did not end in 0x0B or 0x05. Instead, it ended in 0x%02X", stop))
        end

        table.insert(instr, { 0x04, blockType, ifBlock, elseBlock })
      elseif opcode == 0x0C or opcode == 0x0D or opcode == 0x10 or opcode == 0xD2 or opcode >= 0x20 and opcode <= 0x26 then
        table.insert(instr, { opcode, c.readU32() })
      elseif opcode == 0x0E then
        local labelCount = c.readU32()
        local labels = {}
        for i=1,labelCount do
          labels[i] = c.readU32()
        end
        local defaultLabel = c.readU32()
        table.insert(instr, { opcode, labels, defaultLabel })
      elseif opcode == 0x11 then
        table.insert(instr, { 0x11, c.readU32(), c.readU32() })
      elseif opcode >= 0x28 and opcode <= 0x3E then
        table.insert(instr, { opcode, readMemArg() })
      elseif opcode == 0x41 then
        table.insert(instr, { 0x41, c.readS32() })
      elseif opcode == 0x42 then
        table.insert(instr, { 0x42, c.readS64() })
      else
        error(string.format("Unimplemented opcode: 0x%02X", opcode))
      end
    end
  end

  local function readExpr()
    local instr, stop = readInstrSeq()
    if stop ~= 0x0B then
      error(string.format("Expression did not end in 0x0B. Instead, it ended in 0x%02X", stop))
    end
    return instr
  end

  -- Read all sections

  while c.getCursor() <= string.len(data) do
    local sectionId = c.readByte()
    local sectionSize = c.readU32()
    local nextSection = c.getCursor() + sectionSize

    if sectionId == 0 then
      local customName = c.readName()
      local customData = string.sub(data, c.getCursor(), nextSection - 1)
      table.insert(mod.custom, { name=customName, data=customData })
      c.setCursor(nextSection)
    elseif sectionId == 1 then
      local types = createSection("types", {})
      local typeCount = c.readU32()
      for i=1,typeCount do
        c.expect("\x60")
        local funcType = {
          args = {},
          returns = {},
        }

        local argCount = c.readU32()
        for j=1,argCount do
          funcType.args[j] = c.readByte()
        end
        local retCount = c.readU32()
        for j=1,retCount do
          funcType.returns[j] = c.readByte()
        end

        types[i] = funcType
      end
    elseif sectionId == 2 then
      local imports = createSection("imports", {})
      local importCount = c.readU32()
      for i=1,importCount do
        local modName = c.readName()
        local name = c.readName()
        local importType = c.readByte()
        local importDesc = nil
        if importType == EXTERN_FUNC then
          -- Function
          importDesc = c.readU32()
        elseif importType == EXTERN_TABLE then
          -- Table
          importDesc = readTableType()
        elseif importType == EXTERN_MEM then
          -- Memory
          importDesc = readLimits()
        elseif importType == EXTERN_GLOBAL then
          -- Global
          importDesc = readGlobalType()
        end
        imports[i] = {
          modName = modName,
          name = name,
          importType = importType,
          desc = importDesc,
        }
      end
    elseif sectionId == 3 then
      local funcs = createSection("funcs", {})
      local funcCount = c.readU32()
      for i=1,funcCount do
        funcs[i] = c.readU32()
      end
    elseif sectionId == 4 then
      local tables = createSection("tables", {})
      local tableCount = c.readU32()
      for i=1,tableCount do
        tables[i] = readTableType()
      end
    elseif sectionId == 5 then
      local memories = createSection("memories", {})
      local memoryCount = c.readU32()
      for i=1,memoryCount do
        memories[i] = readLimits()
      end
    elseif sectionId == 6 then
      local globals = createSection("globals", {})
      local globalCount = c.readU32()
      for i=1,globalCount do
        local globalType = readGlobalType()
        local init = readExpr()
        globals[i] = { globalType=globalType, init=init }
      end
    elseif sectionId == 7 then
      local exports = createSection("exports", {})
      local exportCount = c.readU32()
      for i=1,exportCount do
        local name = c.readName()
        local exportType = c.readByte()
        local exportIndex = c.readU32()
        exports[i] = {
          name = name,
          exportType = exportType,
          index = exportIndex,
        }
      end
    elseif sectionId == 8 then
      createSection("start", c.readU32())
    elseif sectionId == 9 then
      local elements = createSection("elements", {})
      local elementCount = c.readU32()
      for i=1,elementCount do
        local elemBits = c.readU32()

        local mode, activeInit
        if bit32.band(elemBits, 0x1) == 0 then
          mode = "active"

          activeInit = { tableIndex=0 }
          if bit32.band(elemBits, 0x2) ~= 0 then
            activeInit.tableIndex = c.readU32()
          end

          activeInit.offset = readExpr()
        else
          if bit32.band(elemBits, 0x2) == 0 then
            mode = "passive"
          else
            mode = "declarative"
          end
        end

        -- Segment initializer
        local elemType, initType, init
        if bit32.band(elemBits, 0x4) == 0 then
          initType = "index"

          if bit32.band(elemBits, 0x3) == 0 then
            elemKind = ELEM_KIND_FUNC
          else
            elemKind = c.readByte()
          end

          init = {}
          local indexCount = c.readU32()
          for j=1,indexCount do
            init[j] = c.readU32()
          end
        else
          initType = "expr"

          if bit32.band(elemBits, 0x3) == 0 then
            elemKind = REFTYPE_FUNC
          else
            elemKind = c.readByte()
          end

          init = {}
          local exprCount = c.readU32()
          for j=1,exprCount do
            init[j] = readExpr()
          end
        end

        elements[i] = {
          mode=mode,
          activeInit=activeInit,
          elemKind=ELEM_KIND_FUNC,
          initType=initType,
          init=init,
        }
      end
    elseif sectionId == 10 then
      local codes = createSection("codes", {})
      local codeCount = c.readU32()
      for i=1,codeCount do
        local size = c.readU32()
        local locals = {}
        local localCount = c.readU32()
        for j=1,localCount do
          locals[j] = { count=c.readU32(), valType=c.readByte() }
        end
        local expr = readExpr()
        codes[i] = { locals=locals, expr=expr }
      end
    elseif sectionId == 11 then
      local datas = createSection("datas", {})
      local dataCount = c.readU32()
      for i=1,dataCount do
        local dataBits = c.readU32()

        local mode, activeInit
        if bit32.band(dataBits, 0x1) == 0 then
          mode = "active"
          activeInit = { memIndex=0 }

          if bit32.band(dataBits, 0x2) ~= 0 then
            activeInit.memIndex = c.readU32()
          end

          activeInit.offset = readExpr()
        else
          mode = "passive"
        end

        local byteCount = c.readU32()
        local init = string.sub(data, c.getCursor(), c.getCursor()+byteCount-1)
        c.setCursor(c.getCursor() + byteCount)

        datas[i] = {
          mode=mode,
          activeInit=activeInit,
          init=init,
        }
      end
    elseif sectionId == 12 then
      createSection("dataCount", c.readU32())
    end
  end

  -- Done reading all sections. Post-process data.

  if mod.dataCount ~= nil and mod.dataCount ~= #mod.datas then
    error(string.format("Data count does not match (%d declared, %d defined)", mod.dataCount, #mod.datas))
  end

  if #mod.funcs ~= #mod.codes then
    error(string.format("Function and code counts do not match (%d functions, %d codes)", #mod.funcs, #mod.codes))
  end

  local funcs, codes = mod.funcs, mod.codes
  mod.codes = nil
  mod.funcs = {}

  for i=1,#funcs do
    mod.funcs[i] = codes[i]
    mod.funcs[i].funcType = funcs[i]
  end

  return setmetatable(mod, moduleMt)
end

function luawasm.instantiate(path, importDefs)
  local mod = luawasm.load(path)
  return mod:instantiate(importDefs)
end

return luawasm
