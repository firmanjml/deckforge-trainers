-- DeckForge GameMaker runtime resolver (port of the former Rust resolver).
--
-- Discovers the GameMaker runtime metadata (NameList / ObjectList /
-- CScriptList, object table, property tables) inside the attached process and
-- resolves `object.property` into a concrete memory address — the same
-- strategy as the Cheat Engine GameMaker tables. Initialization scans
-- internally and automatically; failures raise Lua errors (never silent
-- fallback to value guessing).
--
-- Usage from a resolver:
--   return gm_addr('BaseGame', 'player_health')
--
-- Discovery state is cached in the global `gm` table; the shared VM resets on
-- process exit, so stale discovery never survives a game restart.

gm = gm or {}

local T = trainer

-- ---------------------------------------------------------------------------
-- Reader helpers (pointer-width aware; nil on unreadable memory)
-- ---------------------------------------------------------------------------

-- Pointer width is resolved lazily on first use: the library must load
-- cleanly without an attached process (the VM boots before attach).
local PS, IS64
local function init_width()
  if PS then return end
  PS = T.pointer_size() -- 8 or 4
  IS64 = PS == 8
end

local function valid_ptr(v)
  if v == nil then return false end
  if IS64 then
    return v >= 0x10000 and v < 0x0000800000000000
  else
    return v >= 0x10000 and v <= 0xFFFFF000
  end
end

-- CE readPointer semantics: nil on unreadable *or* implausible value.
local function read_ptr(addr)
  local ok, v = pcall(T.read_pointer, addr)
  if not ok or not valid_ptr(v) then return nil end
  return v
end

-- Raw pointer read: nil only when the memory itself is unreadable (a readable
-- 0 is a value, matching CE's readPointer nil semantics).
local function read_ptr_raw(addr)
  local ok, v = pcall(T.read_pointer, addr)
  if not ok then return nil end
  return v
end

local function read_i32(addr)
  local ok, v = pcall(T.read_i32, addr)
  if not ok then return nil end
  return v
end

local function read_cstr(addr, max)
  local ok, v = pcall(T.read_string, addr, math.min(max or 128, 4096))
  if not ok or v == nil or #v == 0 then return nil end
  return v
end

local function is_mapped(addr)
  return T.region_of(addr) ~= nil
end

-- Read `count` pointer-sized slots starting at `addr` into an array.
local function read_ptr_array(addr, count)
  local ok, data = pcall(T.read_block, addr, count * PS)
  if not ok then return nil end
  local out = {}
  local fmt = IS64 and "<I8" or "<I4"
  for i = 1, count do
    out[i] = string.unpack(fmt, data, (i - 1) * PS + 1)
  end
  return out
end

-- GameMaker name validity (CE charset filter: [^%w_@] rejected, empty
-- rejected, "xxx" rejected).
function gm.valid_name(s)
  return s ~= nil
    and #s > 0
    and #s <= 128
    and not s:find("[^%w_@]")
    and not s:find("xxx")
end
local valid_gm_name = gm.valid_name

local function dlog(...)
  -- Debug logging gated on the engine's own debug flag style.
  if gm.debug then T.log(...) end
end

-- ---------------------------------------------------------------------------
-- Region scanning (CE stringscan / sigscan / pointerscan equivalents)
-- ---------------------------------------------------------------------------

local CHUNK = 4 * 1024 * 1024

-- All regions (cached per call).
local function regions()
  return T.regions()
end

-- Find every occurrence of `needle` (a Lua string of raw bytes) in regions
-- matching `filter(region)`, chunked, overlap-safe.
local function scan_regions_for_bytes(regs, needle, max_hits)
  local hits = {}
  if #needle == 0 then return hits end
  for _, r in ipairs(regs) do
    if #hits >= max_hits then break end
    if r.readable and r.size > 0 and r.size <= 512 * 1024 * 1024 then
      local overlap = #needle - 1
      local offset = 0
      while offset < r.size do
        local back = math.min(overlap, offset)
        local addr = r.base + offset - back
        local chunk_size = math.min(CHUNK + back, r.size - (offset - back))
        local ok, data = pcall(T.read_block, addr, chunk_size)
        if ok then
          local new_start = r.base + offset
          local i = 1
          while true do
            local s, _ = data:find(needle, i, true)
            if not s then break end
            local abs = addr + s - 1
            if abs + #needle > new_start then
              hits[#hits + 1] = abs
              if #hits >= max_hits then return hits end
            end
            i = s + 1
          end
        end
        offset = offset + math.min(CHUNK, r.size - offset)
      end
    end
  end
  return hits
end

-- ---------------------------------------------------------------------------
-- Discovery: locate NameList / ObjectList / CScriptList
-- ---------------------------------------------------------------------------

local function read_size_of_image(base)
  local ok, e_lfanew = pcall(T.read_u32, base + 0x3C)
  if not ok then return nil end
  local ok2, v = pcall(T.read_u32, base + e_lfanew + 24 + 0x38)
  if not ok2 then return nil end
  return v
end

local function module_span(module)
  local m = T.find_module(module)
  if not m then error("module not found: " .. module) end
  local size = read_size_of_image(m.base) or (64 * 1024 * 1024)
  return m.base, m.base + size
end

-- x64: find `lea r64, [rip+disp]` instructions (48 8D ...) whose resolved
-- target equals `target`, within the module's executable span.
local function find_lea_refs(target, lo, hi)
  local regs = {}
  for _, r in ipairs(regions()) do
    if r.readable and r.executable and r.base < hi and (r.base + r.size) > lo then
      regs[#regs + 1] = {
        base = math.max(r.base, lo),
        size = math.min(r.base + r.size, hi) - math.max(r.base, lo),
        readable = true,
      }
    end
  end
  local hits = scan_regions_for_bytes(regs, "\x48\x8D", 4096)
  local refs = {}
  for _, h in ipairs(hits) do
    -- Decode a short window; the lea is the first instruction, its
    -- rip-relative target (if any) is the first address operand.
    local ok, targets = pcall(T.disasm_targets, h, 8)
    if ok and targets and targets[1] == target then
      refs[#refs + 1] = h
    end
  end
  return refs
end

-- x86: find 4-byte pointers to `target` (CE pointerscan). Module first, then
-- all readable regions as a fallback.
local function find_pointer_refs(target, lo, hi)
  local needle = string.pack("<I4", target)
  local mod_regs = {}
  for _, r in ipairs(regions()) do
    if r.readable and r.base < hi and (r.base + r.size) > lo then
      mod_regs[#mod_regs + 1] = {
        base = math.max(r.base, lo),
        size = math.min(r.base + r.size, hi) - math.max(r.base, lo),
        readable = true,
      }
    end
  end
  local hits = scan_regions_for_bytes(mod_regs, needle, 256)
  if #hits > 0 then return hits end
  dlog("[GameMaker] no in-module refs; scanning all regions")
  return scan_regions_for_bytes(regions(), needle, 256)
end

-- CE findAddress: decode a short window and harvest pointer-like address
-- operands (deduped, in instruction order).
local function harvest_address_operands(from, len)
  local ok, targets = pcall(T.disasm_targets, from, len)
  if not ok or not targets then return {} end
  local out, seen = {}, {}
  for _, a in ipairs(targets) do
    if valid_ptr(a) and not seen[a] then
      seen[a] = true
      out[#out + 1] = a
    end
  end
  return out
end

-- Structural shape validation (CE [ENABLE] candidate checks).
local function validate_candidate(which, base)
  local a = read_ptr(base)
  if not a or a % 4 ~= 0 then return false end
  local b = read_ptr(a)
  if not b then return false end
  if not read_ptr(b) then return false end

  if which == "namelist" then
    local s0 = read_cstr(b, 64)
    if not s0 or #s0 <= 2 then return false end
    local p1 = read_ptr(a + PS)
    if not p1 then return false end
    local s1 = read_cstr(p1, 64)
    if not s1 or #s1 <= 2 then return false end
    local p2 = read_ptr(a + 4 * PS)
    if not p2 then return false end
    return read_cstr(p2, 64) ~= nil
  elseif which == "objectlist" then
    return true
  else -- cscriptlist
    local inner_offsets = IS64 and { 0x30 } or { 0x14, 0xC, 0x8 }
    for _, inner in ipairs(inner_offsets) do
      local ok = true
      for o = PS, 20 * PS, PS do
        local t1 = read_ptr(a + o)
        local good = t1 and read_ptr(t1)
        if good then
          local t2 = read_ptr(t1 + inner)
          good = t2 and read_ptr(t2)
        end
        if not good then
          ok = false
          break
        end
      end
      if ok then return true end
    end
    return false
  end
end

local ANCHORS = {
  { which = "namelist", needle = "<unknown variable>", label = "NameList" },
  { which = "objectlist", needle = "Preparing %d objects", label = "ObjectList" },
  { which = "cscriptlist", needle = "<undefined>", label = "CScriptList" },
}

local function locate_one(anchor, lo, hi)
  local hits = scan_regions_for_bytes(
    (function()
      local regs = {}
      for _, r in ipairs(regions()) do
        if r.readable and r.base < hi and (r.base + r.size) > lo then
          regs[#regs + 1] = {
            base = math.max(r.base, lo),
            size = math.min(r.base + r.size, hi) - math.max(r.base, lo),
            readable = true,
          }
        end
      end
      return regs
    end)(),
    anchor.needle,
    64
  )
  if #hits == 0 then
    error(anchor.label .. " not found: anchor string not present in module")
  end
  -- findAddress window: 0x50 for NameList/ObjectList, 0x100 for CScriptList.
  local window = anchor.which == "cscriptlist" and 0x100 or 0x50
  for _, hit in ipairs(hits) do
    local refs
    if IS64 then
      refs = find_lea_refs(hit, lo, hi)
    else
      refs = find_pointer_refs(hit, lo, hi)
    end
    for _, ref in ipairs(refs) do
      -- x86: findAddress starts decoding at ref+4 (past the pointer imm).
      local start = IS64 and ref or (ref + 4)
      for _, cand in ipairs(harvest_address_operands(start, window)) do
        for m = 0, 0x10, 4 do
          local base = cand + m
          if validate_candidate(anchor.which, base) then
            dlog(string.format("[GameMaker] %s candidate accepted: 0x%X", anchor.label, base))
            return base
          end
        end
      end
    end
  end
  error(anchor.label .. " not found: no structurally valid candidate")
end

local function locate_lists(module)
  local lo, hi = module_span(module)
  local out = {}
  for _, anchor in ipairs(ANCHORS) do
    out[anchor.which] = locate_one(anchor, lo, hi)
    dlog(string.format("[GameMaker] %s: 0x%X", anchor.label, out[anchor.which]))
  end
  return out
end

-- ---------------------------------------------------------------------------
-- NameList / CScriptList enumeration
-- ---------------------------------------------------------------------------

local NAME_SLOTS = 0x1000 * 2

local function walk_name_array(list, names, state)
  local array = read_ptr(list)
  if not array then return end
  local slots = read_ptr_array(array, NAME_SLOTS + 1)
  if not slots then return end
  local prev = 0
  for i, p in ipairs(slots) do
    if p ~= prev then
      prev = p
      if valid_ptr(p) then
        local s = read_cstr(p, 128)
        if s and valid_gm_name(s) then
          local idx = i - 1
          local existing = names[idx]
          if existing == nil then
            names[idx] = s
          elseif existing ~= s then
            names[idx] = existing .. "/" .. s
          end
          if idx > (state.max_name_index or 0) then
            state.max_name_index = idx
          end
        end
      end
    end
  end
end

local function enum_name_list(name_list_sym, names, state)
  local list = name_list_sym

  -- Shape check: array may start at list+2*size.
  local shift_ok = (function()
    local p = read_ptr(list + 2 * PS)
    return p and read_ptr(p) ~= nil
  end)()
  if shift_ok and (read_i32(list + 3 * PS) or 0) > (read_i32(list + PS) or 0) then
    list = list + 2 * PS
  end

  walk_name_array(list, names, state)

  -- One realignment attempt (CE loopdone logic).
  local realigned = false
  for i = PS, 0x10, 4 do
    if list >= i then
      local p = read_ptr(list - i)
      if p and read_ptr(p) then
        list = list - i
        realigned = true
        break
      end
    end
  end
  if not realigned then
    for i = PS, 0x10, 4 do
      local p = read_ptr(list + i)
      if p and read_ptr(p) then
        list = list + i
        realigned = true
        break
      end
    end
  end
  if realigned then
    dlog(string.format("[GameMaker] NameList base realigned to 0x%X", list))
    walk_name_array(list, names, state)
  end
end

local MAX_TAG = 0x1000000
local MAX_HARVEST = 32 * 1024 * 1024

-- Walk the region containing `hit`, recording every `[tag] <g> [char*]` pair.
local function harvest_name_region(hit, g, names)
  local region = T.region_of(hit)
  if not region then return end
  local span = math.min(region.size, MAX_HARVEST)
  local start = region.base
  local harvested = 0

  local offset = 0
  while offset < span do
    local chunk_size = math.min(CHUNK, span - offset)
    local ok, data = pcall(T.read_block, start + offset, chunk_size)
    if ok then
      local fmt = IS64 and "<I8" or "<I4"
      local i = 1
      while i + PS - 1 <= #data do
        -- Tag value at i-g (local buffer check — cheap).
        local tag_off = i - g -- 1-based buffer index of tag
        if tag_off >= 1 and tag_off + 3 <= #data then
          local tag = string.unpack("<I4", data, tag_off)
          if tag > 1 and tag < MAX_TAG and names[tag] == nil then
            local sp = string.unpack(fmt, data, i)
            if valid_ptr(sp) then
              local s = read_cstr(sp, 128)
              if s and valid_gm_name(s) then
                names[tag] = s
                harvested = harvested + 1
              end
            end
          end
        end
        i = i + PS
      end
    end
    offset = offset + chunk_size
  end
  if harvested > 0 then
    T.log(string.format("[GameMaker] name harvest: %d additional name(s)", harvested))
  end
end

-- CE fastscan name recovery: some builds store name tags that never appear
-- in the NameList; find the tag elsewhere in writable memory next to a
-- pointer to the name string.
local function recover_name(tag, names)
  local needle = string.pack("<I4", tag)
  local writable = {}
  for _, r in ipairs(regions()) do
    if r.readable and r.writable then writable[#writable + 1] = r end
  end
  local hits = scan_regions_for_bytes(writable, needle, 64)
  for _, hit in ipairs(hits) do
    for _, g in ipairs({ -PS, PS, 2 * PS }) do
      local slot = hit + g
      local p = read_ptr(slot)
      local name = p and read_cstr(p, 48)
      if name and #name > 4 and #name < 40 and valid_gm_name(name) then
        names[tag] = name
        harvest_name_region(hit, g, names)
        return name
      end
    end
  end
  return nil
end

local function enum_cscript_list(cscript_list_sym)
  local out = {}
  if IS64 then
    local count = math.max(0, math.min(read_i32(cscript_list_sym - 2 * PS) or 0, 0x10000))
    local array = read_ptr(cscript_list_sym)
    if not array then return out end
    local slots = read_ptr_array(array, count * 2 + 1)
    if not slots then return out end
    local prev = 0
    for _, entry in ipairs(slots) do
      if entry ~= prev then
        prev = entry
        if entry == 0 or not read_ptr_raw(entry) then break end
        local sp = read_ptr(entry + 0x30)
        local s = sp and read_cstr(sp, 128)
        if s then out[#out + 1] = s end
      end
    end
    return out
  end

  -- x86
  local count = math.max(0, math.min(read_i32(cscript_list_sym + 2 * PS) or 0, 0x10000))
  local array = read_ptr(cscript_list_sym)
  if not array then return out end
  local koff, noff
  local probe = (function()
    local e = read_ptr(array)
    return e and read_ptr(e + 0xC)
  end)()
  if probe then
    koff, noff = 0xC, 0x0
  else
    koff, noff = 0x8, 0x5C
  end
  local slots = read_ptr_array(array, count * 2 + 1)
  if not slots then return out end
  local prev = 0
  for _, entry in ipairs(slots) do
    local cscript = read_ptr(entry + koff) or 0
    if cscript ~= prev then
      prev = cscript
      if cscript == 0 or not read_ptr_raw(cscript) then break end
      local sp = read_ptr(cscript + noff)
      local s = sp and read_cstr(sp, 128)
      if s then out[#out + 1] = s end
    end
  end
  return out
end

-- ---------------------------------------------------------------------------
-- ObjectList enumeration
-- ---------------------------------------------------------------------------

local function enum_object_list(object_list_sym)
  local name_chain = IS64 and 0x18 or 0xC

  local list = read_ptr(object_list_sym)
  if not list then error("ObjectList head pointer unreadable") end

  -- Probe whether the deep name chain resolves; if not, names live at +0x14.
  local name_off = (function()
    local a = read_ptr_raw(object_list_sym)
    local b = a and read_ptr_raw(a)
    local c = b and read_ptr_raw(b)
    local d = c and read_ptr_raw(c + name_chain)
    local e = d and read_ptr_raw(d)
    return e ~= nil and 0 or 0x14
  end)()

  local count = read_i32(list + PS) or 0
  if count <= 0 then error("ObjectList count is not positive") end
  count = math.min(count, 0x10000)

  local entries = read_ptr(list)
  if not entries then error("ObjectList entry array unreadable") end
  local slots = read_ptr_array(entries, count * 2 + 1)
  if not slots then error("ObjectList array unreadable") end

  local objects = {}
  local index = {}
  local prev_obj = 0
  for _, entry in ipairs(slots) do
    if entry == 0 then break end
    if not read_ptr_raw(entry) then break end
    local obj = read_ptr(entry + name_chain)
    if obj and obj ~= prev_obj then
      prev_obj = obj
      local name_ptr = read_ptr(obj + name_off)
      local name = name_ptr and read_cstr(name_ptr, 128)
      if name and valid_gm_name(name) then
        local key = name:lower()
        if not index[key] then
          index[key] = #objects + 1
          objects[#objects + 1] = { name = name, address = obj }
        end
      end
    end
  end
  if #objects == 0 then
    error("ObjectList enumeration produced no objects")
  end
  return objects, index
end

-- ---------------------------------------------------------------------------
-- RTTI: find live YYObjectBase instances, pick BaseGame
-- ---------------------------------------------------------------------------

-- Scan the region containing the ObjectList symbol for pointers to objects
-- whose RTTI class is YYObjectBase (the CE table's BaseGame scan).
local function find_instances(object_list_sym)
  local region = T.region_of(object_list_sym)
  if not region or not region.readable then return {} end
  local out = {}
  local offset = 0
  while offset < region.size do
    local chunk_size = math.min(CHUNK, region.size - offset)
    local chunk_addr = region.base + offset
    local ok, data = pcall(T.read_block, chunk_addr, chunk_size)
    if ok then
      local fmt = IS64 and "<I8" or "<I4"
      -- CE scans this region 4 bytes at a time regardless of pointer size.
      local i = 1
      while i + PS - 1 <= #data do
        local v = string.unpack(fmt, data, i)
        if valid_ptr(v) then
          local name = T.rtti_class_name(v)
          if name and name:find("YYObjectBase") then
            out[#out + 1] = { slot = chunk_addr + i - 1, ptr = v }
          end
        end
        i = i + 4
      end
    end
    offset = offset + chunk_size
  end
  return out
end

-- BaseGame selection (CE semantics): the YYObjectBase instance with the
-- largest variable count (`i32(*(inst + Of3)`); ties → first in slot order.
-- Returns the *slot* (deref once to reach the instance).
local function pick_base_game(instances, of3)
  local best_slot, best_count = nil, 0
  for _, inst in ipairs(instances) do
    local vars = read_ptr(inst.ptr + of3)
    local count = vars and read_i32(vars) or 0
    if count > best_count then
      best_slot, best_count = inst.slot, count
    end
  end
  return best_slot
end

-- ---------------------------------------------------------------------------
-- x86 offset detection (CE checkOffset)
-- ---------------------------------------------------------------------------

local X86_SETS = {
  { 0x44, 0x8, 0x2C, 0x10 },
  { 0xD0, 0x8, 0x44, 0x10 },
  { 0xBC, 0x8, 0x34, 0x10 },
  { 0xB8, 0x8, 0x4,  nil  },
  { 0xD0, 0x8, 0x60, 0x10 },
  { 0x38, 0x8, 0x24, 0x10 },
}

-- Validate an offset set against a CObject chain (CE checkOffset inner chain).
local function validate_set(obj_addr, set)
  local of1, of2, of3, of4 = set[1], set[2], set[3], set[4]
  local p = read_ptr(obj_addr + of1)
  if not p then return false end
  local q = read_ptr(p + of2)
  if not q or q % 4 ~= 0 then return false end
  local v = read_ptr(q + of3)
  if not v then return false end
  if of4 then
    local x = read_ptr(q + of3 + of4)
    if not (x and read_ptr(x)) then return false end
    local y = read_ptr(v + of4)
    return y ~= nil and read_ptr(y) ~= nil
  else
    return read_ptr(v) ~= nil
  end
end

-- Validate an offset set against a live YYObjectBase instance.
local function validate_set_instance(inst, set)
  local of3, of4 = set[3], set[4]
  local vars = read_ptr(inst + of3)
  if not vars then return false end
  local num = read_i32(vars)
  if not num or num < 1 or num > 0x10000 then return false end
  if of4 then
    return read_ptr(vars + of4) ~= nil
  end
  return true
end

local function detect_offsets_x86(objects, instances)
  local best_i, best_inst_hits, best_obj_hits = nil, -1, -1
  for i, set in ipairs(X86_SETS) do
    local obj_hits = 0
    for _, obj in ipairs(objects) do
      if validate_set(obj.address, set) then obj_hits = obj_hits + 1 end
    end
    local inst_hits = 0
    for _, inst in ipairs(instances) do
      if validate_set_instance(inst.ptr, set) then inst_hits = inst_hits + 1 end
    end
    dlog(string.format("[GameMaker] checkOffset set %d: %d object(s), %d instance(s)",
      i + 1, obj_hits, inst_hits))
    -- Instance matches are the stronger signal and win ties.
    if best_i == nil or inst_hits > best_inst_hits
      or (inst_hits == best_inst_hits and obj_hits > best_obj_hits) then
      best_i, best_inst_hits, best_obj_hits = i, inst_hits, obj_hits
    end
  end
  local set = X86_SETS[best_i]
  T.log(string.format(
    "[GameMaker] checkOffset: set %d {Of1=0x%X, Of2=0x%X, Of3=0x%X, Of4=%s} (%d objects, %d instances)",
    best_i + 1, set[1], set[2], set[3],
    set[4] and string.format("0x%X", set[4]) or "nil",
    best_obj_hits, best_inst_hits))
  return { of0 = 0xC, of1 = set[1], of2 = set[2], of3 = set[3], of4 = set[4] }
end

-- ---------------------------------------------------------------------------
-- Property enumeration (CE getProperties / enumObjectsProperties)
-- ---------------------------------------------------------------------------

local MAX_PROPS = 0x10000
local MAX_NAME_INDEX = 0x1000000

local function get_properties(state, obj_struct, object_name)
  local of4 = state.offsets.of4
  if not of4 then return 0 end
  local num_raw = read_i32(obj_struct)
  if not num_raw or num_raw <= 0 then return 0 end
  local num = math.min(num_raw, MAX_PROPS)
  local var_array = read_ptr(obj_struct + of4)
  if not var_array then return 0 end

  -- Slots walked: j = 0..=num*PS (CE parity), plus one extra slot so the
  -- name-index read at entry+PS stays in bounds.
  local slot_count = num * PS + 2
  local ok, raw = pcall(T.read_block, var_array, slot_count * PS)
  if not ok then return 0 end
  local fmt = IS64 and "<I8" or "<I4"
  local function slot_u64(j) -- j is 0-based slot index
    local pos = j * PS + 1
    if pos + PS - 1 > #raw then return nil end
    return string.unpack(fmt, raw, pos)
  end
  local function i32_at(byte_off) -- 0-based byte offset
    if byte_off < 0 or byte_off + 4 > #raw then return nil end
    return string.unpack("<i4", raw, byte_off + 1)
  end

  local obj_key = object_name:lower()
  local is_basegame = obj_key == "basegame"
  local recorded = 0

  local limit = math.min(num * PS + 1, math.floor(#raw / PS) - 1)
  for j = 0, limit - 1 do
    local elem = slot_u64(j)
    -- CE gate: readPointer(readPointer(entry)) — the entry value must point
    -- to *readable* memory (raw read: a read 0 is truthy in Lua).
    --
    -- We also process slots with elem == 0 (null RValue pointer). In
    -- GameMaker, a variable's RValue pointer may be null before the game
    -- initializes it, but the name index (stored in an adjacent slot) is
    -- still valid. If we skip null-RValue slots, the property's offset is
    -- never recorded, and the property can never be resolved — even after
    -- the game later initializes the RValue. Processing these slots
    -- ensures all declared variables are discoverable.
    local has_rvalue = elem ~= nil and elem ~= 0
      and valid_ptr(elem) and is_mapped(elem) and read_ptr_raw(elem) ~= nil
    if elem and (elem == 0 or has_rvalue) then
      -- `Older` layout detection (BaseGame only, needs a valid RValue).
      if has_rvalue and is_basegame and state.older < 4 and j >= 3 then
        local ni = i32_at(j * PS + PS)
        local ni2 = i32_at(j * PS - PS)
        if ni and ni2 and ni > 1 and ni2 > 1 then
          local entry_addr = var_array + j * PS
          local p = read_ptr(entry_addr - 3 * PS)
          if p and read_ptr(p) and ni - 1 == ni2 then
            state.older = state.older + 1
          end
        end
      end

      -- Name index: entry+PS normally, entry-PS on newer layouts.
      local name_index
      if state.older < 4 then
        local v = i32_at(j * PS + PS)
        if not v or v <= 0 then goto continue end
        name_index = v
      else
        if j == 0 then goto continue end
        local v = i32_at(j * PS - PS)
        if not v or v <= 0 then goto continue end
        name_index = v
      end
      if name_index <= 1 or name_index >= MAX_NAME_INDEX then goto continue end

      local name = state.names[name_index]
      if not name then
        -- CE fastscan fallback: recover the tag's name from a secondary name
        -- table elsewhere in writable memory.
        if state.recoveries_done < 6 and not state.ignore_tags[name_index] then
          state.recoveries_done = state.recoveries_done + 1
          name = recover_name(name_index, state.names)
          if not name then
            state.ignore_tags[name_index] = true
            state.unknown_name_indices = state.unknown_name_indices + 1
            goto continue
          end
        else
          state.unknown_name_indices = state.unknown_name_indices + 1
          goto continue
        end
      end

      local offset = j * PS
      local member_key = obj_key .. "." .. name:lower()
      -- First discovery wins (CE parity).
      if state.member_offsets[member_key] == nil then
        state.member_offsets[member_key] = offset
      end
      local pkey = name:lower()
      if state.prop_offsets[pkey] == nil then
        state.prop_offsets[pkey] = offset
      end
      recorded = recorded + 1
    end
    ::continue::
  end
  return recorded
end

local function enum_objects_properties(state)
  local total = 0
  local of = state.offsets

  -- BaseGame first. With Of4: [[BaseGame]+Of3]; without: [BaseGame] itself.
  if state.base_game then
    local inst = read_ptr(state.base_game)
    local vars
    if inst then
      if of.of4 then vars = read_ptr(inst + of.of3) else vars = inst end
    end
    if vars then
      total = total + get_properties(state, vars, "BaseGame")
    else
      dlog("[GameMaker] BaseGame instance/vars not readable yet (title screen?)")
    end
  end

  -- Every object from the ObjectTable.
  for _, obj in ipairs(state.objects) do
    local a = read_ptr(obj.address + of.of1)
    local b = a and read_ptr(a + of.of2)
    local vars = b and read_ptr(b + of.of3)
    if vars then
      total = total + get_properties(state, vars, obj.name)
    end
  end
  return total
end

-- ---------------------------------------------------------------------------
-- Session: initialization + public resolution API
-- ---------------------------------------------------------------------------

local X64_OFFSETS = { of0 = 0x18, of1 = 0x68, of2 = 0x10, of3 = 0x58, of4 = 0x10 }

local function initialize()
  init_width()
  local module = T.module()
  T.log("[GameMaker] Architecture: " .. (IS64 and "x64" or "x86"))

  local lists = locate_lists(module)

  local state = {
    offsets = X64_OFFSETS,
    name_list = lists.namelist,
    object_list = lists.objectlist,
    cscript_list = lists.cscriptlist,
    names = {},
    max_name_index = 0,
    member_offsets = {},
    prop_offsets = {},
    unknown_name_indices = 0,
    older = 0,
    ignore_tags = {},
    recoveries_done = 0,
  }

  -- Enumerate objects, scripts, names.
  local objects, index = enum_object_list(state.object_list)
  state.objects = objects
  state.object_index = index
  state.scripts = enum_cscript_list(state.cscript_list)
  enum_name_list(state.name_list, state.names, state)
  T.log(string.format("[GameMaker] Objects discovered: %d", #state.objects))
  T.log(string.format("[GameMaker] Names discovered: %d", (function()
    local n = 0
    for _ in pairs(state.names) do n = n + 1 end
    return n
  end)()))

  -- Live YYObjectBase instances via minimal RTTI (needed for offset
  -- validation and BaseGame selection).
  local instances = find_instances(state.object_list)
  T.log(string.format("[GameMaker] YYObjectBase instances: %d", #instances))

  -- Structure offsets: fixed on x64, probed on x86.
  if not IS64 then
    state.offsets = detect_offsets_x86(state.objects, instances)
  end

  -- BaseGame: the instance with the most variables (CE semantics).
  state.base_game = pick_base_game(instances, state.offsets.of3)
  if not state.base_game then
    error("BaseGame not found: no YYObjectBase instance near ObjectList")
  end
  T.log(string.format("[GameMaker] BaseGame: 0x%X", state.base_game))

  -- Property tables.
  local props = enum_objects_properties(state)
  T.log(string.format("[GameMaker] Properties discovered: %d", props))
  if state.unknown_name_indices > 0 then
    dlog(string.format("[GameMaker] %d property slot(s) had unknown name indices (skipped)",
      state.unknown_name_indices))
  end

  T.log("[GameMaker] Resolver ready")
  return state
end

local function ensure()
  if gm.state then return gm.state end
  gm.state = initialize()
  return gm.state
end

-- Resolve a GameMaker object to its variable-storage struct address.
local function get_object(object)
  local state = ensure()
  local of = state.offsets
  local key = object:lower()

  if key == "basegame" then
    local slot = state.base_game
    if not slot then error("BaseGame was not discovered") end
    local inst = read_ptr(slot)
    if not inst then
      error("BaseGame instance not readable (is the game in-game?)")
    end
    -- CE: [[BaseGame]+Of3] with Of4 layouts, [BaseGame] without.
    if of.of4 then
      local v = read_ptr(inst + of.of3)
      if not v then error("BaseGame variable storage not readable") end
      return v
    end
    return inst
  end

  local idx = state.object_index[key]
  if not idx then
    error('object "' .. object .. '" not found in ObjectList')
  end
  local obj = state.objects[idx]
  local a = read_ptr(obj.address + of.of1)
  local b = a and read_ptr(a + of.of2)
  local c = b and read_ptr(b + of.of3)
  if not c then
    error('object "' .. object .. '" has no live variable storage (no active instance?)')
  end
  return c
end

-- Resolve a property name to its byte offset within the variable array.
--
-- Only object-specific offsets (member_offsets) are used. The global
-- prop_offsets table is NOT consulted as a fallback because each GameMaker
-- object has its own variable-array layout — an offset valid for oPlayer is
-- NOT valid for BaseGame. Using a cross-object offset would compute a wrong
-- slot inside the requested object's array, yielding a valid pointer to a
-- *different* variable's RValue and silently corrupting it on write.
local function get_property(object, property)
  local state = ensure()
  local member_key = object:lower() .. "." .. property:lower()
  local off = state.member_offsets[member_key]
  if off then return off end
  error('property "' .. property .. '" not found on object "' .. object .. '"')
end

local function resolve_inner(object, property)
  local vars = get_object(object)
  local prop_off = get_property(object, property)
  local state = ensure()
  local of4 = state.offsets.of4
  if not of4 then
    error("this GameMaker layout has no Of4; property resolution unsupported")
  end
  local var_array = read_ptr(vars + of4)
  if not var_array then
    error('variable array of "' .. object .. '" not readable')
  end
  local entry = var_array + prop_off
  local addr = read_ptr(entry)
  if not addr then
    error('value pointer for "' .. object .. '.' .. property .. '" not readable')
  end
  dlog(string.format("[GameMaker] %s.%s -> 0x%X", object, property, addr))
  return addr
end

-- Resolve `object.property` to the address of its current value.
--
-- Resolution strategy:
--   1. Try the requested object directly (fast path).
--   2. If the property isn't on that object, search ALL discovered objects
--      for it and try each one. This is safe because we use the found
--      object's OWN instance pointer and its OWN per-object offset — never
--      a cross-object offset (which was the cause of silent memory
--      corruption and game crashes).
--   3. If the error is a game-state transition (BaseGame not yet
--      instantiated, instance not readable), re-run discovery once — the
--      game may have transitioned from title to in-game since attach.
--   4. All other errors (property not found, value pointer not readable,
--      variable array not readable) are returned immediately. Re-discovery
--      won't help: the offset is already correct (or the property doesn't
--      exist), and the full discovery takes many seconds, which would
--      exceed the relay's 15s timeout.
function gm_addr(object, property)
  local ok, addr = pcall(resolve_inner, object, property)
  if ok then return addr end

  local err = tostring(addr)

  -- Property not on the requested object → search all objects that have it.
  if err:find("not found on object") or err:find("not found in ObjectList") then
    local state = ensure()
    local pkey = property:lower()
    local tried = {}
    for member_key in pairs(state.member_offsets) do
      local obj_name, prop_name = member_key:match("^(.+)%.(.+)$")
      if prop_name == pkey and not tried[obj_name:lower()] then
        tried[obj_name:lower()] = true
        if obj_name:lower() ~= object:lower() then
          T.log(string.format("[GameMaker] '%s' not on '%s'; trying '%s'",
                property, object, obj_name))
          local ok2, addr2 = pcall(resolve_inner, obj_name, property)
          if ok2 then return addr2 end
        end
      end
    end
    -- Property not on any discovered object. Re-discovery won't help.
    error(err)
  end

  -- Game-state transitions: BaseGame/instance might not have existed when we
  -- first attached (title screen → in-game). Re-discover once.
  if err:find("was not discovered")
     or err:find("instance not readable")
     or err:find("no live variable storage") then
    T.log("[GameMaker] resolution failed (" .. err .. "); re-initializing")
    gm.state = nil
    return resolve_inner(object, property)
  end

  -- All other errors (value pointer not readable, variable array not
  -- readable, no Of4, etc.): re-discovery won't help. Return immediately
  -- so the caller gets a clear error instead of a 15s timeout.
  error(err)
end

gm.addr = gm_addr
