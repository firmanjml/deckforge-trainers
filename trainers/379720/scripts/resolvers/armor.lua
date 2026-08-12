-- Armor gauge (current) address for the freeze cheat.
--
-- player_instance.asm captures the live player-struct pointer (rcx) into
-- the _use allocation on every armor-gauge read (the original instruction
-- is movss xmm0,[rcx+0x43C20]). Re-resolved each tick by the freeze manager.
--
-- Armor [Gauge] Default offset: 0x43C20 (float32).
local use_addr = trainer.symbol("_use")
if use_addr == nil then
  error("player_instance bootstrap is not active")
end
local player = trainer.read_pointer(use_addr)
return player + 0x43C20
