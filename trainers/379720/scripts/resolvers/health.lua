-- Health gauge (current) address for the freeze cheat.
--
-- player_instance.asm captures the live player-struct pointer (rcx) into
-- the _use allocation on every armor-gauge read. The freeze manager
-- re-resolves this each tick, so the frozen health follows the player
-- struct across room transitions and save loads.
--
-- Health [Gauge] Default offset: 0x43BD4 (float32).
local use_addr = trainer.symbol("_use")
if use_addr == nil then
  error("player_instance bootstrap is not active")
end
local player = trainer.read_pointer(use_addr)
if player == 0 then
  error("player pointer has not been captured yet")
end
return player + 0x43BD4
