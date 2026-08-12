-- Weapon Upgrade Points address for the freeze cheat.
--
-- player_instance.asm captures the live player-struct pointer (rcx) into
-- the _use allocation. The weapon upgrade-point counter is a 4-byte field
-- at player + 0x55AB8. Re-resolved each tick so it follows the player
-- struct; freezing it at 9999 keeps weapon upgrade points topped up.
local use_addr = trainer.symbol("_use")
if use_addr == nil then
  error("player_instance bootstrap is not active")
end
local player = trainer.read_pointer(use_addr)
return player + 0x55AB8
