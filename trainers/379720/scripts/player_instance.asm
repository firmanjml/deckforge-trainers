; ============================================================
; player_instance  — DOOM (2016), Vulkan (DOOMx64vk.exe)
;
; Captures the player-struct pointer (rcx) into the _use
; allocation every time the armor-gauge read runs, so the
; freeze/value cheats can resolve Health / Armor / Weapon
; Upgrade Points as offsets from the live player struct.
;
; Original instruction (8 bytes):
;   F3 0F 10 81 20 3C 04 00   movss xmm0,[rcx+00043C20]
; ============================================================

[ENABLE]
aobscanmodule(_player,DOOMx64vk.exe,F3 0F 10 81 20 3C 04 00)
alloc(newmem,256,_player)
alloc(_use,8)
label(return)
registersymbol(_player)
registersymbol(_use)

newmem:
  mov [_use],rcx
  movss xmm0,[rcx+0x43C20]
  jmp return

_player:
  jmp newmem
  nop 3

return:

[DISABLE]
_player:
  db F3 0F 10 81 20 3C 04 00

unregistersymbol(_player)
unregistersymbol(_use)
dealloc(_use)
dealloc(newmem)
