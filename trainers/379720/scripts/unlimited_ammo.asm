; ============================================================
; unlimited_ammo  — DOOM (2016), Vulkan (DOOMx64vk.exe)
;
; Arcade/Campaign/Classic Maps/Rune Trial — Inventory/Use —
; Ammo/Fuel (Chainsaw/Weapons). Forces the shared ammo/fuel
; counter ([rbx+38]) to 99 on every read so weapons and the
; chainsaw never run dry.
;
; Original code (7 bytes):
;   8B 43 38          mov eax,[rbx+38]
;   48 83 C4 20       add rsp,0x20
; (AOB tail 5B C3 CC = pop rbx; ret; int3 is context only.)
; ============================================================

[ENABLE]
aobscanmodule(_ammo_fuel,DOOMx64vk.exe,8B 43 38 48 83 C4 20 5B C3 CC)
alloc(newmem,256,_ammo_fuel)
label(return)
registersymbol(_ammo_fuel)

newmem:
  mov dword ptr [rbx+38],#99
  mov eax,[rbx+38]
  add rsp,0x20
  jmp return

_ammo_fuel:
  jmp newmem
  nop 2

return:

[DISABLE]
_ammo_fuel:
  db 8B 43 38 48 83 C4 20

unregistersymbol(_ammo_fuel)
dealloc(newmem)
