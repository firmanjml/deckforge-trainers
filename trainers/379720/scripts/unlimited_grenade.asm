; ============================================================
; unlimited_grenade  — DOOM (2016), Vulkan (DOOMx64vk.exe)
;
; Arcade/Campaign/Classic Maps — Inventory/Use — Grenade
; (Frag/Hologram/Siphon). Forces the grenade counter
; ([rax+0xCB50]) to 9 on every read.
;
; Original code (6 bytes):
;   8B 88 50 CB 00 00   mov ecx,[rax+0000CB50]
; ============================================================

[ENABLE]
aobscanmodule(_grenade,DOOMx64vk.exe,8B 88 50 CB 00 00)
alloc(newmem,256,_grenade)
label(return)
registersymbol(_grenade)

newmem:
  mov dword ptr [rax+0xCB50],#9
  mov ecx,[rax+0xCB50]
  jmp return

_grenade:
  jmp newmem
  nop

return:

[DISABLE]
_grenade:
  db 8B 88 50 CB 00 00

unregistersymbol(_grenade)
dealloc(newmem)
