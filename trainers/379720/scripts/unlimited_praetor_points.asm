; ============================================================
; unlimited_praetor_points  — DOOM (2016), Vulkan (DOOMx64vk.exe)
;
; Campaign — Statistics — Arsenal/Runes — Mastery Challenges/Runes.
; Forces the Praetor Suit upgrade-point counters to 9999 at
; both the "collected" and "used" update sites so the suit
; points never run out.
;
; Site 1 — collected (6 bytes):
;   01 51 38     add [rcx+38],edx
;   8B 71 38     mov esi,[rcx+38]
; Site 2 — used (5 bytes):
;   89 7B 38     mov [rbx+38],edi
;   8B C7        mov eax,edi
; ============================================================

[ENABLE]
aobscanmodule(_praetor_suit_upgrade_points_collected,DOOMx64vk.exe,01 51 38 8B 71 38)
aobscanmodule(_praetor_suit_upgrade_points_used,DOOMx64vk.exe,89 7B 38 8B C7)
alloc(newmem_x,256,_praetor_suit_upgrade_points_collected)
alloc(newmem_y,256,_praetor_suit_upgrade_points_used)
label(code_x)
label(return_x)
label(return_y)
registersymbol(_praetor_suit_upgrade_points_collected)
registersymbol(_praetor_suit_upgrade_points_used)

newmem_x:
  mov dword ptr [rcx+38],#9999
code_x:
  add [rcx+38],edx
  mov esi,[rcx+38]
  jmp return_x

_praetor_suit_upgrade_points_collected:
  jmp newmem_x
  nop

return_x:

newmem_y:
  mov dword ptr [rbx+38],#9999
  mov eax,edi
  jmp return_y

_praetor_suit_upgrade_points_used:
  jmp newmem_y

return_y:

[DISABLE]
_praetor_suit_upgrade_points_collected:
  db 01 51 38 8B 71 38

_praetor_suit_upgrade_points_used:
  db 89 7B 38 8B C7

unregistersymbol(_praetor_suit_upgrade_points_collected)
unregistersymbol(_praetor_suit_upgrade_points_used)
dealloc(newmem_x)
dealloc(newmem_y)
