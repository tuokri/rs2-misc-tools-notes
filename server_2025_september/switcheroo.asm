mov r9d,1                       ; Force set GPackagesPassedMD5Checks to true.
nop                             ; Padding.
mov edx,3                       ; Force set GOfficialGameServerStatus to 3 (PASSED?).
nop                             ; Padding.
jmp vngame.7FF61783E981         ; Skip the rest of the checks.
