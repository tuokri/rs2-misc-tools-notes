mov rcx,qword ptr ds:[7FF63E1DC218]
call vngame.7FF63D3B68F0
mov rcx,41F00000
movq xmm1,rcx
comiss xmm1,xmm0
jb vngame.7FF63D5206F9
