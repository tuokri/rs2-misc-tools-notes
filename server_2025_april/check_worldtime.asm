mov rcx,qword ptr ds:[7FF60E65C218]             # TODO: address of GWorld?
call vngame.7FF60D8368F0                        # GWorld->GetWorldInfo()->TimeSeconds or GWorld->GetTimeSeconds()?
mov rcx,41F00000                                # Hard-coded IEEE-754 bytes 30.0.
movq xmm1,rcx                                   # Put our float into a float register.
comiss xmm1,xmm0                                # Compare 30.0 with world time.
jb vngame.7FF60D9A06F9                          # Skip custom log procedure if more than 30 seconds has passed.
