mov rcx,qword ptr ds:[7FF6182797E8]             # TODO: Unreal logging object address?
lea r8,qword ptr ds:[7FF617FF7A70]              # Address of our custom log message.
mov edx,2F8                                     # Log category / verbosity.
call vngame.7FF616EAD100                        # Call Unreal logging function.
