# Perplexed

We're provided with a 64-bit ELF. Running it, we get a simple password check.

```console
$ chmod +x ./perplexed
$ ./perplexed 
Enter the password: adsf
Wrong :(
```

Based on past experience, the goal is to find the password, which is likely the flag itself. Firing up Ghidra, we can quickly find the relevant logic. 

```c
undefined8 check(char *param_1)

{
  size_t sVar1;
  undefined8 uVar2;
  size_t sVar3;
  char local_58 [36];
  uint local_34;
  uint local_30;
  undefined4 local_2c;
  int local_28;
  uint local_24;
  int local_20;
  int local_1c;
  
  sVar1 = strlen(param_1);
  if (sVar1 == 0x1b) {
    local_58[0] = -0x1f;
    local_58[1] = -0x59;
    local_58[2] = '\x1e';
    local_58[3] = -8;
    local_58[4] = 'u';
    local_58[5] = '#';
    local_58[6] = '{';
    local_58[7] = 'a';
    local_58[8] = -0x47;
    local_58[9] = -99;
    local_58[10] = -4;
    local_58[0xb] = 'Z';
    local_58[0xc] = '[';
    local_58[0xd] = -0x21;
    local_58[0xe] = 'i';
    local_58[0xf] = 0xd2;
    local_58[0x10] = -2;
    local_58[0x11] = '\x1b';
    local_58[0x12] = -0x13;
    local_58[0x13] = -0xc;
    local_58[0x14] = -0x13;
    local_58[0x15] = 'g';
    local_58[0x16] = -0xc;
    local_1c = 0;
    local_20 = 0;
    local_2c = 0;
    for (local_24 = 0; local_24 < 0x17; local_24 = local_24 + 1) {
      for (local_28 = 0; local_28 < 8; local_28 = local_28 + 1) {
        if (local_20 == 0) {
          local_20 = 1;
        }
        local_30 = 1 << (7U - (char)local_28 & 0x1f);
        local_34 = 1 << (7U - (char)local_20 & 0x1f);
        if (0 < (int)((int)param_1[local_1c] & local_34) !=
            0 < (int)((int)local_58[(int)local_24] & local_30)) {
          return 1;
        }
        local_20 = local_20 + 1;
        if (local_20 == 8) {
          local_20 = 0;
          local_1c = local_1c + 1;
        }
        sVar3 = (size_t)local_1c;
        sVar1 = strlen(param_1);
        if (sVar3 == sVar1) {
          return 0;
        }
      }
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}
```

The first variable we notice is `param_1`, which appears to be the user's input. The next line that  pops out is `sVar1 = strlen(param_1);`, which is then checked to be `0xb1` or `27`. From this, we can gather that the flag must be 27 characters long (26 excluding the newline).
<br>
Now, there's a bunch of checks we're probably meant to manually reverse, but this seems like an easy target for an automated solve using angr.

Solve Script:
```py
import angr
import claripy

input_len = 26 # Flag length
p = angr.Project('./perplexed', auto_load_libs=True)
flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]
flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')])

st = p.factory.full_init_state(
        args=['./engine'],
        add_options=angr.options.unicorn,
        stdin=flag
        )

# Standard characters only
for k in flag_chars:
    st.solver.add(k < 0x7f)
    st.solver.add(k > 0x20)

sm = p.factory.simulation_manager(st)
sm.run()

for x in sm.deadended:
    if b"Correct" in x.posix.dumps(1):
        print(x.posix.dumps(0))(base)
```

After running for a couple minutes, we get the flag!
<br>
Overall, I was bit disappointed that the "hardest" rev was so cheeseable, which I think this was reflected in the high solve count. But I was also glad it wasn't too hard, since no one on our team is a rev fanatic.
