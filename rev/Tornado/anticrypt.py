#This is the "bad_flag" which we want to reverse the process on
bad_flag = '3ce29d5f8d646d853b5f6677a564aec6bd1c9f0cbfac0af73fb5cfb446e08cfec5a261ec050f6f30d9f1dfd85a9df875168851e1a111a9d9bfdbab238ce4a4eb3b4f8e0db42e0a5af305105834605f90621940e3f801e0e4e0ca401ff451f1983701831243df999cfaf40b4ac50599de5c87cd68857980a037682b4dbfa1d26c949e743f8d77549c5991c8e1f21d891a1ac87166d3074e4859a26954d725ed4f2332a8b326f4634810a24f1908945052bfd0181ff801b1d3a0bc535df622a299a9666de40dfba06a684a4db213f28f3471ba7059bcbdc042fd45c58ae4970f53fb808143eaa9ec6cf35339c58fa12efa18728eb426a2fcb0234d8539c0628c49b416c0963a33e6a0b91e7733b42f29900921626bba03e76b1911d20728254b84f38a2ce12ec5d98a2fa3201522aa17d6972fe7c04f1f64c9fd4623583cc5a91cc471a13d6ab9b0903704727d1eb987fd5d59b5757babb92758e06d2f12fd7e32d66fe9e3b9d11cd93b11beb70c66b57af71787457c78ff152ff4bd63a83ef894c1f01ae476253cbef154701f07cc7e0e16f7eede0c8fa2d5a5dd5624caa5408ca74b4b8c8f847ba570023b481c6ec642dac634c112ae9fec3cbd59e1d2f84f56282cb74a3ac6152c32c671190e2f4c14704ed9bbe74eaafc3ce27849533141e9642c91a7bf846848d7fbfcd839c2ca3b'


import random


# This is build to bring bad_flag to a series of 32 byte "blocks" this is the natural output of the AES encrypt
# each block seems to have an additional number of bytes on the rear, we can clean the output by only taking the first two 
# bytes of the cipher

def mad_blocks(bad_flag):
    return [bad_flag[i:i+32] for i in range(0, len(bad_flag), 32)]

# The seed must be contained as one of the letters within the flag which means all we need to do is
# go through each of them and run an anti shuffle program which would replace all of the stuff back to 
# where it was

# This will be done by running the randomized ints and then rolling back the changes exactly
# Shuffled word
wordy = 'aaFho_i_aC2b_abfc8edFw!kolae_ngbom_r__f_9T525eg__ihedd}{pmertt'

def anti_translate(text, l, r):
    return text[:l]+text[len(text)-r+l:]+text[l:len(text)-r+l]

# Will seed through the word untill it finds the correct combination
def anti_shuffle(shuffled):
    correct = ''
    flag = "FwordCTF"
    for i in shuffled:
        part = shuffled
        random.seed(i)
        numbers = []
        # Collect what the random l and r would have been in a list to reverse the the shuffle
        for _ in range(45):
           l = random.randint(0,15) 
           r = random.randint(l+1,33)
           numbers.append((l,r))
        for current in reversed(numbers):
            part = anti_translate(part, current[0], current[1])

        print(part)
        if(part[:len(flag)] == flag):
            print("Correct!")
            shuffled = ''


anti_shuffle(wordy)
