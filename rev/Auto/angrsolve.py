
import angr
import claripy
import monkeyhex
import os
import re


def main(path):
# path = 'chall/out000'
    pathn = './' + os.path.split(path)[-1]
    project = angr.Project(path)

    def ascii_only_constraint(variable, state):
            for b in variable.chop(8):
                    state.add_constraint(claripy.And(b >= 0x20, b < 0x7f))
    kwargs = {}

    simgr_kwargs = {}

    buf_len = 4
    stdin_bvs = claripy.BVS('stdin_bvs', buf_len*8)
    # kwargs['stdin'] = stdin_bvs
    kwargs['args'] = [pathn, stdin_bvs]

    initial_state = project.factory.entry_state(**kwargs)


    def is_successful(state):
            stdout_output = state.posix.dumps(1)
            return stdout_output.find(b'GOOOOOOOOOOOOOOOOOOOD') > -1

    def should_abort(state):
            stdout_output = state.posix.dumps(1)
            return stdout_output.find(b'NOOOOOOOOOOOOOOOOOO') > -1


    simgr = project.factory.simgr(initial_state, **simgr_kwargs)
    simgr.explore(find=0x0040139c, avoid=should_abort)
    if simgr.found:
        a = simgr.one_found.solver.eval(stdin_bvs, cast_to=bytes)
        print(a)
        return a


fmt = 'chall/out%03d'
solves = []
for i in range(0, 400):
    solves.append(main(fmt % i))

dump = b''.join([i[:2] for i in solves])
flag = re.search(b'FwordCTF\{[^}]+\}', dump)[0].decode()

print(flag)
