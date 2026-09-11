# Standard-library PTY broker for CLI tests on Unix. Credentials arrive over a
# private pipe and never appear in arguments, environment, or diagnostic output.
import json
import os
import pty
import select
import sys
import termios
import time

master, slave = pty.openpty()
print(os.ttyname(slave), flush=True)
try:
    for line in sys.stdin:
        request = json.loads(line)
        if request["command"] == "input":
            deadline = time.monotonic() + 5
            while termios.tcgetattr(slave)[3] & termios.ECHO:
                if time.monotonic() >= deadline:
                    raise RuntimeError("terminal did not disable echo")
                time.sleep(0.005)
            os.write(master, (request["value"] + "\n").encode())
            # ReadPassword must not echo even when stdout is redirected.
            if select.select([master], [], [], 0.05)[0]:
                raise RuntimeError("terminal echoed hidden input")
            print("sent", flush=True)
        elif request["command"] == "echo":
            print("on" if termios.tcgetattr(slave)[3] & termios.ECHO else "off", flush=True)
        else:
            raise RuntimeError("unknown terminal test command")
finally:
    os.close(master)
    os.close(slave)
