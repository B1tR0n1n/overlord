#!/usr/bin/env python3
"""Job-control test for `overlord run` on a real controlling terminal.

The fix under test: an interactive session must hand the terminal foreground to
the wrapped command's process group (tcsetpgrp), so Ctrl-C/Ctrl-Z reach the
command, not overlord. We verify it structurally: inside the wrapped command,
the terminal's foreground process group equals the command's own group. Under
the old start_new_session behaviour the command had no controlling tty and this
would not hold.

Uses os.forkpty so overlord runs as a session leader owning a pty, exactly as a
terminal would launch it. Backend-agnostic (runs on fuse); no kernel needed.
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OVERLORD_HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = OVERLORD_HOME


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    subprocess.run(["rm", "-rf", OVERLORD_HOME, TARGET])
    sys.exit(1)


TARGET = tempfile.mkdtemp()
with open(os.path.join(TARGET, "seed.txt"), "w") as f:
    f.write("seed\n")

# inside the wrapped command: is our process group the terminal's foreground?
probe = ("import os,sys\n"
         "try:\n"
         "    fg = os.tcgetpgrp(sys.stdin.fileno()) == os.getpgrp()\n"
         "except OSError:\n"
         "    fg = False\n"
         "open('jc.txt','w').write('FG' if fg else 'BG')\n")

cmd = [sys.executable, os.path.join(HERE, "overlord.py"), "run", "-t", TARGET,
       "--", sys.executable, "-c", probe]

pid, mfd = os.forkpty()
if pid == 0:                      # child: session leader with the pty as ctty
    os.execvpe(cmd[0], cmd, os.environ)

out = b""
while True:
    try:
        chunk = os.read(mfd, 4096)
    except OSError:
        break
    if not chunk:
        break
    out += chunk
os.waitpid(pid, 0)
text = out.decode(errors="replace")

m = re.search(r"session (\S+)", text)
if not m:
    fail(f"no session id in output:\n{text}")
sid = m.group(1)

# apply the session so we can read the probe's verdict from the real target
r = subprocess.run([sys.executable, os.path.join(HERE, "overlord.py"), "commit", sid],
                   capture_output=True, text=True)
if r.returncode != 0:
    fail(f"commit failed: {r.stderr}")

verdict = open(os.path.join(TARGET, "jc.txt")).read().strip()
if verdict != "FG":
    fail(f"wrapped command was not the terminal foreground group (got {verdict!r}) "
         f"— job control handoff did not happen")
print("  ok: interactive run hands terminal foreground to the wrapped command")

print("PASS: job control")
subprocess.run(["rm", "-rf", OVERLORD_HOME, TARGET])
