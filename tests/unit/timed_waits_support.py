"""Source snippets for the timed-wait gate: what it must flag, and what it must leave alone."""

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "no-timed-waits.py"


def load_script():
    spec = importlib.util.spec_from_file_location("no_timed_waits", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # `dataclass` looks its own module up while the module is still executing
    spec.loader.exec_module(module)
    return module


# What must be flagged =================================================================================================

# (source, rule): the rule is the one the finding has to carry.
SLEEPS = [
    ("import time\ntime.sleep(1)\n", "banned-reference"),
    ("import time\ntime.sleep(0)\n", "banned-reference"),
    ("import time as t\nt.sleep(1)\n", "banned-reference"),
    ("from time import sleep\nsleep(1)\n", "banned-reference"),
    ("from time import sleep as snooze\nsnooze(1)\n", "banned-reference"),
    ("import time\nnap = time.sleep\n", "banned-reference"),
    ("import time\nimport functools\nnap = functools.partial(time.sleep, 1)\n", "banned-reference"),
    ("import asyncio\nasync def f():\n    await asyncio.sleep(1)\n", "banned-reference"),
    ("from asyncio import sleep\n", "banned-reference"),
    ("import anyio\nasync def f():\n    await anyio.sleep(1)\n", "sleep"),
    ("def f(self):\n    self.sleep(1)\n", "sleep"),
    ("def f(loop, cb):\n    loop.call_later(5, cb)\n", "sleep"),
    ("import subprocess\nsubprocess.run(['sleep', '5'])\n", "argv-wait"),
    ("import subprocess\nsubprocess.run(('usleep', '5'))\n", "argv-wait"),
    ("import subprocess\nsubprocess.run('sleep 5', shell=True)\n", "argv-wait"),
    ("import os\nos.system('echo; sleep 1')\n", "argv-wait"),
    ("import subprocess\nsubprocess.run(['timeout', '30', 'cmd'])\n", "argv-wait"),
    ("import signal\nsignal.alarm(5)\n", "banned-reference"),
    ("import signal\nsignal.setitimer(signal.ITIMER_REAL, 5)\n", "banned-reference"),
    ("import threading\nthreading.Timer(5, print).start()\n", "banned-reference"),
    ("import os\nos.waitpid(1, os.WNOHANG)\n", "banned-reference"),
    ("from os import WNOHANG\n", "banned-reference"),
    ("import socket\ns.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, b'x')\n", "banned-reference"),
]

TIMEOUTS = [
    ("import subprocess\nsubprocess.run(['x'], timeout=30)\n", "timeout-argument"),
    ("import subprocess\nsubprocess.check_output(['x'], timeout=30)\n", "timeout-argument"),
    ("import subprocess\nsubprocess.run(['x'], timeout=0)\n", "timeout-argument"),
    ("def f(p):\n    p.wait(timeout=5)\n", "timeout-argument"),
    ("def f(p):\n    p.communicate(timeout=5)\n", "timeout-argument"),
    ("def f(q):\n    q.get(timeout=5)\n", "timeout-argument"),
    ("def f(lock):\n    lock.acquire(timeout=5)\n", "timeout-argument"),
    ("def f(t):\n    t.join(timeout=5)\n", "timeout-argument"),
    ("def f(x, n):\n    x.run(connect_timeout=n)\n", "timeout-argument"),
    ("def f(x):\n    x.run(wait_deadline=5)\n", "timeout-argument"),
    ("def f(x, opts):\n    x.run(**{'timeout': 5})\n", "timeout-argument"),
    ("import functools\nfunctools.partial(print, timeout=5)\n", "timeout-argument"),
    ("def f(sock):\n    sock.settimeout(5)\n", "timeout-call"),
    ("import socket\nsocket.setdefaulttimeout(5)\n", "timeout-call"),
    ("import pytest\npytestmark = pytest.mark.timeout(5)\n", "timeout-call"),
    ("import asyncio\nasync def f(c):\n    await asyncio.wait_for(c, 5)\n", "banned-reference"),
    ("import asyncio\nasync def f():\n    async with asyncio.timeout(5):\n        pass\n", "banned-reference"),
    ("import asyncio\nasync def f(ts):\n    await asyncio.wait(ts, timeout=5)\n", "timeout-argument"),
    ("import httpx\nhttpx.Timeout(5)\n", "timeout-call"),
    ("import httpx\nhttpx.Client(timeout=httpx.Timeout(5))\n", "timeout-call"),
    ("import httpx\nhttpx.Client(timeout=5)\n", "timeout-argument"),
    ("def f(client):\n    client.timeout = 5\n", "timeout-assignment"),
    ("def f(client):\n    client.timeout += 1\n", "timeout-assignment"),
    ("import socket\nsocket.create_connection(('h', 1), 5)\n", "timeout-argument"),
    ("import socket\nsocket.create_connection(('h', 1), timeout=5)\n", "timeout-argument"),
    ("import urllib.request\nurllib.request.urlopen('u', None, 5)\n", "timeout-argument"),
]

# The default of the library is a timeout too, so the call has to say what it wants.
IMPLICIT = [
    ("import httpx\nhttpx.get('u')\n", "implicit-timeout"),
    ("import httpx\nhttpx.post('u', json={})\n", "implicit-timeout"),
    ("import httpx\nhttpx.Client()\n", "implicit-timeout"),
    ("import httpx as h\nh.Client(transport=None, **{})\n", "implicit-timeout"),
    ("from httpx import AsyncClient\nAsyncClient()\n", "implicit-timeout"),
    ("import httpx\nopts = {}\nhttpx.Client(**opts)\n", "implicit-timeout"),
]

# `Event.wait(5)` and friends: the receiver's type is unknown, so the arguments say it.
TIMED_METHODS = [
    ("def f(e):\n    e.wait(5)\n", "timed-wait"),
    ("def f(c):\n    c.wait_for(lambda: True, 5)\n", "timed-wait"),
    ("def f(c):\n    c.wait_for(lambda: True, timeout=5)\n", "timeout-argument"),
    ("def f(p):\n    p.communicate(b'', 5)\n", "timed-wait"),
    ("def f(t, n):\n    t.join(n)\n", "timed-wait"),
    ("def f(t):\n    t.join(5)\n", "timed-wait"),
    ("def f(q):\n    q.get(True, 5)\n", "timed-wait"),
    ("def f(q, x):\n    q.put(x, True, 5)\n", "timed-wait"),
    ("def f(lock):\n    lock.acquire(True, 5)\n", "timed-wait"),
    ("def f(future):\n    future.result(5)\n", "timed-wait"),
    ("def f(poller):\n    poller.poll(5)\n", "timed-wait"),
    ("def f(selector):\n    selector.select(5)\n", "timed-wait"),
    ("import select\nselect.select([1], [], [], 5)\n", "timeout-argument"),
    ("import concurrent.futures as cf\ncf.wait([], 5)\n", "timeout-argument"),
]

ARGV_OPTIONS = [
    (
        "import subprocess\nsubprocess.run(['docker', 'compose', 'up', '--wait', '--wait-timeout', '30'])\n",
        "argv-timeout"
    ),
    ("import subprocess\nsubprocess.run(['docker', 'compose', 'up', '--wait-timeout=30'])\n", "argv-timeout"),
    ("import subprocess\nsubprocess.run(['goetia', 'daemon', 'start', '--timeout', '5'])\n", "argv-timeout"),
    ("def f(n):\n    return ['tool', f'--timeout={n}']\n", "argv-timeout"),
    ("ARGV = ('curl', '--max-time', '5', 'u')\n", "argv-timeout"),
    ("ARGV = ['curl', '-m', '5', 'u']\n", "argv-timeout"),
    ("ARGV = ['docker', 'stop', '-t', '5', 'c']\n", "argv-timeout"),
    ("ARGV = ['docker', 'stop', '--time', '5', 'c']\n", "argv-timeout"),
]

ENVIRONMENT = [
    ("import subprocess\nsubprocess.run(['x'], env={'COMPOSE_HTTP_TIMEOUT': '5'})\n", "env-timeout"),
    ("env = {}\nenv['DOCKER_CLIENT_TIMEOUT'] = '5'\n", "env-timeout"),
    ("def f(monkeypatch):\n    monkeypatch.setenv('GOETIA_TIMEOUT', '5')\n", "env-timeout"),
    ("import shlex\nshlex.split('docker compose up --wait --wait-timeout 30')\n", "argv-wait"),
    ("def f(a):\n    from time import *\n    sleep(1)\n", "sleep"),
]

CLOCK_POLLING = [
    ("import time\nwhile time.monotonic() < deadline:\n    pass\n", "clock-loop"),
    ("import time\nwhile not done():\n    now = time.monotonic()\n", "clock-loop"),
    ("import time\nfor attempt in attempts:\n    time.time()\n", "clock-loop"),
    ("from time import monotonic\nwhile monotonic() < deadline:\n    pass\n", "clock-loop"),
    ("import time as t\nwhile t.perf_counter_ns() < deadline:\n    pass\n", "clock-loop"),
    ("import time\ndeadline = time.monotonic() + 5\n", "clock-arithmetic"),
    ("import time\nelapsed = time.time() - start\n", "clock-arithmetic"),
    ("import time\nlate = time.monotonic() > deadline\n", "clock-arithmetic"),
    ("import datetime\nwhile datetime.datetime.now() < deadline:\n    pass\n", "clock-loop"),
    ("from datetime import datetime\nwhile datetime.now() < deadline:\n    pass\n", "clock-loop"),
    ("import datetime\nwhile True:\n    datetime.datetime.utcnow()\n", "clock-loop"),
]

PLATFORM = [
    ("import ctypes\nctypes.windll.kernel32.Sleep(100)\n", "sleep"),
    ("import win32api\nwin32api.Sleep(100)\n", "sleep"),
    ("import win32event\nwin32event.WaitForSingleObject(h, 5000)\n", "timed-wait"),
    ("import win32event\nwin32event.WaitForMultipleObjects([a, b], False, 0)\n", "timed-wait"),
    ("import anyio\nasync def f():\n    with anyio.fail_after(5):\n        pass\n", "sleep"),
    ("def f(proc):\n    while proc.poll() is None:\n        pass\n", "loop-poll"),
    ("def f(q):\n    while True:\n        q.get_nowait()\n", "loop-poll"),
]

HIDDEN = [
    ("exec('import time; time.sleep(1)')\n", "dynamic"),
    ("eval('1')\n", "dynamic"),
    ("__import__('time').sleep(1)\n", "dynamic"),
    ("import importlib\nimportlib.import_module('time')\n", "dynamic"),
    ("import time\ngetattr(time, 'sleep')(1)\n", "dynamic"),
    ("def f(x):\n    return getattr(x, 'settimeout')\n", "dynamic"),
    ("def broken(:\n", "unparsable"),
]

MUST_FLAG = SLEEPS + TIMEOUTS + IMPLICIT + TIMED_METHODS + ARGV_OPTIONS + ENVIRONMENT + PLATFORM + CLOCK_POLLING + HIDDEN

# What must be left alone ==============================================================================================

MUST_PASS = [
    "import win32event\nwin32event.WaitForSingleObject(h, win32event.INFINITE)\n",
    "import win32event\nwin32event.WaitForMultipleObjects([a, b], False, -1)\n",
    "def f(proc):\n    proc.poll()\n",
    "def f(q):\n    q.get_nowait()\n",
    "import os\nhome = os.environ['HOME']\n",
    "env = {'RT_DOMAIN': 'x', 'PATH': '/bin'}\n",
    "import shlex\nshlex.split('docker compose up --wait')\n",
    "import time\nstamp = time.time()\n",
    "import time\nprint(time.monotonic())\n",
    "import datetime\nnow = datetime.datetime.now()\nlater = now + datetime.timedelta(days=1)\n",
    "import datetime\nfor day in days:\n    datetime.datetime.now()\n",
    "names = ', '.join(parts)\n",
    "data = b''.join(chunks)\n",
    "text = ''.join(x for x in y)\n",
    "text = f'{a}'.join(parts)\n",
    "def f(sep: str, parts):\n    return sep.join(parts)\n",
    "def f(parts):\n    sep = ' '\n    return sep.join(parts)\n",
    "import os\npath = os.path.join(a, b)\n",
    "import os\npath = os.path.join(root)\n",
    "def f(t):\n    t.join()\n",
    "def f(p):\n    p.wait()\n",
    "def f(e):\n    e.wait()\n",
    "def f(c):\n    c.wait_for(lambda: True)\n",
    "def f(q):\n    q.get()\n",
    "def f(q):\n    q.get(True)\n",
    "def f(d):\n    d.get('key', 5)\n",
    "def f(lock):\n    lock.acquire()\n",
    "def f(lock):\n    lock.acquire(False)\n",
    "def f(future):\n    future.result()\n",
    "def f(sock):\n    sock.settimeout(None)\n",
    "import select\nselect.select([1], [], [])\n",
    "def f(poller):\n    poller.poll()\n",
    "import asyncio\nasync def f(ts):\n    await asyncio.wait(ts)\n",
    "import httpx\nhttpx.Client(timeout=None)\n",
    "import httpx\nhttpx.get('u', timeout=None)\n",
    "import httpx\nhttpx.Timeout(None)\n",
    "import httpx\nhttpx.Client(transport=t, timeout=None, follow_redirects=True)\n",
    "def f(x):\n    x.get('u', timeout=None)\n",
    "def f(log):\n    log.exception('boom')\n",
    "import subprocess\nraise subprocess.TimeoutExpired(['x'], 5)\n",
    "raise TimeoutError()\n",
    "import httpx\nraise httpx.ReadTimeout('slow')\n",
    "flags = {'--start', '--timeout', '--force'}\nassert not flags & set(argv)\n",
    "assert '--timeout' not in argv\n",
    "def test_passes_no_timeout():\n    pass\n",
    "'''A docstring about sleep and --timeout and deadlines.'''\n",
    "x = 'sleep 5'\n",
    "kind = 'sleep' in names\n",
    "import subprocess\nsubprocess.run(['docker', 'compose', 'up', '--wait'])\n",
    "import subprocess\nsubprocess.run(['docker', 'stop', 'c'])\n",
    "while True:\n    chunk = f.read(5)\n    if not chunk:\n        break\n",
    "import os\nflags = os.O_RDONLY\n",
]

# Markers ==============================================================================================================

# Sources whose every timeout is covered by a marker. (source, the line of the marker, its event)
EXEMPT = [
    (
        "import socket\n# external-bound: sshd answering\nsocket.create_connection(h, timeout=5)\n",
        2,
        "sshd answering",
    ),
    ("import socket\nsocket.create_connection(h, timeout=5)  # external-bound: sshd answering\n", 2, "sshd answering"),
    (
        "import subprocess\nsubprocess.run(\n    ['docker', 'info'],\n    timeout=60,  # external-bound: docker answering\n"
        "    check=False,\n)\n",
        4,
        "docker answering",
    ),
    (
        "import socket\n# Why this is a bound\n# external-bound: sshd answering\n# and more\nsocket.create_connection(h, timeout=5)\n",
        3,
        "sshd answering",
    ),
    (
        "import subprocess\n# external-bound: docker answering\nLIMIT = 60\nsubprocess.run(['docker'], timeout=LIMIT)\n",
        2,
        "docker answering",
    ),
    (
        "import httpx\n# external-bound: GitHub answering\nLIMIT = httpx.Timeout(60.0)\nc = httpx.Client(timeout=LIMIT)\n",
        2,
        "GitHub answering",
    ),
    (
        "import httpx\ndef f():\n    # external-bound: the front answering\n    with httpx.Client(timeout=5) as c:\n        c.get('u')\n",
        3,
        "the front answering",
    ),
    (
        "import httpx\n# external-bound: the front answering\nhttpx.get('u')\n",
        2,
        "the front answering",
    ),
]

# Sources where a marker does not help: (source, rule that must remain)
NOT_EXEMPTED = [
    # Never exempt.
    ("import time\n# external-bound: x\ntime.sleep(1)\n", "banned-reference"),
    ("import time\ntime.sleep(1)  # external-bound: x\n", "banned-reference"),
    ("import time\n# external-bound: x\ndeadline = time.monotonic() + 5\n", "clock-arithmetic"),
    ("import time\n# external-bound: x\nwhile time.monotonic() < d:\n    pass\n", "clock-loop"),
    ("import os\n# external-bound: x\nos.waitpid(1, os.WNOHANG)\n", "banned-reference"),
    ("import subprocess\n# external-bound: x\nsubprocess.run(['sleep', '1'])\n", "argv-wait"),
    # A marker is a comment on or directly above the statement, naming its event.
    ("import subprocess\n# external-bound: x\n\nsubprocess.run(['x'], timeout=5)\n", "timeout-argument"),
    ("import subprocess\nx = 1  # external-bound: x\nsubprocess.run(['x'], timeout=5)\n", "timeout-argument"),
    ("import subprocess\n# external-bound: x\nprint(1)\nsubprocess.run(['x'], timeout=5)\n", "timeout-argument"),
    ("import subprocess\n# external bound: x\nsubprocess.run(['x'], timeout=5)\n", "timeout-argument"),
    ("import subprocess\n# note external-bound: x\nsubprocess.run(['x'], timeout=5)\n", "timeout-argument"),
    ("import subprocess\ns = '# external-bound: x'\nsubprocess.run(['x'], timeout=5)\n", "timeout-argument"),
    ("import subprocess\nsubprocess.run(['x'], timeout=5)\n# external-bound: x\n", "timeout-argument"),
    # One marker covers one statement.
    (
        "import subprocess\n# external-bound: x\nsubprocess.run(['x'], timeout=5)\nsubprocess.run(['y'], timeout=5)\n",
        "timeout-argument"
    ),
    # A compound statement's marker covers its header, not its body.
    (
        "import httpx\nwith httpx.Client(timeout=5) as c:  # external-bound: x\n    c.get('u', timeout=7)\n",
        "timeout-argument",
    ),
    # A name is exempt only through a module-level assignment under a marker.
    ("import subprocess\ndef f(limit):\n    subprocess.run(['x'], timeout=limit)\n", "timeout-argument"),
    ("import subprocess\nLIMIT = 5\nsubprocess.run(['x'], timeout=LIMIT)\n", "timeout-argument"),
    (
        "import subprocess\ndef f():\n    # external-bound: x\n    limit = 5\n    subprocess.run(['x'], timeout=limit)\n",
        "timeout-argument",
    ),
    (
        "import subprocess\nOTHER = 1\n# external-bound: x\nOTHER2 = 2\nsubprocess.run(['x'], timeout=OTHER)\n",
        "timeout-argument"
    ),
    # Not a name at all.
    (
        "import subprocess\n# external-bound: x\nLIMIT = 5\nsubprocess.run(['x'], timeout=LIMIT + 1)\n",
        "timeout-argument"
    ),
]

# Markers that are themselves wrong: (source, text the finding must carry)
BAD_MARKERS = [
    ("# external-bound: nothing waits here\nx = 1\n", "exempts nothing"),
    ("import subprocess\n# external-bound:\nsubprocess.run(['x'], timeout=5)\n", "names no event"),
    ("import subprocess\n# external-bound:    \nsubprocess.run(['x'], timeout=5)\n", "names no event"),
    ("import time\n# external-bound: x\ntime.sleep(1)\n", "exempts nothing"),
    ("x = 1  # external-bound: not a wait\n", "exempts nothing"),
    ("# external-bound: a constant nothing uses\nLIMIT = 5\n", "exempts nothing"),
]
