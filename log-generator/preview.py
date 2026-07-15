#!/usr/bin/env python3
"""Print 20 sample log lines to stdout without sending to syslog-ng."""
import random
from generate_logs import POPULATION

for i in range(20):
    fn = random.choice(POPULATION)
    print(fn().rstrip())
