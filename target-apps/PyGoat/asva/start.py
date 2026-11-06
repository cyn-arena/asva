"""Initialize the runtime database before starting the application."""
import os
import subprocess
import sys

subprocess.run([sys.executable, "manage.py", "migrate", "--noinput"], check=True)
subprocess.run([sys.executable, "manage.py", "populate_challenges"], check=True)
os.execvp(sys.argv[1], sys.argv[1:])
