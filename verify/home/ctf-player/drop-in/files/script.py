import os
import subprocess
for f in os.listdir("."):
	subprocess.run("../decrypt.sh "+f)