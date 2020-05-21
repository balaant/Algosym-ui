import subprocess
import os
# javac -d C:\Users\Riven\PycharmProjects\best_hack2020\users_files_bin\123 Algorithm2.java

try:
    filename = os.getcwd()+r"/users_files/202cb962ac59075b964b07152d234b70\Algorithm2.java"
    bin_path = os.getcwd()+r"/users_files_bin" +"/123"
    subprocess.call(f"javac -d {bin_path} {filename}", shell=True)
except Exception:
    pass