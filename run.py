import os
import subprocess


# INPUT_DIR = "dataset/sample/d_link/bin"
# LOG_FILE = "log/tmp.log"
# SCRIPT_PATH = "/home/user/BinXray/extract.py"


from my_config import wsl_to_win_path
from my_config import (
    BASE_PATH,
    IDB_PATH,
    IDA_PATH,
    LOG_PATH,
    OUTPUT_DIR,
    RESULT_DIR,
    DBG_DIR,
)

IDA_SCRIPT_PATH = "/home/user/BinXray/extract.py"

IDB_PATH_WIN = wsl_to_win_path(IDB_PATH)


def main():
    target_proj = "expat"
    INPUT_DIR = os.path.join(BASE_PATH, "dataset_sample", target_proj, "bin")

    print(f"[*] IDA_SCRIPT_PATH: {IDA_SCRIPT_PATH}")
    print(f"[*] IDA_PATH:        {IDA_PATH}")
    print(f"[*] BASE_PATH:       {BASE_PATH}")
    print(f"[*] INPUT_DIR:       {INPUT_DIR}")
    print(f"[*] IDB_PATH:        {IDB_PATH}")
    print()

    os.makedirs(LOG_PATH,   exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(RESULT_DIR, exist_ok=True)
    os.makedirs(DBG_DIR, exist_ok=True)
    os.makedirs(IDB_PATH, exist_ok=True)

    all_file_list = os.listdir(INPUT_DIR)
    file_list = []
    for f in all_file_list:
        if (".i64" not in f) and ("idb" not in f):
            file_list.append(f)

    #! TODO: Fix me
    file_list = file_list

    for item in file_list:
        TARGET_PATH = os.path.join(INPUT_DIR, item)
        TARGET_PATH_WIN = wsl_to_win_path(TARGET_PATH)
        file_name = os.path.basename(TARGET_PATH)
        LOG_FILE = os.path.join(LOG_PATH, f"{file_name}.log")
        LOG_FILE_WIN = wsl_to_win_path(LOG_FILE)

        print(f"[*] TARGET_PATH:     {TARGET_PATH}")
        print(f"[*] TARGET_PATH_WIN: {TARGET_PATH_WIN}")
        print(f"[*] LOG_FILE:        {LOG_FILE}")
        print(f"[*] LOG_FILE_WIN:    {LOG_FILE_WIN}")

        print()

        cmd = [
            IDA_PATH,
            "-c",
            "-A",
            f"-L{LOG_FILE_WIN}",
            f"-S{IDA_SCRIPT_PATH}",
            f"-o{os.path.join(IDB_PATH_WIN, file_name)}.idb",
            # f"-o{IDB_PATH_WIN}/{file_name}.idb",
            TARGET_PATH_WIN,
        ]
        print(" ".join(cmd))

        subprocess.run(cmd, check=False)

if __name__ == "__main__":
    main()
