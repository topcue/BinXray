import os
import multiprocessing
from tqdm import tqdm

from my_config import wsl_to_win_path, run_ida
from my_config import (
    BASE_PATH,
    IDB_PATH,
    IDA_PATH,
    LOG_PATH,
    OUTPUT_DIR,
    PICKLE_PATH,
    NUM_JOBS,
    IDA_SCRIPT_PATH,
    PROJECT_NAME,
    DATASET_NAME
)

IDB_PATH_WIN = wsl_to_win_path(IDB_PATH)


def main():
    DEBUG = True

    INPUT_DIR = os.path.join(BASE_PATH, DATASET_NAME, PROJECT_NAME, "bin")

    print(f"[*] IDA_SCRIPT_PATH: {IDA_SCRIPT_PATH}")
    print(f"[*] IDA_PATH:        {IDA_PATH}")
    print(f"[*] BASE_PATH:       {BASE_PATH}")
    print(f"[*] INPUT_DIR:       {INPUT_DIR}")
    print(f"[*] IDB_PATH:        {IDB_PATH}")
    print()

    os.makedirs(LOG_PATH,   exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(PICKLE_PATH, exist_ok=True)
    os.makedirs(IDB_PATH, exist_ok=True)

    all_file_list = os.listdir(INPUT_DIR)
    file_list = []
    for f in all_file_list:
        if (".i64" not in f) and ("idb" not in f):
            file_list.append(f)



    file_list = file_list

    jobs = []
    for item in file_list:
        TARGET_PATH = os.path.join(INPUT_DIR, item)
        TARGET_PATH_WIN = wsl_to_win_path(TARGET_PATH)
        file_name = os.path.basename(TARGET_PATH)
        LOG_FILE = os.path.join(LOG_PATH, f"{file_name}.log")
        LOG_FILE_WIN = wsl_to_win_path(LOG_FILE)

        if DEBUG:
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
            TARGET_PATH_WIN,
        ]
        jobs.append((cmd, '', '', False))
    
    print("[*] IDA processing..")
    with multiprocessing.Pool(processes=NUM_JOBS) as pool:
        for _ in tqdm(
            pool.imap_unordered(run_ida, jobs),
            total=len(jobs),
        ):
            pass

if __name__ == "__main__":
    main()

# EOF
