import os
import argparse
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


def parse_args():
    parser = argparse.ArgumentParser(description="Run IDA analysis on binaries.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-run IDA even if output (.idb/.i64) already exists"
        )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show more debugging messages."
        )
    return parser.parse_args()


def collect_targets(input_dir: str, idb_dir: str, force: bool):
    # Collect already-processed binary names (stems)
    done = set()
    for name in os.listdir(idb_dir):
        lname = name.lower()
        if lname.endswith(".i64") or lname.endswith(".idb"):
            stem, _ = os.path.splitext(name)
            done.add(stem)

    # Collect input binaries
    all_inputs = []
    for name in os.listdir(input_dir):
        lname = name.lower()
        # Exclude IDA database files if they exist in input_dir
        if lname.endswith(".i64") or lname.endswith(".idb"):
            continue
        all_inputs.append(name)

    # Filter targets
    targets = []
    for name in sorted(all_inputs):
        if not force and name in done:
            continue
        targets.append(name)

    # Print summary information
    print(
        "[*] Target collection summary\n"
        f"    - Input binaries      : {len(all_inputs)}\n"
        f"    - Already processed   : {len(done)}\n"
        f"    - Targets to process  : {len(targets)}\n"
        f"    - Force mode          : {force}"
    )
    return targets


def main():
    args = parse_args()
    force = args.force
    DEBUG = args.debug

    print(f"[*] PROJECT_NAME: {PROJECT_NAME}\n")

    INPUT_DIR = os.path.join(BASE_PATH, DATASET_NAME, PROJECT_NAME, "bin")

    print(f"[*] IDA_SCRIPT_PATH: {IDA_SCRIPT_PATH}")
    print(f"[*] IDA_PATH:        {IDA_PATH}")
    print(f"[*] BASE_PATH:       {BASE_PATH}")
    print(f"[*] INPUT_DIR:       {INPUT_DIR}")
    print(f"[*] IDB_PATH:        {IDB_PATH}")
    print(f"[*] PICKLE_PATH:     {PICKLE_PATH}")
    print(f"[*] FORCE:           {force}")
    print()

    os.makedirs(LOG_PATH,    exist_ok=True)
    os.makedirs(OUTPUT_DIR,  exist_ok=True)
    os.makedirs(PICKLE_PATH, exist_ok=True)
    os.makedirs(IDB_PATH,    exist_ok=True)

    if DEBUG:
        print(f"[DEBUG] INPUT_DIR: {INPUT_DIR}")
        print(f"[DEBUG] IDB_PATH:  {IDB_PATH}")

    file_list = collect_targets(INPUT_DIR, IDB_PATH, force)

    if DEBUG:
        for f in file_list:
            print(f"[DEBUG] target file: {f}")

    jobs = []
    for item in file_list:
        TARGET_PATH = os.path.join(INPUT_DIR, item)
        TARGET_PATH_WIN = wsl_to_win_path(TARGET_PATH)
        file_name = os.path.basename(TARGET_PATH)

        LOG_FILE = os.path.join(LOG_PATH, f"{file_name}.log")
        LOG_FILE_WIN = wsl_to_win_path(LOG_FILE)

        if DEBUG:
            print(f"[*] TARGET_PATH: {TARGET_PATH}")

        cmd = [
            IDA_PATH,
            "-c",
            "-A",
            f"-L{LOG_FILE_WIN}",
            f"-S{IDA_SCRIPT_PATH}",
            f"-o{os.path.join(IDB_PATH_WIN, file_name)}.idb",
            TARGET_PATH_WIN,
        ]
        jobs.append((cmd, "", "", False))

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
