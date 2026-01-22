# BinXray (Reimplementation & Environment Adaptation)

This repository provides a reimplementation and environment adaptation of **BinXray**,
a system proposed in the paper:

- *Patch-Based Vulnerability Matching for Binary Programs* (ISSTA 2020)

This is **not** an official release by the original authors.

## Scope

The primary goal of this repository is to make BinXray runnable in modern environments:
- Newer **Python** versions
- Recent **IDA / IDAPython** versions

This repository is intended to support experimental evaluation in our research.

## Upstream Reference

The original authors provided artifact materials via the following page:
- https://sites.google.com/view/submission-for-issta-2020

The original scripts released by the authors were used as a reference
during reimplementation, but are not redistributed in this repository.

## What this repository contains

- A runnable pipeline for BinXray-style feature extraction / matching, adapted for:
  - modern Python runtime
  - updated IDA automation workflow
- Refactoring and compatibility fixes around:
  - filesystem layout
  - path handling
  - IDA batch execution
  - serialization and intermediate outputs (as needed)

## What this repository does NOT contain

- The original dataset used in the paper is **not included**.
- This repository does **not** redistribute any non-public or restricted materials.

All experiments are conducted on independently prepared datasets.

## Requirements (example)

- Python: 3.x
- IDA: tested with a recent IDA version (see notes below)

> Note: Exact supported versions depend on your environment and may require minor adjustments.

## Usage (high-level)

Typical workflow:
1. Prepare binaries under an input directory.
2. Run IDA in batch mode to extract required information.
3. Run the Python pipeline to build representations and perform matching.

See scripts and comments in this repository for the current entry points.

## Reproducibility Notes

- Results may vary depending on:
  - compiler/toolchain differences
  - IDA version and analysis settings
  - operating system and filesystem specifics
- For consistent evaluation, record:
  - Python version
  - IDA version
  - configuration flags and runtime arguments
  - dataset snapshot / commit hash

## Citation

If you use this repository in academic work, please cite the original paper:

- *Patch-Based Vulnerability Matching for Binary Programs* (ISSTA 2020)

## License

MIT License (for this repository only).

This license applies only to code in this repository that is written or substantially modified
by the authors of this repository. It does not imply any license grant for any upstream
materials referenced above.

## Contact

For questions or issues about this reimplementation/adaptation, please open an issue in this repository.
