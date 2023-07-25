<p align="center">
 <img width="100px" src=./images/cnsl.jpg align="center" alt="GitHub Readme" />
 <h2 align="center">Seccomp Profile Refinement Readme! </h2>
</p>

| The aim of this repository is a proposal of building a precise system call whitelist to avoid the over-privilege issue for containerized applications at two different execution phases: the initialization and the serving phases. | ![ContainerHIDS](https://i0.wp.com/foxutech.com/wp-content/uploads/2017/03/Docker-Security.png?fit=820%2C407&ssl=1 "ContainerHIDS") |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------:|

# TABLE OF CONTENTS
- [Background](#background)
- [Setup](#setup)
- Usage
- Experiment results

# BACKGROUND 
## Research paper
We present our approach and the findings of this work in the following research paper:
**Refining Seccomp Security Profile for Container Hardening** - *Mobisec Conference 2022* & the completed and extended version **Towards Secure Containerized Applications with Seccomp Profile Refinement**, *submitted to Computers & Security Journal 2022*.
## Overall Architecture
<img src="images/architecture.png" width="100%">

- **Input**: Image is pulled from Docker-hub with the information is saved to a json file

- **Dynamic analysis**: run container with a configurable time (60 seconds); then use Sysdig tool to monitor container and collect binaries & libraries in runtime

- **Static analysis**: use source code + binaries & libs to build an application call graph (LLVM compiler + SVF tool + binary analysis); utilize Glibc to map between functions to system calls

- **Output**: Seccomp profiles contains 2 whitelists of system calls corresponding initialization and serving phase

# SETUP

## Requirements
- Ubuntu 20.04 64-bit
- Docker version 20.10.17
- [Sysdig](https://sysdig.com/) version 0.32.0

# USAGE 
```
    cd ./script
    ./setup.sh #
```








