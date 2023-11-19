# stamp-ebpf

## Setup 
1. Follow the [install_dependencies.md](install_dependencies.md) to setup dependencies. 
2. Run `./config` to verify dependencies and generate `config.mk` for compiling. 
3. Run `make` to compile all modules.

## Quick Start
A quick guide for running all the STAMP modules included. For more details please refer to the readme file located at each folder.

### STAMP Collector
Load the collector kernel function to interface `eth0`, run collect data for 10 seconds, and save the collected result at `data/test.csv`:<br/>
`$ src/collector/collector_user --dev eth0 --filename src/collector/collector_kern.o --out-file data/test.csv --duration 10`

Unload collector kernel function:<br/>
`$ src/collector/collector_user --dev eth0 --unload-all`

### STAMP Reflector
Load the reflector kernel function to interface `eth0`:<br/>
`$ src/reflector/xdp-loader load eth0 src/reflector/reflector_kern.o`

Unload reflector kernel function:<br/>
`$ src/reflector/xdp-loader unload eth0 --all`