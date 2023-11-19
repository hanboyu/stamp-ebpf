# STAMP Collector

## Usage
Load the collector kernel function to interface `eth0`, run collect data for 10 seconds, and save the collected result at `data/test.csv`:<br/>
`$ ./collector_user --dev eth0 --filename collector_kern.o --out-file test.csv --duration 10`

Unload collector kernel function:<br/>
`$ ./collector_user --dev eth0 --unload-all`

## Command Line Options
| Command | Description |
| --- | --- |
| Required options |
|`-d`, `--dev <ifname>` | Operate on device `<ifname>`|
| Required for running collector |
| `-o`, `--out-file <out-file>` | Path to the output csv file |
| `-t`, `--duration <seconds>` | Duration of running collector in seconds |
| Other options |
| `-h`, `--help` | Show help |
|`-U`, `--unload <id>` | Unload XDP program <id> instead of loading |
|`--unload-all` | Unload all XDP programs on device |
| `--filename <file>` | Load program from `<file>` | 
| `--progname <name>` | Load program from function `<name>` in the ELF file |
