# STAMP Reflector

## Usage
We use the `xdp-loader` provided by `xdp-tools` for loading and unloading the reflector function. The `xdp-loader` executable file is automatically copied to the current directory when using `make` to compile. 

Load the reflector kernel function to interface `eth0`:<br/>
`$ ./xdp-loader load eth0 reflector_kern.o`

Unload reflector kernel function:<br/>
`$ ./xdp-loader unload eth0 --all`

## xdp-load
Please refer to the [xdp-loader documentation](https://github.com/xdp-project/xdp-tools/blob/c9913f9ffc8b5a70d547c7dda6491fef9695464d/xdp-loader/README.org) for command line options.
