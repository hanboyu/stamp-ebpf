# Install Dependencies
Operating system: Ubuntu 22.04 or later 

## Based on libxdp and libbpf
This project leverages [libxdp](https://github.com/xdp-project/xdp-tools/) to load and manage XDP programs. The libxdp library is maintained as part of the [XDP Project](https://github.com/xdp-project). The tutorial also leverages [libbpf](https://github.com/libbpf/libbpf/) to ease development and loading of BPF programs. The libbpf library is part of the kernel tree under [tools/lib/bpf](https://github.com/torvalds/linux/blob/master/tools/lib/bpf/README.rst), but Facebook engineers maintain a stand-alone build on GitHub under https://github.com/libbpf/libbpf.

### libxdp and libbpf as git-submodules
This repository uses both [libxdp](https://github.com/xdp-project/xdp-tools/) and [libbpf](https://github.com/libbpf/libbpf) as git-submodules. After cloning this repository you need to run the command:<br/>
`git submodule update --init`

## Dependencies

The main dependencies are `libxdp`, `libbpf`, `llvm`, `clang` and `libelf`. LLVM+clang compiles our restricted-C programs into BPF-byte-code, which is stored in an ELF object file (`libelf`), that is loaded by `libbpf` into the kernel via the `bpf` syscall. XDP programs are managed by `libxdp` which implements the XDP multi-dispatch protocol.

The Makefiles in this repo will try to detect if you are missing some dependencies, and give you some pointers.

** Packages on Debian/Ubuntu

Install the dependencies:

`$ sudo apt install clang llvm libelf-dev libpcap-dev build-essential`

To install the 'perf' utility, run this:

`$ sudo apt install linux-tools-$(uname -r)`

## Kernel Headers Dependency

The Linux kernel provides a number of header files, which are usually installed
in `/usr/include/linux`. The different Linux distributions usually provide a
software package with these headers.

`$ sudo apt install linux-headers-$(uname -r)`


## Recommended Tools

The `bpftool` is the recommended tool for inspecting BPF programs running on
your system. It also offers simple manipulation of eBPF programs and maps.
The `bpftool` is part of the Linux kernel tree under [tools/bpf/bpftool/](https://github.com/torvalds/linux/tree/master/tools/bpf/bpftool), but
some Linux distributions also ship the tool as a software package.

`$ sudo apt install linux-tools-common linux-tools-generic`

## Reference
For more information on installing dependencies on different Linux distributions please refer to https://github.com/xdp-project/xdp-tutorial/blob/master/setup_dependencies.org

