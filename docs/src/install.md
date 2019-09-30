## Source Code and Licensing
Exact Capture is available from [github.com](https://github.com/exablaze-oss/exact-capture) as an open source project.
If you would like to discuss alternative licensing schemes, please contact the Exablaze sales team.

## Hardware Requirements
Exact Capture requires a high performance server to operate optimally.
Please read the [Server Requirements](server.md) for more details.

## Software Requirements
To build the software, you will need a recent C compiler supporting C99 or higher, and to have installed the ExaNIC software libraries (also available from github.com).

##Building
There are 3 build options for Exact Capture:

1. Performance build
2. Error assertions build
3. Debug build

By default, Exact Capture is built in performance mode.
In performance mode, unnecessary internal error checking is disabled.
For example, bounds checks on memory access.
To build Exact Capture in performance mode, simply run `make` in the top level.

To build a version with stricter internal error checking assertions, run `make assert`.
This version is still capable of operating at 10Gb/s on many systems, though will suffer marginal performance degradation, especially on slower CPUs.

To build a debug version, run `make debug`.
The debug build applies stricter warning checking requirements at build time, and enables detailed debug tracing throughout the application.
This version is unlikely to keep up at high-rate.

## (un)Installation
To install Exact Capture, run `make install` as the root user. To uninstall, run `make uninstall` as the root user.
