# Cld

Linker for the Coff object file format. This project is meant as the base for [zig](https://ziglang.org)'s self-hosted linker.
This repository will probably not contain a full-featured linker as the main work will move to the Zig repository at one point,
as well as upstreamed into [zld](https://github.com/kubkon/zld).
For those reasons, the code within this repository will be closely inline with the structure of the other linkers of the Zig project.

## building

Cld will always closely follow the master branch of the Zig programming language.
Building `Cld` itself will be as simple as running:
```sh
zig build
```
This will create a `cld` binary in the `zig-out/bin` folder.

To enable debug logging, the CLI flag `-Denable-logging` can be supplied to the `zig build` command.
This will enable logging for the built binary, meaning it must be re-compiled to disable logging once again.
