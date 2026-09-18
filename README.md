# Hiding

[![tests](https://github.com/AldaronLau/hiding/actions/workflows/ci.yml/badge.svg)](https://github.com/AldaronLau/hiding/actions/workflows/ci.yml)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/y/AldaronLau/hiding)](https://github.com/AldaronLau/hiding)
[![GitHub contributors](https://img.shields.io/github/contributors/AldaronLau/hiding)](https://github.com/AldaronLau/hiding/graphs/contributors)  
[![Crates.io](https://img.shields.io/crates/v/hiding)](https://crates.io/crates/hiding)
[![Crates.io](https://img.shields.io/crates/d/hiding)](https://crates.io/crates/hiding)
[![Crates.io (recent)](https://img.shields.io/crates/dr/hiding)](https://crates.io/crates/hiding)  
[![Crates.io](https://img.shields.io/crates/l/hiding)](https://github.com/search?q=repo%3AAldaronLau%2Fhiding+path%3A**%2FLICENSE*&type=code)
[![Docs.rs](https://docs.rs/hiding/badge.svg)](https://docs.rs/hiding/)

Simple crate for hiding secrets

Check out the [documentation] for examples.

### Features

 - Wrapper types for secrets that zeroïze on drop, implements debug redacting the contents
 - Stack and heap options
 - Prevents moves where zeroïzing might not happen otherwise
 - Built on the `zeroize` crate

## MSRV

The current MSRV is Rust 1.95.

Any future MSRV updates will follow the [Ardaku MSRV guidelines].

## License

Copyright © 2026 The Hiding Contributors.

Licensed under any of
 - Apache License, Version 2.0, ([LICENSE\_APACHE] or
   <https://www.apache.org/licenses/LICENSE-2.0>)
 - Boost Software License, Version 1.0, ([LICENSE\_BOOST] or
   <https://www.boost.org/LICENSE_1_0.txt>)
 - MIT License, ([LICENSE\_MIT] or <https://mit-license.org/>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as described above, without any additional terms or conditions.

## AI / LLM (Non-)Usage

All of my projects are developed without using AI/LLM tooling.  LLM usage for
contributions to any of my projects is strictly disallowed, with the exception
of LLM tooling trained on exclusively CC0, Unlicense, or equivalently-licensed
code.  Additionally, any LLM tooling used for contributions must not claim or
require claiming its own authorship according to its usage policy.

By opening a PR on any of my repositories, you assert that the work (excluding
any test data) is either human generated, computer generated trained on works in
the public domain (with generated works under your sole ownership to license),
or a combination of the two.  LLM bug reports are welcome as issues, as long as
there is a disclaimer that it was discovered with an LLM.  For comments on PRs
and issues, LLM usage is strictly disallowed, including quoting or citing an
LLM's opinion or suggestion.

## Help

If you want help using or contributing to this library, feel free to send me an
email at <aldaronlau+oss@gmail.com>.

[Ardaku MSRV guidelines]: https://github.com/ardaku/.github/blob/v0/profile/MSRV.md
[LICENSE\_APACHE]: https://github.com/AldaronLau/hiding/blob/v0/LICENSE_APACHE
[LICENSE\_BOOST]: https://github.com/AldaronLau/hiding/blob/v0/LICENSE_BOOST
[LICENSE\_MIT]: https://github.com/AldaronLau/hiding/blob/v0/LICENSE_MIT
[documentation]: https://docs.rs/hiding
