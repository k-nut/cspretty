# CSPretty

A small Rust based Content Security Policy pretty printer.

## Installation
```bash
cargo install cspretty
```

## Usage
`cspretty` expects to receive a content-security policy via stdin.
The easiest way to use it is to pipe to it directly. You might for example use
`curl -Is https://www.mozilla.org/en-US/ | grep content-security | cspretty`
to show a pretty printed version of Mozilla's CSP. 

`cspretty` accepts lines that start with `content-security-policy` (like curl's
headers would) or lines that only contain a CSP. Non matching lines will
be ignored.

See this video for an example:
[![asciicast](https://asciinema.org/a/RiOgqlZHnuneqo99a6pAxHXy9.svg)](https://asciinema.org/a/RiOgqlZHnuneqo99a6pAxHXy9)

## Functionality
`cspretty` adds line breaks between the different sources to make it easier
to get a quick overview. It also classifies values into four different classes
and applies a color to them: red for directives that are generally considered
unsafe, green for safe values, black on red for values that could not be parsed
and no highlighting for all other values.