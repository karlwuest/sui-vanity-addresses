# Sui Vanity Address Generator

This tool allows generating addresses that start with a provided string (converted to hexspeak).
This only works for strings for which an obvious hexspeak version exists, e.g. "seaice" = `5ea1ce`,
otherwise the program will return an error. Alternatively, a hex prefix can be provided directly.

```sh
$ vanity -h
Usage: vanity [OPTIONS] <VANITY_PREFIX>

Arguments:
  <VANITY_PREFIX>  A string that the vanity address must start with. This string will be converted to closely matching hexspeak characters. Alternatively, a hex prefix can be provided that must start with `0x`

Options:
      --addresses-per-round <ADDRESSES_PER_ROUND>  Number of keys to generate per round. This determines how many keys are generated in parallel and how quickly the program will provide progress output [default: 10000]
  -n, --n-vanity-addresses <N_VANITY_ADDRESSES>    Number of vanity addresses to generate. If provided, the program will stop at the end of the round after finding the specified number of vanity addresses. The program may still output more
                                                   than the specified number of vanity addresses if it finds additional addresses in a single round [default: 1]
  -o, --output-dir <OUTPUT_DIR>                    The output directory to write the keys to [default: .]
  -h, --help                                       Print help
```
