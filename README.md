# jwtcrack
a dumb jwt cracker

# Usage
```console
$ jwtcrack -h
Usage: jwtcrack [OPTIONS] <JWT> <WORDLIST>

Arguments:
  <JWT>       JWT token to crack
  <WORDLIST>  Path to the wordlist file containing potential secrets

Options:
  -t, --threads <THREADS>  Number of threads to use (0 means use default thread count) [default: 0]
  -h, --help               Print help

```
