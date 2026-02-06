# tnid-cli

Command-line tool for working with [TNIDs](https://crates.io/crates/tnid) (Typed Named Identifiers).

## Installation

```bash
cargo install tnid-cli
```

This installs the `tnid` binary.

## Usage

### Generate

```bash
# Generate a time-ordered (V0) TNID
$ tnid generate user
user.BsOdOgguzJorJeVH7

# Generate a high-entropy (V1) TNID
$ tnid generate user -n 1
user.8z099cGumNjXw8whQ

# Output as UUID
$ tnid generate user -o uuid
d6157338-6696-8b69-895b-2e3528a74163
```

### Inspect

```bash
$ tnid inspect user.BsOdOgguzJorJeVH7
name: user
name_hex: d6157
variant: V0
tnid_string: user.BsOdOgguzJorJeVH7
uuid_string: d6157338-6696-86cb-8ebf-534dd4aa0488
```

Also accepts UUID format as input:

```bash
$ tnid inspect d6157338-6696-86cb-8ebf-534dd4aa0488
```

### Encrypt / Decrypt

Encrypt a V0 TNID to V1 using format-preserving encryption:

```bash
$ tnid encrypt user.BsOdOgguzJorJeVH7 0102030405060708090a0b0c0d0e0f10
user.-8hAMlKY0mjrmzQHv

$ tnid decrypt user.-8hAMlKY0mjrmzQHv 0102030405060708090a0b0c0d0e0f10
user.BsOdOgguzJorJeVH7
```

The key can also be provided via the `TNID_KEY` environment variable:

```bash
$ export TNID_KEY=0102030405060708090a0b0c0d0e0f10
$ tnid encrypt user.BsOdOgguzJorJeVH7
$ tnid decrypt user.-8hAMlKY0mjrmzQHv
```

### Validate Name

```bash
$ tnid validate-name user
valid

$ tnid validate-name User
invalid: invalid character 'U' (0x55) in name; only 0-4 and a-z are allowed
```

## License

MIT
