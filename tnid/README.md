# TNID

**UUID-compatible IDs with names and compile-time type safety.**

TNIDs are UUIDv8-compatible identifiers that include a human-readable name and can be strictly typed at compile time.

```rust
use tnid::{Case, NameStr, Tnid, TnidName};

struct User;
impl TnidName for User {
    const ID_NAME: NameStr<'static> = NameStr::new_const("user");
}

// Create a time-ordered ID (like UUIDv7)
let user_id = Tnid::<User>::new_time_ordered();
println!("{}", user_id);  // user.Br2flcNDfF6LYICnT

// Or a high-entropy ID (like UUIDv4)
let session_id = Tnid::<User>::new_high_entropy();
```

## Why TNIDs?

- **Type-safe**: `Tnid<User>` and `Tnid<Post>` are different types. Accidentally passing a post ID to a `user` function? Compile error.
- **Named**: IDs include a human-readable name prefix. See `user.Br2flcNDfF6LYICnT` in your logs and instantly know what it is.
- **UUID-compatible**: TNIDs are valid UUIDv8s that work directly with Postgres UUID columns and UUID-expecting APIs.
- **Compile-time validated**: Try to create a TNID with name "INVALID"? Your code won't even compile.
- **Sortable strings**: Unlike UUID hex (case-insensitive mess), TNID strings sort correctly and have exactly one representation.

## Status

**Beta**: The TNID spec is still being finalized and shouldn't be relied on for production use yet. This implementation tracks the evolving spec.

A full specification site will be available at [tnid.info](http://tnid.info).

## Installation

```bash
cargo add tnid
```

## Documentation

See the [API documentation](https://docs.rs/tnid) for complete details, examples, and feature flags.

## License

MIT
