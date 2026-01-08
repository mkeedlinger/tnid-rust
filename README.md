# TNID

**UUID-compatible IDs with names and compile-time type safety.**

TNIDs are UUIDv8-compatible identifiers that include a human-readable name and can be strictly typed at compile time.

```rust
use tnid::{TNID, TNIDName, NameStr};

struct User;
impl TNIDName for User {
    const ID_NAME: NameStr<'static> = NameStr::new_const("user");
}

// Create a time-ordered ID (like UUIDv7)
let user_id = TNID::<User>::new_time_ordered();
println!("{}", user_id);  // user.Br2flcNDfF6LYICnT

// Or a high-entropy ID (like UUIDv4)
let session_id = TNID::<User>::new_high_entropy();
```

## Why TNIDs?

- **Type-safe**: `TNID<User>` and `TNID<Post>` are different types. Accidentally passing a post ID to a user function? Compile error!
- **Named**: IDs include a human-readable name prefix. See `user.Br2flcNDfF6LYICnT` in your logs and instantly know what it is.
- **UUID-compatible**: TNIDs are valid UUIDv8s that work directly with Postgres UUID columns and UUID-expecting APIs.
- **Compile-time validated**: Try to create a TNID with name "INVALID"? Your code won't even compile.
- **Sortable strings**: Unlike UUID hex (case-insensitive mess), TNID strings sort correctly and have exactly one representation.

## Status

⚠️ **Beta**: The TNID spec is still being finalized and shouldn't be relied on for production use yet. This implementation tracks the evolving spec.

A full specification site will be available at [tnid.info](http://tnid.info).

## Installation

```bash
cargo add tnid
```

## Examples

### Creating TNIDs

```rust
use tnid::{TNID, TNIDName, NameStr};

struct Post;
impl TNIDName for Post {
    const ID_NAME: NameStr<'static> = NameStr::new_const("post");
}

// Time-ordered (v0) - sorts by creation time
let id = TNID::<Post>::new_v0();

// High-entropy (v1) - maximum randomness
let id = TNID::<Post>::new_v1();
```

### String Representations

```rust
// TNID string format - human-readable, sortable, unambiguous
let tnid_str = id.as_tnid_string();
// "post.Br2flcNDfF6LYICnT" - you can SEE it's a post ID!

// UUID hex format - for databases and APIs that expect UUIDs
let uuid_str = id.to_uuid_string_cased(false);
// "cab1952a-f09d-86d9-928e-96ea03dc6af3" - works in Postgres, MySQL, etc.

// Time-ordered IDs sort correctly in BOTH representations!
let id1 = TNID::<Post>::new_v0();
std::thread::sleep(std::time::Duration::from_millis(10));
let id2 = TNID::<Post>::new_v0();
assert!(id1.as_tnid_string() < id2.as_tnid_string());  // Sorts correctly!
assert!(id1.as_u128() < id2.as_u128());                // In all representations!
```

### Parsing

```rust
// Parse from TNID string
let id = TNID::<Post>::parse_tnid_string("post.Br2flcNDfF6LYICnT").unwrap();

// Parse from UUID string
let id = TNID::<Post>::parse_uuid_string("cab1952a-f09d-86d9-928e-96ea03dc6af3").unwrap();

// From raw u128
let id = TNID::<Post>::from_u128(0xCAB1952A_F09D_86D9_928E_96EA03DC6AF3).unwrap();
```

### Type Safety in Action

```rust
struct User;
impl TNIDName for User {
    const ID_NAME: NameStr<'static> = NameStr::new_const("user");
}

struct Post;
impl TNIDName for Post {
    const ID_NAME: NameStr<'static> = NameStr::new_const("post");
}

fn delete_user(user_id: TNID<User>) { /* ... */ }
fn delete_post(post_id: TNID<Post>) { /* ... */ }

let user_id = TNID::<User>::new_v0();
let post_id = TNID::<Post>::new_v0();

delete_user(user_id);  // Works!
delete_post(post_id);  // Works!

// delete_user(post_id);  // Compile error! Can't pass a Post ID to a User function
// delete_post(user_id);  // Compile error! Type mismatch caught at compile time
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `time` | ✓ | Time-based v0 TNID generation (like UUIDv7) |
| `rand` | ✓ | Random v1 TNID generation (like UUIDv4) |
| `encryption` | | Encrypt v0 to v1 to hide timestamps from clients, decrypt on the backend |
| `uuid` | | Convert to/from the `uuid` crate's `Uuid` type |

## Documentation

See the [API documentation](https://docs.rs/tnid) for complete details.

## License

MIT
