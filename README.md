# webauthn-signer

A library to allow WebAuthn to be used for signing arbitrary payloads.

## Design principles

### Root keys
- Root keys are WebAuthn keys which can be used to sign payloads.
- Multiple root keys must be supported, in case one in lost/stolen/etc. or if
  platform-specific keys are used (can't just transport the one key between
  devices).
  - We should always distinguish between loss, compromise, and accessibility of
    a key. Multiple keys are the solution to all of these, but may have
    different implications in each case.
- Payloads can be signed by any one of the root keys.
  - Payloads always include a reference to the root key which signed them, and a
    timestamp.
- Any change to the set of root keys requires the signatures of all other root
  keys.
  - Removal of a root key requires signatures of all root keys other than the
    one being removed.
  - Addition of a root key requires signatures of all existing root keys plus
    that of the new one.

### Endpoints
- An endpoint is a device which has access to a root key, such that it can
  participate in signing operations.
  - A root key is not necessarily 1:1 mapped to an endpoint. For example, a
    Yubikey could be moved between endpoints, granting access to an entirely new
    endpoint, etc.
- We assume a particular endpoint has no memory of any state, other than the
  ability to sign a payload with a WebAuthn key with a particular ID. An endpoint
  which has forgotten the state is called a "naive endpoint".
- It's desirable to store the state on a service somewhere, so it can be accessed
  from anywhere.
  - The service itself may want to use the state as a way to authenticate the
    user, and grant access to some other data.
- We assume the state can be stored somewhere entirely untrusted, and each
  endpoint needs to be able to verify the validity of the state.
- If we present a state to a naive endpoint which was signed by a key known to
  that endpoint, the endpoint should accept it as legitimate.
- Some root keys may be local to a particular endpoint (think Windows Hello
  etc.)
  - Due to this, we need to be able to represent a pending root key signing
    state, as we cannot necessarily complete a re-signing operation entirely
    locally.
  - To complete a signing cross-endpoint, each endpoint which possesses a root
    key must validate the latest state (i.e. make it not naive).
  - The node initiating the re-signing first signs the updated root key set.
    This pending (partially signed) state is then shared by the service to any
    other endpoint which might be able to add to the signatures.
  - We can trust that the service has not tampered with the state, because: we
    have already verified that we trust the root key that just added the first
    signature; thus we can verify that we trust the new state which has been
    presented; and the user knows that they just initiated the request and so
    can safely continue signing with the remaining keys.
  - If the user knows that they did *not* just initiate this signing, that
    could indicate that the first key to sign was compromised by someone else.
    In this case, they should ignore the pending signing request, and initiate
    another which removes the compromised key. Assuming they still possess the
    remaining root keys, they can complete this signing request to remove the
    compromised key.
  - The UI should indicate to the user a clear summary/diff of what they are
    signing. This will allow the user to verify that they are signing what they
    expect on each endpoint.

### Threat models
We consider two distinct threat models:
1. The service hosting the root key state tampers with it, to insert its own
   root keys.
   - This is mitigated by every change to the root key set requiring
2. An attacker has stolen the private key corresponding to a root key.

We assume that these are distinct, and the service can provide additional
protections against (2) due to this.

For example, what if a key is compromised and we delete it from the state, but
the malicious actor keeps a copy of the state before this and presents it to a
naive endpoint?

- Each version of the state is timestamped, and subject to expiry. The previous
  item in the chain will eventually expire.
- If only a single key is compromised, and there are at least 2 other root keys
  (i.e. a total of 3), then the attacker does not have enough keys to change or
  re-sign the set of root keys. They can, however, sign messages with that root
  key until the root key state expires.
- As another layer, the threat model of a stolen key is unlikely to intersect
  with the compromise (or deliberate malice) of the service hosting the state.
  The service is likely to always serve the latest state, as it has no incentive
  to co-operate with a distinct attacker who has stolen a root key.

### Signature verification
How does someone else verify that a message was signed by a user they trust?

- The set of root keys can evolve over time, such that none of the original
  root keys remain in the set.
- One solution (which has a fatal flaw) would be to define the first root key
  of a user as the "genesis key". The fingerprint of this key defines the
  identity of the user.
  - As a user modifies their set of root keys, a chain of changes is maintained,
    rooted at the genesis key.
  - Over time, the genesis key could be removed entirely from the set of root
    keys by adding a new root key, signing this with the genesis, and then
    removing the genesis, signing this with the new root.
  - Problem: if the genesis key is compromised, someone else could create a
    viable new chain from scratch and present this alternative chain to any
    naive endpoint.
  - More generally, if the set of root keys ever narrows to a single key (not
    just at the genesis, it could be anywhere in the chain), then compromise of
    that single key compromises the entire chain thereafter. The compromise
    could happen at any later date, not just concurrently with the narrowing of
    the chain, because the compromised key could then rewrite its own version of
    the chain after that point.
- What if instead, the genesis key is a temporary local key which is thrown away
  after its first signing. It is required to first sign 3 separate WebAuthn root
  keys. Thus, if any single key is compromised, it cannot rewrite the chain, as
  any subsequent message requires at least 2 of the original 3 keys to sign.
  - Again more generally, we should never allow the set of root keys to drop
    below 3.
  - Note that with this approach, chain rewriting would still be possible if 2/3
    keys included in a single element of the chain is compromised at some point
    in the future (not necessarily at the same time). For example, if some point
    in the chain contains keys `{A,B,C}` and after a number of changes it
    eventually evolves to `{D,E,F}`, perhaps partly because keys `A` and `B`
    were compromised in separate events, an attacker who has both `A` and `B`
    could rewrite the chain from the `{A,B,C}` point.
    - There are a number of defences against that:
      - WebAuthn key compromise is considered extremely unlikely anyway, and
        compromise of 2 (or more) keys by the same attacker that appear in a
        single key set even more unlikely.
      - It is unlikely that an attacker who compromises these keys (for example,
        physical theft of two separate Yubikeys) would also compromise the
        service hosting the state. The service could enforce a rule that the
        state only ever moves forward, and thus any forking of the chain at an
        earlier point would be rejected. It could also check timestamps in
        signed payloads, to ensure history is not being rewritten at a later
        date. The user could be warned if an attempt is made.
      - In practice, it is unlikely that every single endpoint will be naive.
        Some endpoints will be able to persist state (including the full
        history of the chain) and thus also enforce that a chain cannot be
        forked/rewritten, independent of the service. They could also warn the
        user of this occurrence.
      - Other users' nodes could also enforce the chain history, provided they
        are not naive (i.e. they have some way to persist state). This creates a
        distributed, decentralised network of nodes that could detect compromise
        of the service, making it obvious to the general public.
      - Thus, full chain compromise of a user would only be possible if:
        - an attacker simultaneously compromises all but one of a user's latest
          private root keys, or;
        - an attacker compromises the service, causing it to not validate
          chains; the same attacker also has access to the private keys of all
          but one of the root keys which have appeared in a single element of a
          user's chain at some point; all of that user's endpoints are naive
          and thus cannot warn the user of a tampered chain; and all of the
          other users which trust that user's genesis key are also naive and
          thus cannot detect the tampered chain.

With that definition of a genesis key, and the criteria above:
- Someone else who wishes to verify a message signed by a trusted peer just
  needs to maintain a copy of that peer's genesis public key. They can then be
  presented a message signed by one of the latest root keys, as well as the
  root key chain. They then:
  - Verify that the chain is rooted at the genesis key they trust.
  - Follow the signatures to verify the rules that govern the chain (i.e. each
    element of the chain needs to be signed by all root keys in the prior
    element of the chain, and a root key can be removed without its own
    signature provided all other root keys sign this removal).
  - Note that they can cache this step of verification.
  - Verify that the message provided was signed by one of the root keys in
    the final element of the chain.

### Root key state service
Consider the act of the user logging into the service which manages their root
key set:
- Say they open a fresh browser, which makes this a naive endpoint.
- They visit the service's login page, which sends a random nonce to the user.
- They use an existing root key (say a Yubikey) to sign this nonce, and then
  send this signature on every subsequent request to the service.
- The service keeps track of the expiry of that nonce, and until then, accepts
  every request from the user using that signed nonce.
- Of course, any modification to the root key set will require the signatures of
  all root keys (i.e. the signed nonce will not suffice).

### Local node keys
This library is designed to be general-purpose - anything the user wishes to
sign/verify should be supported. However, it also tries to be pragmatic and add
helpers for the expected common usecase of signing other keys with the root
keys.

To illustrate this, consider:
- One user wishes to chat with another user. They do not want to sign every
  single message with a root key, as this would involve friction of interacting
  with the key every single time.
- Instead, they generate a public/private keypair and sign all outgoing messages
  with the private key.
- They sign the public key with one of their root keys, and send this to their
  peer.
- The peer can then trust every message signed by that user, by first verifying
  the shared temporary key against the root key set, and thereafter verifying
  every message against the temporary key (and making sure it hasn't expired).

Further, consider how devices that are not WebAuthn-enabled fit into this. For
example, a network of trusted embedded devices:
- All nodes in the network can trust their admin just by being initialised with
  the genesis public key. They can then verify any messages coming from the
  admin the same way as anyone can verify it (by following the above process to
  follow the chain).
- These devices have a node keypair, which is just a public/private keypair they
  generate in the usual way (perhaps storing on disk). They use this to sign
  their own outgoing messages, as well as verify any messages coming from
  another node.
- This node can be trusted by any other node because its public node key will
  be signed by a root key message.
