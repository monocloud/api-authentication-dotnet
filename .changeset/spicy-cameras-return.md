---
'@monocloud/authentication-api': patch
---

- Added `DeleteAsync` to `IIntrospectionCache`, restoring the delete capability the interface family had
  before it was removed from the Node backend SDK; existing implementations must add the new member.
- The SDK never calls it itself — it lets consumers evict a cached introspection entry before it expires
  (for example when a token is revoked), using a key produced by
  `MonoCloudAuthenticationOptions.CacheKeyGenerator`.
