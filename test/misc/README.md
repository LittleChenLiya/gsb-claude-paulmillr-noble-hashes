# misc

Miscelanous items that could be useful when developing / testing.

`unrolled-` files contain hash implementations with unrolled loops, which contribute to speed-up, but are hard to audit.

`pool-demo.js` is a dependency-free local command (`node test/misc/pool-demo.js`, Node >= 22.6)
that walks the `HashPool` lifecycle: capacity-1 rental, empty instance after return, cancellable
waiting, and shutdown with an in-flight return. The deterministic test suite lives in
`test/hash-pool.test.ts` (`npm run test:pool`).