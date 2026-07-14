# Bleeplab × Sockerless runner harness

This is a consumer integration test, not a second implementation of either
project. It builds Bleeplab from this repository and consumes a Sockerless
checkout through the named BuildKit context `sockerless`.

Run `SOCKERLESS_ROOT=/path/to/sockerless make runner-sockerless-test` from a
checkout of this repository.

The harness runs the official `gitlab-runner` docker executor against
Bleeplab, the Sockerless AWS simulator, and the Sockerless Amazon Elastic
Container Service backend. No simulator-specific product behavior is
introduced: the only differing coordinates are the local endpoint and
credentials.
