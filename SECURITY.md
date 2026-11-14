# Security policy

There is no qualified stable version yet. Report vulnerabilities privately through the repository's GitHub security advisory interface; do not publish credentials, private keys or production configurations in issues.

The controller and agents run under separate unprivileged identities. A host grants a limited set of typed operations to its agent. A restricted root helper independently validates operations and package protection. Management endpoints must use HTTPS outside literal loopback development environments.

Public forward proxies require authentication, explicit client networks, destination policies and encrypted transport. TLS tunnelling does not intercept or decrypt destination HTTPS sessions. Plaintext SOCKS5 and UDP association must not be exposed publicly.

Package deletion is not equivalent to configuration rollback. Package-maintainer scripts are distribution code and can affect services; disposable installation/removal qualification and transaction records are mandatory before claiming native support.
