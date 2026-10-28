# Isolated validation package (synthetic demo data)

This report was produced by running `node bin/csi.js audit --live` inside an
isolated Linux namespace (user+mount+pid+net) with a minimal rootfs built for
testing. Every "secret" in it (the DB password, AWS keys, proxy credentials,
SSH key) is INVENTED test data planted in that rootfs - none of it comes from
any real environment.

**Read PROVENANCE.md first**: it maps each finding to what the tool actually
measured vs. what was deliberately planted for the demo.

The report demonstrates the redaction boundary: all 7 planted secret strings
appear 0 times in the output; redacted fields show
`[REDACTED - value not collected]`.

- report.json / report.html: the audit output from that isolated run
  (report.html carries a demo banner added for this package; otherwise it is
  the generator's unmodified output).
- The isolated environment itself: env vars, /app/.env, /root/.aws/credentials,
  /root/.aws/config, /root/.ssh/id_rsa, and a world-writable docker.sock
  placeholder, all created for the test.
