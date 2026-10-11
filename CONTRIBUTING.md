# Contributing

Run the offline suite before submitting changes:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m unittest discover -s tests
```

Keep the runtime dependency-free. Tests must not contact a vehicle or start an external diagnostic application. Use synthetic VINs, network observations, coding groups and transport failures; never commit real captures, backups, local configurations or reference archives.

A new parameter requires an exact software profile, group geometry, offset/mask/encoding, supported values and independent evidence for its meaning. A new module also requires its complete authentication, signing, metadata, finalize/activation, readback and recovery contract. A display label or a successful read alone is insufficient evidence for writing.

Preserve fresh identity/software/original-signature checks, explicit terminal approval, durable mutation intent, bounded traffic, honest uncertainty reporting and one-use signing handles. Do not add automatic retries, implicit writes or a general arbitrary-request sender.

Document externally sourced material separately from the project's source license. Changes to bundled signing material must update its configuration hashes and pass offline signature verification. Do not include license credentials or unrelated signing roles.
