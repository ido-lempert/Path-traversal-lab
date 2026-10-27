# Path traversal: a local lab

Learning notes on one classic bug, path traversal, using a tiny file server that runs only on your own machine (127.0.0.1).

- `vulnerable_app.py` joins the requested name onto a folder without checking where the result lands. A request containing `..` can read a file outside the public folder.
- The same file has the fix (`FIXED=1`): resolve the real path, then check that it is still inside the public folder.
- `demo.py` starts both versions and prints what each returns.

```sh
python3 demo.py
```

## What the demo shows
See `output.txt` for a real run.

## Notes
- The check must happen on the resolved path. Looking for `..` in the string is easy to get wrong (encodings, symlinks).
- A 403 for a path outside the folder and a 404 for a missing file is a reasonable split, but some apps return 404 for both so that they do not reveal what exists.

## Scope
This is for learning on a machine you own. Do not point any of it at systems you do not own or have written permission to test.
