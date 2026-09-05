"""Reproduce a checksum-bound PR45 candidate from isolated transport data only."""
import base64
import hashlib
import lzma
import os
from pathlib import Path
import subprocess
import sys

BASE = "bb160fb68ae5e7f0e7af26a3809323f3c9f6335e"
PARENT = "e9799b2f49f7f2326f9bcbd6c55cc3bfb20a6b97"
HEAD = "3f381d431442fb2e6d407fae89084ff62d149b33"
TREE = "04bf37044b7ae7e1f8ade261a786db9d900ac6dd"
INTERMEDIATE_TREE = "aec52a44c425b6baac3c309fcd34cff900964a60"
MESSAGE = "fix: reconcile runtime provenance and lexical review regressions"


def git(*arguments, data=None):
    return subprocess.check_output(["git", *arguments], input=data).decode().strip()


def patch(transport, stem, expected_digest, *, repair_transcription=False):
    parts = [(transport / f"{stem}.{number:03}").read_bytes() for number in (1, 2, 3)]
    if repair_transcription:
        value = parts[2]
        blob = hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()
        if blob != "3fd35cc5cbd9570f0c64e5b3b638a4d10d16859f":
            raise RuntimeError("unexpected transport part before explicit transcription repair")
        bad = b"PSfNbCph " + bytes([110]) + b"dziima"
        good = b"PSfNbCph" + bytes([78]) + b"dziima"
        if value.count(bad) != 1:
            raise RuntimeError("known transport transcription marker is not unique")
        parts[2] = value.replace(bad, good)
        repaired = parts[2]
        blob = hashlib.sha1(b"blob " + str(len(repaired)).encode() + b"\0" + repaired).hexdigest()
        if blob != "663e65a551964ea4b28de66e2ad9d9b6439a5a69":
            raise RuntimeError("repaired transport part differs from the local source")
    encoded = b"".join(parts)
    decoded = base64.b64decode(b"".join(encoded.splitlines()), validate=True)
    result = lzma.decompress(decoded)
    if hashlib.sha256(result).hexdigest() != expected_digest:
        raise RuntimeError("decompressed patch checksum mismatch")
    return result


def main():
    transport = Path(sys.argv[1]).resolve()
    if git("status", "--porcelain"):
        raise RuntimeError("candidate checkout is not clean before reconstruction")
    original = patch(transport, "pr45-integrated.patch.xz.b64",
                     "4d480359ba930dfeb8a8d37451171b2dc7fd89fcc94355229fa89aee051312df")
    followups = patch(transport, "pr45-integrated-followups.patch.xz.b64",
                      "022225e5e23dfa7fc6d2bf83c19abab237ebe9c2d27652b610fc98f6dab6231e",
                      repair_transcription=True)
    git("reset", "--hard", BASE)
    git("apply", "--index", "-", data=original)
    if git("write-tree") != INTERMEDIATE_TREE:
        raise RuntimeError("intermediate tree mismatch")
    git("apply", "--index", "-", data=followups)
    if git("write-tree") != TREE:
        raise RuntimeError("final tree mismatch")
    git("reset", "--soft", PARENT)
    for role in ("AUTHOR", "COMMITTER"):
        os.environ[f"GIT_{role}_NAME"] = "OpenAI PR repair"
        os.environ[f"GIT_{role}_EMAIL"] = "pr45-repair@users.noreply.github.com"
        os.environ[f"GIT_{role}_DATE"] = "2026-09-05T05:35:00Z"
    git("-c", "commit.gpgsign=false", "commit", "--no-gpg-sign", "-m", MESSAGE)
    if git("rev-parse", "HEAD") != HEAD or git("rev-parse", "HEAD^{tree}") != TREE:
        raise RuntimeError("final commit identity mismatch")
    if git("status", "--porcelain"):
        raise RuntimeError("candidate checkout changed during reconstruction")
    print(git("show", "-s", "--format=fuller", "HEAD"))
    print("tree", TREE)
    print("parent", PARENT)


if __name__ == "__main__":
    main()
