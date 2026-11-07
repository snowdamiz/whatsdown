Parent expanded the allocation after R2 started: insert only
`MeshMessengerNativeRetirement.swift` immediately before
`MeshMessengerDataProtection.swift` in the existing
`tests/native-effect-authority-unit0/prove.py` common source list, retaining the
first two entries and DataProtection as last. No other edit to that runner.

Source SHA-256:
`f6cca1cdb463fdfdf5abc20ed4f790bab7a67b041717bd499fa18accabac7bc0`.

Production pins remain DataProtection
`cd5410f2f3c58bb6338c8048a068bb2bb06de515696b121ea54e95a54918ed9a`
and NativeRetirement
`79004e1e8938d3bc922164f64da65ac7bd0af3dd36135423567b3f134833c237`.

Replay command:

```sh
python3 -B mesh-private-messenger/tests/native-effect-authority-unit0/prove.py --output mesh-private-messenger/tests/native-authority-closure/unit-n1b/artifacts/unit0-replay
```

The copied `receipts/unit0/receipt.json` is the final result when present; an
in-progress build or this note is not a pass. UIKit/Expo remains unqualified.
