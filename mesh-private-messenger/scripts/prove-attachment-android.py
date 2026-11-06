#!/usr/bin/env python3
"""Run the shared owned-object transfer proof through production Android JNI."""
from pathlib import Path
import runpy

if __name__ == '__main__':
    runpy.run_path(str(Path(__file__).with_name('prove-attachment-ios.py')))['main']('android')
