"""Extract an untrusted EAS/GitHub evidence tar without links or traversal."""
import argparse
from pathlib import Path, PurePosixPath
import shutil
import tarfile


def extract_archive(archive, destination, maximum_bytes=2_147_483_648, maximum_entries=4096):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('extraction destination must be fresh')
    with tarfile.open(archive, 'r:*') as stream:
        members, seen, total = [], set(), 0
        for count, member in enumerate(stream, start=1):
            if count > maximum_entries:
                raise ValueError('archive exceeds bounded evidence limits')
            path = PurePosixPath(member.name)
            if (path.is_absolute() or '..' in path.parts or '\\' in member.name or ':' in member.name
                    or any(ord(c) < 32 or ord(c) == 127 for c in member.name)
                    or not (member.isfile() or member.isdir())):
                raise ValueError('unsafe archive member')
            normalized = path.as_posix()
            if normalized == '.' and member.isdir():
                continue
            if normalized in seen or not path.parts:
                raise ValueError('duplicate archive member')
            seen.add(normalized)
            total += member.size
            if member.size < 0 or total > maximum_bytes:
                raise ValueError('archive exceeds bounded evidence limits')
            members.append((member, path))
        files = {path for member, path in members if member.isfile()}
        if any(parent in files for _, path in members for parent in path.parents):
            raise ValueError('archive file used as directory')
        destination.mkdir(mode=0o700)
        try:
            for member, relative in members:
                target = destination.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                if target.stat().st_size != member.size:
                    raise ValueError('truncated archive member')
                target.chmod(0o644)
        except BaseException:
            shutil.rmtree(destination)
            raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    extract_archive(args.archive, args.destination)
