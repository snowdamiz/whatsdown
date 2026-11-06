"""Regenerate dependency-free reference vectors using Python's exact integers/calendar."""

import calendar
import csv
import datetime as dt
from pathlib import Path
import random

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURES.mkdir(exist_ok=True)
RNG = random.Random(0x4D4F525345)
MAX = (1 << 128) - 1


def multiply_divide(a, b, divisor):
    if divisor == 0:
        return "division_by_zero"
    quotient = a * b // divisor
    return "overflow" if quotient > MAX else quotient


with (FIXTURES / "multiply_divide.csv").open("w") as output:
    rows = csv.writer(output, lineterminator="\n")
    rows.writerow(["a", "b", "divisor", "result"])
    boundaries = [0, 1, 2, (1 << 64) - 1, 1 << 64, (1 << 127) - 1, 1 << 127, MAX]
    for a in boundaries:
        for b in boundaries:
            for divisor in [0, 1, (1 << 64) - 1, 1 << 127, MAX]:
                rows.writerow([a, b, divisor, multiply_divide(a, b, divisor)])
    for _ in range(256):
        a, b, divisor = [RNG.getrandbits(128) for _ in range(3)]
        rows.writerow([a, b, divisor, multiply_divide(a, b, divisor)])


def anniversary(origin, offset):
    month_index = origin.year * 12 + origin.month - 1 + offset
    year, month_index = divmod(month_index, 12)
    month = month_index + 1
    return origin.replace(year=year, month=month, day=min(origin.day, calendar.monthrange(year, month)[1]))


def timestamp(value):
    return calendar.timegm(value.utctimetuple())


def floor(origin, interval_start, interval_end):
    result = 0
    for offset in range(12):
        start = timestamp(anniversary(origin, offset))
        end = timestamp(anniversary(origin, offset + 1))
        a, b = max(start, interval_start), min(end, interval_end)
        if b > a:
            result += 300_000_000 * (b - start) // (end - start) - 300_000_000 * (a - start) // (end - start)
    return result


with (FIXTURES / "calendar_floor.csv").open("w") as output:
    rows = csv.writer(output, lineterminator="\n")
    rows.writerow(["case", "network_started", "interval_start", "interval_end", "result"])
    for text in [
        "1970-01-01T00:00:00",
        "2000-02-29T23:59:59",
        "2024-01-31T12:34:56",
        "2024-02-29T01:01:36",
        "2026-08-31T23:59:59",
        "2099-01-31T12:34:56",
        "2100-03-01T01:01:36",
        "2399-01-31T12:34:56",
        "9998-12-31T23:59:59",
    ]:
        origin = dt.datetime.fromisoformat(text).replace(tzinfo=dt.timezone.utc)
        launch = timestamp(origin)
        for offset in range(12):
            start, end = [timestamp(anniversary(origin, month)) for month in [offset, offset + 1]]
            rows.writerow([f"{text}/month{offset}", launch, start, end, 300_000_000])
        for week in range(53):
            start = launch + week * 604_800
            end = start + 604_800
            rows.writerow([f"{text}/week{week}", launch, start, end, floor(origin, start, end)])
        for index in range(12):
            start = max(0, launch + RNG.randrange(-604_800, 32_000_000))
            end = start + RNG.randrange(0, 40_000_000)
            rows.writerow([f"{text}/range{index}", launch, start, end, floor(origin, start, end)])
