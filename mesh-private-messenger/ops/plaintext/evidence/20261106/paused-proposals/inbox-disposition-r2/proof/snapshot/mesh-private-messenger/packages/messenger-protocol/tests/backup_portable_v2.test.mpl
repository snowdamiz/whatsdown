from Tests.BackupPortableV2Fixture import (
  portable_v2_fixture_literals,
  portable_v2_fixture_binding,
  portable_v2_fixture_dispatch,
  portable_v2_fixture_bounds,
  portable_v2_fixture_oneuse,
  portable_v2_fixture_private
)

test("portable v2 opens independent canonical archive literals") do
  assert(portable_v2_fixture_literals())
end

test("portable v2 binds complete encrypted manifest and payload identity") do
  assert(portable_v2_fixture_binding())
end

test("portable v2 dispatch preserves exact v1 and rejects downgrade mixtures") do
  assert(portable_v2_fixture_dispatch())
end

test("portable v2 enforces canonical archive extent boundaries and maximum") do
  assert(portable_v2_fixture_bounds())
end

test("portable v2 creates fresh one-use exports and permits pristine restore retry") do
  assert(portable_v2_fixture_oneuse())
end

test("portable v2 preserves protected archive content across complete operations") do
  assert(portable_v2_fixture_private())
end
