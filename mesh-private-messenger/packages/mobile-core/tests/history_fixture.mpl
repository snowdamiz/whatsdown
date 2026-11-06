from MobileCore import group_history_export, load_history_export

##! Test-only observers for histories constructed from synthetic public fixtures.
##! Keep production history exports labeled; comparisons and subsequent test
##! operations may observe these known fixture bytes and their failure outcomes.

pub fn fixture_direct_history(request :: Bytes) -> Bytes!String do
  declassify(load_history_export(request),
    "synthetic public direct-history test fixture and outcome only; no application disclosure")
end

pub fn fixture_group_history(request :: Bytes) -> Bytes!String do
  declassify(group_history_export(request),
    "synthetic public group-history test fixture and outcome only; no application disclosure")
end
