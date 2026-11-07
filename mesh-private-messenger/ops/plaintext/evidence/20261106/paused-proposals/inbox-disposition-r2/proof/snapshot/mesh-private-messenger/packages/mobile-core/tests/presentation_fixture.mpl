from MobileCore import presentation_load_export, presentation_save_export

##! Test-only observers for names, avatars, nicknames and community records
##! constructed from synthetic public fixtures. Production results stay labeled.

pub fn fixture_load_presentation(request :: Bytes) -> Bytes!String do
  declassify(presentation_load_export(request),
    "synthetic public presentation-load test fixture and outcome only; no application disclosure")
end

pub fn fixture_save_presentation(request :: Bytes) -> Bytes!String do
  declassify(presentation_save_export(request),
    "synthetic public presentation-save test fixture and outcome only; no application disclosure")
end
