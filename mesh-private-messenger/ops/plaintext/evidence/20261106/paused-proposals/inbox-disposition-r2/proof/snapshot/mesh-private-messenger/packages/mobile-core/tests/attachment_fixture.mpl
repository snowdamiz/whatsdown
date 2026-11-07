from Mobile.CreditAttachmentNative import native_attachment_fetch_chunk
from MobileCore import credit_attachments_export, attachment_download_plan_export

##! Test-only observers for attachment metadata from synthetic public fixtures.
##! Production getters retain private output and private failure outcomes.

pub fn fixture_credit_attachments(request :: Bytes) -> Bytes!String do
  declassify(credit_attachments_export(request),
    "synthetic public paid-attachment inventory test fixture and outcome only; no application disclosure")
end

pub fn fixture_attachment_download_plan(request :: Bytes) -> Bytes!String do
  declassify(attachment_download_plan_export(request),
    "synthetic public attachment download-plan test fixture and outcome only; no application disclosure")
end

pub fn fixture_attachment_fetch_chunk(request :: Bytes) -> Bytes!String do
  declassify(native_attachment_fetch_chunk(request),
    "synthetic public attachment chunk test fixture and outcome only; no application disclosure")
end
