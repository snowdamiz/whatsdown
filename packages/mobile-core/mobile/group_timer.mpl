from Mobile.Codec import (
  mobile_byte,
  mobile_finish,
  mobile_join,
  mobile_read_byte,
  mobile_read_u32,
  mobile_read_u64,
  mobile_reader,
  mobile_vector,
  mobile_wide,
  mobile_write_u32,
  mobile_write_u64,
  take_fixed,
  take_vector
)
from Mobile.GroupState import group_timer_label
from Mobile.Presentation import load_presentation_record, presentation_fields, presented_body
from Mobile.Types import MobileReadBytes
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local

##! Disappearing and view-once messages in groups (`protocol/mls-groups-v1.md`,
##! "Disappearing and view-once messages").
##!
##! A group message of version 5 carries its plaintext inside a `GOP` frame:
##! `u8 1 || "GOP" || u8 flags || u32 timer_seconds || u64 timer_stamp ||
##! u64 sent_at || vector32(content)`. Flag 1 marks a view-once message, flag 2
##! a change of the group's timer (its content is empty). Every such message
##! carries the sender's timer, so a member added later learns it from the next
##! one; the timer with the later stamp wins, then the longer one, so every
##! member settles on the same timer whatever order the messages arrive in.

pub struct GroupOptions do
  flags :: Int
  timer_seconds :: Int
  timer_stamp :: U64
  sent_at :: U64
  content :: Bytes
end

pub struct GroupTimer do
  seconds :: Int
  stamp :: U64
end

pub fn group_view_once_flag() -> Int do
  1
end

pub fn group_timer_change_flag() -> Int do
  2
end

## The longest timer, 30 days, as for direct chats; the app offers 1 minute, 1
## hour and 1 day.

pub fn group_timer_valid(seconds :: Int) -> Bool do
  seconds >= 0 && seconds <= 2592000
end

fn options_header() -> Bytes!String do
  mobile_join([mobile_byte(1)?, Bytes.from_utf8("GOP")], 0, Bytes.empty())
end

pub fn group_options_encode(value :: GroupOptions) -> Bytes!String do
  if value.flags < 0 || value.flags > 3 || !group_timer_valid(value.timer_seconds) do
    return Err("invalid_group_options")
  end
  mobile_join([
      options_header()?,
      mobile_byte(value.flags)?,
      mobile_write_u32(value.timer_seconds)?,
      mobile_write_u64(value.timer_stamp)?,
      mobile_write_u64(value.sent_at)?,
      mobile_vector(value.content)?
    ],
    0,
    Bytes.empty())
end

pub fn group_options_decode(input :: Bytes) -> GroupOptions!String do
  let state = mobile_reader(input, 65346, "invalid_group_options")?
  let header = take_fixed(state, 4)?
  let flags = take_fixed(header.state, 1)?
  let seconds = take_fixed(flags.state, 4)?
  let stamp = take_fixed(seconds.state, 8)?
  let sent_at = take_fixed(stamp.state, 8)?
  let content = take_vector(sent_at.state, 65317)?
  mobile_finish(content.state, "invalid_group_options")?
  let value = GroupOptions {
    flags: mobile_read_byte(flags.value)?,
    timer_seconds: mobile_read_u32(seconds.value)?,
    timer_stamp: mobile_read_u64(stamp.value)?,
    sent_at: mobile_read_u64(sent_at.value)?,
    content: content.value
  }
  let change = value.flags == group_timer_change_flag()
  if !Bytes.secure_equals(header.value, options_header()?)
    || value.flags < 0
    || value.flags > 2
    || !group_timer_valid(value.timer_seconds)
    || (change && Bytes.length(value.content) > 0) do
    Err("invalid_group_options")
  else
    Ok(value)
  end
end

pub fn group_timer_off() -> GroupTimer!String do
  Ok(GroupTimer { seconds: 0, stamp: mobile_wide("0")? })
end

pub fn group_timer_load(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> GroupTimer!String do
  let label = group_timer_label(group_id)
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      group_timer_off()
    else
      Err(error)
    end
    Ok(blob) -> do
      let value = open_local(blob, wrapping_key, local_context(label)?)?
      let state = mobile_reader(value, 12, "invalid_group_timer")?
      let seconds = take_fixed(state, 4)?
      let stamp = take_fixed(seconds.state, 8)?
      mobile_finish(stamp.state, "invalid_group_timer")?
      Ok(GroupTimer {
        seconds: mobile_read_u32(seconds.value)?,
        stamp: mobile_read_u64(stamp.value)?
      })
    end
  end
end

pub fn group_timer_sealed(value :: GroupTimer,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> Result<(String, Bytes), String> do
  let label = group_timer_label(group_id)
  let encoded = mobile_join([mobile_write_u32(value.seconds)?, mobile_write_u64(value.stamp)?],
    0,
    Bytes.empty())?
  Ok((label, seal_local(encoded, wrapping_key, local_context(label)?)?))
end

pub fn group_timer_newer(candidate :: GroupTimer, current :: GroupTimer) -> Bool do
  let order = U64.compare(candidate.stamp, current.stamp)
  order > 0 || (order == 0 && candidate.seconds > current.seconds)
end

## Any member sets a plain group's timer; in a community only its owner and
## admins do, as only they post there.

pub fn group_timer_allowed(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  sender_account_id :: Bytes) -> Bool!String do
  let stored = load_presentation_record(database_path,
    wrapping_key,
    Bytes.from_utf8("group/" <> Bytes.to_hex(group_id)))?
  if Bytes.length(stored) == 0 do
    return Ok(true)
  end
  let fields = presentation_fields(stored)?
  Ok(Bytes.length(fields.community) == 0
    || Bytes.secure_equals(fields.owner, sender_account_id)
    || List.any(fields.admins, fn(admin) do Bytes.secure_equals(admin, sender_account_id) end))
end

## When a message sent at `sent_at` under a timer of `seconds` goes; 0 when it stays.

pub fn group_expiry(sent_at :: U64, seconds :: Int) -> U64!String do
  if seconds == 0 do
    mobile_wide("0")
  else
    U64.add(sent_at, mobile_wide(Int.to_string(seconds * 1000))?)
  end
end

## What a send puts on the wire and in this device's records: the plaintext
## (a `GOP` frame when `framed`, sent as group message version 5), the timer
## record to write, and the history entry's expiry, kind and, for a timer
## change, its notice (empty when the change changed nothing).

pub struct GroupSendPlan do
  framed :: Bool
  plaintext :: Bytes
  labels :: List<String>
  blobs :: List<Bytes>
  expires_at :: U64
  kind :: Int
  notice :: Bytes
end

fn timer_notice(seconds :: Int) -> Bytes do
  Bytes.from_utf8(Int.to_string(seconds))
end

fn stamp_after(now :: U64, current :: GroupTimer) -> U64!String do
  let next = U64.add(current.stamp, mobile_wide("1")?)?
  if U64.compare(now, next) > 0 do
    Ok(now)
  else
    Ok(next)
  end
end

# Setting the timer a group already has sends it again under its own stamp: a
# member added since learns it, and nobody else sees a change.

fn change_plan(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  sender_account_id :: Bytes,
  seconds :: Int,
  now :: U64) -> GroupSendPlan!String do
  if !group_timer_valid(seconds) do
    return Err("invalid_group_timer")
  end
  if !group_timer_allowed(database_path, wrapping_key, group_id, sender_account_id)? do
    return Err("group_timer_not_allowed")
  end
  let current = group_timer_load(database_path, wrapping_key, group_id)?
  let unchanged = seconds == current.seconds && U64.to_string(current.stamp) != "0"
  let next = if unchanged do
    current
  else
    GroupTimer { seconds: seconds, stamp: stamp_after(now, current)? }
  end
  let (label, blob) = group_timer_sealed(next, wrapping_key, group_id)?
  Ok(GroupSendPlan {
    framed: true,
    plaintext: group_options_encode(GroupOptions {
      flags: group_timer_change_flag(),
      timer_seconds: next.seconds,
      timer_stamp: next.stamp,
      sent_at: now,
      content: Bytes.empty()
    })?,
    labels: [label],
    blobs: [blob],
    expires_at: mobile_wide("0")?,
    kind: 2,
    notice: if unchanged do
      Bytes.empty()
    else
      timer_notice(seconds)
    end
  })
end

## `flags` holds the view-once flag for a message; `change` is the timer a
## timer change sets, or -1 for a message. A message goes out framed when it
## is view-once, the group's timer is on, or it is signed deniably (version 6
## always carries the frame); otherwise as version 4, which builds from before
## timers read.

pub fn group_send_plan(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  sender_account_id :: Bytes,
  flags :: Int,
  change :: Int,
  content :: Bytes,
  now :: U64,
  deniable :: Bool) -> GroupSendPlan!String do
  if change >= 0 do
    return change_plan(database_path, wrapping_key, group_id, sender_account_id, change, now)
  end
  let timer = group_timer_load(database_path, wrapping_key, group_id)?
  let framed = deniable || flags != 0 || timer.seconds > 0
  Ok(GroupSendPlan {
    framed: framed,
    plaintext: if framed do
      group_options_encode(GroupOptions {
        flags: flags,
        timer_seconds: timer.seconds,
        timer_stamp: timer.stamp,
        sent_at: now,
        content: content
      })?
    else
      content
    end,
    labels: [],
    blobs: [],
    expires_at: group_expiry(now, timer.seconds)?,
    kind: if flags == group_view_once_flag() do
      1
    else
      0
    end,
    notice: Bytes.empty()
  })
end

## What a received message leaves: its history body, expiry and kind, the
## timer record to write, and what the receive call returns.

pub struct GroupReceivedPlan do
  body :: Bytes
  expires_at :: U64
  kind :: Int
  labels :: List<String>
  blobs :: List<Bytes>
  shown :: Bytes
end

fn received_timer_writes(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  sender_account_id :: Bytes,
  options :: GroupOptions) -> Result<(List<String>, List<Bytes>), String> do
  let candidate = GroupTimer { seconds: options.timer_seconds, stamp: options.timer_stamp }
  let current = group_timer_load(database_path, wrapping_key, group_id)?
  if group_timer_newer(candidate, current)
    && group_timer_allowed(database_path, wrapping_key, group_id, sender_account_id)? do
    let (label, blob) = group_timer_sealed(candidate, wrapping_key, group_id)?
    Ok(([label], [blob]))
  else
    Ok(([], []))
  end
end

## A version 5 or 6 message must hold a `GOP` frame. Its timer is taken if its
## sender may set one and it is newer than this device's; a timer change that
## changed nothing leaves no notice. A message expires `timer_seconds` after it
## was sent, by the sender's clock but never later than by this device's.

pub fn group_received_plan(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  sender_account_id :: Bytes,
  version :: Int,
  plaintext :: Bytes,
  now :: U64) -> GroupReceivedPlan!String do
  if version != 5 && version != 6 do
    return Ok(GroupReceivedPlan {
      body: plaintext,
      expires_at: mobile_wide("0")?,
      kind: 0,
      labels: [],
      blobs: [],
      shown: presented_body(plaintext)
    })
  end
  let options = case group_options_decode(plaintext) do
    Err(_) -> Err("group_message_rejected")
    Ok(value)
  end?
  let (labels, blobs) = received_timer_writes(database_path,
    wrapping_key,
    group_id,
    sender_account_id,
    options)?
  let sent_at = if U64.compare(options.sent_at, now) < 0 do
    options.sent_at
  else
    now
  end
  if options.flags == group_timer_change_flag() do
    Ok(GroupReceivedPlan {
      body: if List.length(labels) > 0 do
        timer_notice(options.timer_seconds)
      else
        Bytes.empty()
      end,
      expires_at: mobile_wide("0")?,
      kind: if List.length(labels) > 0 do
        2
      else
        0
      end,
      labels: labels,
      blobs: blobs,
      shown: Bytes.empty()
    })
  else
    let view_once = options.flags == group_view_once_flag()
    Ok(GroupReceivedPlan {
      body: options.content,
      expires_at: group_expiry(sent_at, options.timer_seconds)?,
      kind: if view_once do
        1
      else
        0
      end,
      labels: labels,
      blobs: blobs,
      shown: if view_once do
        Bytes.empty()
      else
        presented_body(options.content)
      end
    })
  end
end
