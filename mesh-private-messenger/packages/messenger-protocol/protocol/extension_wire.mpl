##! Suite and extension-vector codecs.

from Binary.Reader import BinaryReader
from Protocol.WirePrimitives import (
  ProtocolReadExtensions,
  ProtocolReadSuites,
  protocol_append,
  protocol_byte,
  protocol_join,
  protocol_take_u16,
  protocol_take_u8,
  protocol_take_vector,
  protocol_vector,
  protocol_write_u16
)
from Protocol.V1 import ProtocolError, ProtocolExtension, protocol_validate_suite_list

fn encode_suite_entries(values :: List < Int >, index :: Int, output :: Bytes) -> Bytes ! ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_suite_entries(values,
    index + 1,
    protocol_append(output, protocol_write_u16(List.get(values, index)) ?) ?)
  end
end

pub fn protocol_encode_suites(values :: List < Int >) -> Bytes ! ProtocolError do
  protocol_validate_suite_list(values, 0) ?
  protocol_join([protocol_byte(List.length(values)) ?, encode_suite_entries(values,
  0,
  Bytes.empty()) ?],
  0,
  Bytes.empty())
end

fn read_suite_entries(state :: BinaryReader, count :: Int, index :: Int, output :: List < Int >) -> ProtocolReadSuites ! ProtocolError do
  if index >= count do
    protocol_validate_suite_list(output, 0) ?
    Ok(ProtocolReadSuites {
      state : state,
      value : output
    })
  else
    let suite = protocol_take_u16(state) ?
    read_suite_entries(suite.state, count, index + 1, List.append(output, suite.value))
  end
end

pub fn protocol_take_suites(state :: BinaryReader) -> ProtocolReadSuites ! ProtocolError do
  let count = protocol_take_u8(state) ?
  if count.value == 0 || count.value > 8 do
    Err(InvalidSuiteList)
  else
    read_suite_entries(count.state, count.value, 0, List.new())
  end
end

pub fn protocol_validate_extensions(values :: List < ProtocolExtension >,
index :: Int,
previous_id :: Int) -> Result <(), ProtocolError > do
  if List.length(values) > 16 do
    Err(TooManyExtensions)
  else
    if index >= List.length(values) do
      Ok(nil)
    else
      let extension = List.get(values, index)
      if extension.id <= previous_id || extension.id > 65535 do
        Err(NonCanonicalEncoding)
      else
        if extension.mandatory do
          Err(UnknownMandatoryExtension)
        else
          if Bytes.length(extension.value) > 1024 do
            Err(InvalidExtension)
          else
            protocol_validate_extensions(values, index + 1, extension.id)
          end
        end
      end
    end
  end
end

fn encode_extension_entries(values :: List < ProtocolExtension >, index :: Int, output :: Bytes) -> Bytes ! ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    let extension = List.get(values, index)
    let encoded = protocol_join([protocol_write_u16(extension.id) ?, protocol_byte(0) ?, protocol_vector(extension.value) ?],
    0,
    Bytes.empty()) ?
    encode_extension_entries(values, index + 1, protocol_append(output, encoded) ?)
  end
end

pub fn protocol_encode_extensions(values :: List < ProtocolExtension >) -> Bytes ! ProtocolError do
  protocol_validate_extensions(values, 0, 0) ?
  protocol_join([protocol_write_u16(List.length(values)) ?, encode_extension_entries(values,
  0,
  Bytes.empty()) ?],
  0,
  Bytes.empty())
end

fn read_extension_entries(state :: BinaryReader,
count :: Int,
index :: Int,
previous_id :: Int,
output :: List < ProtocolExtension >) -> ProtocolReadExtensions ! ProtocolError do
  if index >= count do
    Ok(ProtocolReadExtensions {
      state : state,
      value : output
    })
  else
    let id = protocol_take_u16(state) ?
    let flag = protocol_take_u8(id.state) ?
    if id.value <= previous_id do
      Err(NonCanonicalEncoding)
    else
      if flag.value == 1 do
        Err(UnknownMandatoryExtension)
      else
        if flag.value != 0 do
          Err(InvalidExtension)
        else
          let value = protocol_take_vector(flag.state, 1024) ?
          read_extension_entries(value.state,
          count,
          index + 1,
          id.value,
          List.append(output,
          ProtocolExtension {
            id : id.value,
            mandatory : false,
            value : value.value
          }))
        end
      end
    end
  end
end

pub fn protocol_take_extensions(state :: BinaryReader) -> ProtocolReadExtensions ! ProtocolError do
  let count = protocol_take_u16(state) ?
  if count.value > 16 do
    Err(TooManyExtensions)
  else
    read_extension_entries(count.state, count.value, 0, 0, List.new())
  end
end
