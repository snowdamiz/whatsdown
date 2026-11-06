from Storage.Treasury import TreasuryMovement

pub struct TreasuryPaymentBatch do
  batch_id :: Bytes
  config_hash :: Bytes
  member_hash :: Bytes
  members :: List<TreasuryMovement>
  state :: Int
  nonce_address :: Bytes
  nonce_value :: Bytes
  message :: Bytes
  packet :: Bytes
  transaction_signature :: Bytes
  fee :: U64
  rent :: U64
end
