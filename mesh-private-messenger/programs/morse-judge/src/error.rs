use pinocchio::error::ProgramError;

/// Custom error codes (`ProgramError::Custom(code)`), listed in
/// `protocol/morse-judge-v1.md`. Codes start at 6000 so they never collide
/// with SPL Token errors surfacing from a failed CPI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum JudgeError {
    WrongAccount = 6000,
    Unauthorized = 6001,
    InvalidData = 6002,
    TimelockActive = 6003,
    NoPendingChange = 6004,
    InvalidParameter = 6005,
    RingNotReady = 6006,
    RingAlreadyGrown = 6007,
    InvalidCheckpoint = 6008,
    SignatureNotVerified = 6009,
    DuplicateAnchor = 6010,
    StaleAnchor = 6011,
    RingIndexInvalid = 6012,
    CosignWindowClosed = 6013,
    InvalidStatus = 6014,
    WitnessListFull = 6015,
    SlotNotReusable = 6016,
    DuplicateSigningKey = 6017,
    InvalidWitnessId = 6018,
    MintNotAllowed = 6019,
    BondBelowMinimum = 6020,
    UnbondingNotElapsed = 6021,
    StageInvalid = 6022,
    FrkMalformed = 6023,
    WrongLogKey = 6024,
    NotAFork = 6025,
    ProofWindowClosed = 6026,
    AttestationNotVerified = 6027,
    AlreadyProven = 6028,
    ImplicatedAccountsMismatch = 6029,
    FinderAccountMismatch = 6030,
    NothingToSlash = 6031,
    KindMismatch = 6032,
    AmountZero = 6033,
    WrongDestination = 6034,
    NotClosable = 6035,
    CloseTooEarly = 6036,
}

impl From<JudgeError> for ProgramError {
    fn from(e: JudgeError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

pub fn err<T>(e: JudgeError) -> Result<T, ProgramError> {
    Err(e.into())
}

pub fn require(cond: bool, e: JudgeError) -> Result<(), ProgramError> {
    if cond {
        Ok(())
    } else {
        Err(e.into())
    }
}
