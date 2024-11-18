use crate::{
    utilities::right_pad, Precompile, PrecompileError, PrecompileOutput, PrecompileResult,
    PrecompileWithAddress,
};
use primitives::{alloy_primitives::B512, Bytes, B256};

pub const ECRECOVER: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(1),
    Precompile::Standard(ec_recover_run),
);

pub use self::secp256k1::ecrecover;

#[cfg(test)]
mod tests {
    use super::*;

    // Working ecrecover
    #[test]
    fn test_ecrecover_1() {
        let sig = B512::from_slice(&[
            8, 131, 41, 101, 245, 241, 246, 46, 150, 250, 85, 66, 88, 208, 2, 36, 117, 225, 219, 203, 247, 147, 145, 89, 53, 152, 42, 2, 12, 93, 103, 244, 38, 60, 234, 135, 240, 140, 114, 34, 231, 145, 47, 90, 70, 41, 225, 135, 91, 143, 225, 26, 156, 204, 62, 82, 23, 93, 21, 13, 154, 220, 194, 163
        ]);
        let msg = B256::from_slice(&[
            218, 227, 122, 80, 241, 162, 174, 254, 125, 117, 244, 206, 144, 194, 244, 85, 244, 65, 178, 82, 81, 33, 69, 69, 71, 20, 116, 105, 53, 193, 158, 227
        ]);
        let recid: u8 = 0;
        secp256k1::ecrecover(&sig, recid, &msg).unwrap();
    }

    // Broken ecrecover
    #[test]
    fn test_ecrecover_2() {
        let sig = B512::from_slice(&[
            34, 213, 137, 64, 98, 135, 158, 175, 24, 238, 69, 187, 159, 129, 170, 169, 57, 63, 146, 119, 13, 96, 93, 27, 230, 219, 213, 185, 120, 232, 161, 0, 7, 102, 180, 190, 72, 7, 211, 149, 148, 194, 100, 170, 253, 255, 21, 206, 162, 204, 79, 4, 62, 129, 183, 36, 55, 201, 117, 48, 129, 210, 16, 140
        ]);
        let msg = B256::from_slice(&[
            71, 232, 97, 55, 31, 90, 231, 37, 51, 29, 55, 185, 14, 27, 130, 120, 126, 221, 252, 162, 131, 106, 194, 78, 67, 59, 105, 102, 185, 49, 42, 229
        ]);
        let recid: u8 = 1;
        secp256k1::ecrecover(&sig, recid, &msg).unwrap();
    }
}

#[cfg(not(feature = "secp256k1"))]
#[allow(clippy::module_inception)]
mod secp256k1 {
    use k256::ecdsa::{Error, RecoveryId, Signature, VerifyingKey};
    use primitives::{alloy_primitives::B512, keccak256, B256};

    pub fn ecrecover(sig: &B512, mut recid: u8, msg: &B256) -> Result<B256, Error> {
        // parse signature
        let mut sig = Signature::from_slice(sig.as_slice())?;

        // normalize signature and flip recovery id if needed.
        if let Some(sig_normalized) = sig.normalize_s() {
            sig = sig_normalized;
            recid ^= 1;
        }
        let recid = RecoveryId::from_byte(recid).expect("recovery ID is valid");

        // recover key
        let recovered_key = VerifyingKey::recover_from_prehash(&msg[..], &sig, recid)?;
        // hash it
        let mut hash = keccak256(
            &recovered_key
                .to_encoded_point(/* compress = */ false)
                .as_bytes()[1..],
        );

        // truncate to 20 bytes
        hash[..12].fill(0);
        Ok(hash)
    }
}

#[cfg(feature = "secp256k1")]
#[allow(clippy::module_inception)]
mod secp256k1 {
    use primitives::{alloy_primitives::B512, keccak256, B256};
    use secp256k1::{
        ecdsa::{RecoverableSignature, RecoveryId},
        Message, SECP256K1,
    };

    // Silence the unused crate dependency warning.
    use k256 as _;

    pub fn ecrecover(sig: &B512, recid: u8, msg: &B256) -> Result<B256, secp256k1::Error> {
        let recid = RecoveryId::from_i32(recid as i32).expect("recovery ID is valid");
        let sig = RecoverableSignature::from_compact(sig.as_slice(), recid)?;

        let msg = Message::from_digest(msg.0);
        let public = SECP256K1.recover_ecdsa(&msg, &sig)?;

        let mut hash = keccak256(&public.serialize_uncompressed()[1..]);
        hash[..12].fill(0);
        Ok(hash)
    }
}

pub fn ec_recover_run(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const ECRECOVER_BASE: u64 = 3_000;

    if ECRECOVER_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }

    let input = right_pad::<128>(input);

    // `v` must be a 32-byte big-endian integer equal to 27 or 28.
    if !(input[32..63].iter().all(|&b| b == 0) && matches!(input[63], 27 | 28)) {
        return Ok(PrecompileOutput::new(ECRECOVER_BASE, Bytes::new()));
    }

    let msg = <&B256>::try_from(&input[0..32]).unwrap();
    let recid = input[63] - 27;
    let sig = <&B512>::try_from(&input[64..128]).unwrap();

    let out = secp256k1::ecrecover(sig, recid, msg)
        .map(|o| o.to_vec().into())
        .unwrap_or_default();
    Ok(PrecompileOutput::new(ECRECOVER_BASE, out))
}
