use crate::{MlsDecode, MlsEncode, MlsSize};

impl<T: MlsSize> MlsSize for Option<T> {
    #[inline]
    fn mls_encoded_len(&self) -> usize {
        1 + match self {
            Some(v) => v.mls_encoded_len(),
            None => 0,
        }
    }
}

impl<T: MlsEncode> MlsEncode for Option<T> {
    fn mls_encode<W: crate::Writer>(&self, mut writer: W) -> Result<(), crate::Error> {
        if let Some(item) = self {
            writer.write(&[1])?;
            item.mls_encode(&mut writer)
        } else {
            writer.write(&[0])
        }
    }
}

impl<T: MlsDecode> MlsDecode for Option<T> {
    fn mls_decode<R: crate::Reader>(mut reader: R) -> Result<Self, crate::Error> {
        match u8::mls_decode(&mut reader)? {
            0 => Ok(None),
            1 => T::mls_decode(&mut reader).map(Some),
            n => Err(crate::Error::OptionOutOfRange(n)),
        }
    }
}

impl<T: MlsSize> MlsSize for &Option<T> {
    #[inline]
    fn mls_encoded_len(&self) -> usize {
        (*self).mls_encoded_len()
    }
}

impl<T: MlsEncode> MlsEncode for &Option<T> {
    #[inline]
    fn mls_encode<W: crate::Writer>(&self, writer: W) -> Result<(), crate::Error> {
        (*self).mls_encode(writer)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::{Error, MlsDecode, MlsEncode};
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn none_is_serialized_correctly() {
        assert_eq!(vec![0u8], None::<u8>.mls_encode_to_vec().unwrap());
    }

    #[test]
    fn some_is_serialized_correctly() {
        assert_eq!(vec![1u8, 2], Some(2u8).mls_encode_to_vec().unwrap());
    }

    #[test]
    fn none_round_trips() {
        let val = None::<u8>;
        let x = val.mls_encode_to_vec().unwrap();
        assert_eq!(val, Option::mls_decode(&*x).unwrap());
    }

    #[test]
    fn some_round_trips() {
        let val = Some(32u8);
        let x = val.mls_encode_to_vec().unwrap();
        assert_eq!(val, Option::mls_decode(&*x).unwrap());
    }

    #[test]
    fn deserializing_invalid_discriminant_fails() {
        assert_matches!(
            Option::<u8>::mls_decode(&mut &[2u8][..]),
            Err(Error::OptionOutOfRange(_))
        );
    }
}
