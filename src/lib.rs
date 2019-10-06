use serde::{self, Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Rfc8037Jwk {
    pub x: PublicBytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<PrivateBytes>,
    pub kty: String,
    pub crv: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(transparent)]
pub struct PublicBytes(
    #[serde(with="base64_key")]
    pub [u8;32]
);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(transparent)]
pub struct PrivateBytes(
    #[serde(with="base64_key")]
    pub [u8;32]
);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(try_from = "Rfc8037Jwk")]
#[serde(into = "Rfc8037Jwk")]
pub struct Curve25519PubKey {
    pub public: PublicBytes
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(try_from = "Rfc8037Jwk")]
#[serde(into = "Rfc8037Jwk")]
pub struct Curve25519PrvKey{
    pub public:  PublicBytes,
    pub private: PrivateBytes,
}

impl Into<Rfc8037Jwk> for Curve25519PrvKey {
    fn into(self) -> Rfc8037Jwk {
        Rfc8037Jwk {
            x: PublicBytes(self.public.0),
            d: Some(PrivateBytes(self.private.0)),
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
        }
    }
}

impl Into<Rfc8037Jwk> for Curve25519PubKey {
    fn into(self) -> Rfc8037Jwk {
        Rfc8037Jwk {
            x: PublicBytes(self.public.0),
            d: None,
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
        }
    }
}

impl TryFrom<Rfc8037Jwk> for Curve25519PubKey {
    type Error = &'static str;

    fn try_from(jwk:Rfc8037Jwk) -> Result<Self, Self::Error> {
        if jwk.kty == "OKP".to_string() && jwk.crv == "Ed25519".to_string() && jwk.d.is_none() {
            Ok(Curve25519PubKey{public: jwk.x})
        } else {
            Err("Invalid Ed25519 public key")
        }
    }
}

impl TryFrom<Rfc8037Jwk> for Curve25519PrvKey {
    type Error = &'static str;

    fn try_from(jwk:Rfc8037Jwk) -> Result<Self, Self::Error> {
        if jwk.kty == "OKP".to_string() && jwk.crv == "Ed25519".to_string() && jwk.d.is_some() {
            Ok(Curve25519PrvKey{
                public:jwk.x,
                private:jwk.d.unwrap(),
            })
        } else {
            Err("Invalid Ed25519 private key")
        }
    }
}

mod base64_key {
    use serde;
    use base64;
    use std::fmt;

    pub fn serialize <S> (val: &[u8;32], serializer: S) -> Result<S::Ok, S::Error> where S: serde::ser::Serializer {
        let b64 = base64::encode_config(val, base64::URL_SAFE_NO_PAD);
        serializer.serialize_str(&b64)
    }

    pub fn deserialize <'de, D> (deserializer: D) -> Result<[u8;32], D::Error> where D: serde::de::Deserializer<'de> {
        struct Visitor;

        impl <'de> serde::de::Visitor<'de> for Visitor {
            type Value = [u8;32];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a 32 byte array")
            }

            fn visit_str <E> (self, val: &str) -> Result<Self::Value, E> where E: serde::de::Error {
                let de_vec =
                    base64::decode_config(val, base64::URL_SAFE_NO_PAD).map_err(E::custom)?;

                // ensure exactly 32 bytes was decoded
                if de_vec.len() != 32 {
                    return Err(E::custom("expected 32 bytes!"))
                }

                // copy the bytes from the vector into our owned array
                let mut arr = [0u8;32];
                for (arri, &veci) in arr.iter_mut().zip(de_vec.iter()) {
                    *arri = veci
                }

                Ok(arr)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::{Curve25519PrvKey, Curve25519PubKey};


    const A1_PRV_KEY_EXAMPLE: &'static str = r###"
{
    "kty":"OKP",
    "crv":"Ed25519",
    "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
    "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"

}
"###;
    const A2_PUB_KEY_EXAMPLE: &'static str = r###"
{
    "kty":"OKP",
    "crv":"Ed25519",
    "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
}
"###;
    const MISSING_KEY_TYPE_EXAMPLE: &'static str = r###"
{
    "crv":"Ed25519",
    "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
}
"###;
    const BAD_KEY_TYPE_EXAMPLE: &'static str = r###"
{
    "kty":"OKQ",
    "crv":"Ed25519",
    "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
}
"###;


    const ED25519_PRV_KEY_EXAMPLE: [u8;32] =  [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];

    const ED25519_PUB_KEY_EXAMPLE: [u8;32] =  [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ];

    #[test]
    fn rfc8037_a1_example_should_succeed ()  {
        let v = serde_json::from_str::<Curve25519PrvKey>(A1_PRV_KEY_EXAMPLE);
        assert!(v.is_ok());

        let val = v.unwrap();
        assert_eq!(val.public.0, ED25519_PUB_KEY_EXAMPLE);
        assert_eq!(val.private.0, ED25519_PRV_KEY_EXAMPLE);
    }

    #[test]
    fn rfc8037_a2_example_should_succeed () {
        let v  = serde_json::from_str::<Curve25519PubKey>(A2_PUB_KEY_EXAMPLE);
        assert!(v.is_ok());

        let val = v.unwrap();
        assert_eq!(val.public.0, ED25519_PUB_KEY_EXAMPLE);
    }

    #[test]
    fn public_key_data_should_not_parse_into_private_key () {
        let v = serde_json::from_str::<Curve25519PrvKey>(A2_PUB_KEY_EXAMPLE);
        assert!(v.is_err());
    }

    #[test]
    fn private_key_data_should_not_parse_into_public_key () {
        let v = serde_json::from_str::<Curve25519PubKey>(A1_PRV_KEY_EXAMPLE);
        assert!(v.is_err());
    }

    #[test]
    fn bad_key_type_should_fail () {
        let bad_pub = serde_json::from_str::<Curve25519PubKey>(BAD_KEY_TYPE_EXAMPLE);
        assert!(bad_pub.is_err());
        let bad_prv = serde_json::from_str::<Curve25519PrvKey>(BAD_KEY_TYPE_EXAMPLE);
        assert!(bad_prv.is_err());
    }

    #[test]
    fn missing_key_type_should_fail () {
        let mis_pub = serde_json::from_str::<Curve25519PubKey>(MISSING_KEY_TYPE_EXAMPLE);
        assert!(mis_pub.is_err());
        let mis_prv = serde_json::from_str::<Curve25519PrvKey>(MISSING_KEY_TYPE_EXAMPLE);
        assert!(mis_prv.is_err());
    }
}
