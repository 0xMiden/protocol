use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Fields, Result};

use super::{ProstField, ident_name};

pub(super) fn expand(input: DeriveInput, runtime: TokenStream) -> Result<TokenStream> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(input.generics.span(), "generic messages are not supported"));
    }
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(input.span(), "ProtoDecodeValue requires a named struct"));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new(data.fields.span(), "ProtoDecodeValue requires named fields"));
    };
    if fields.named.len() != 1 {
        return Err(syn::Error::new(fields.span(), "ProtoDecodeValue requires exactly one field"));
    }
    let field = &fields.named[0];
    let prost = ProstField::parse(field)?;
    if prost.message
        || prost.optional
        || prost.repeated
        || prost.map
        || prost.boxed
        || prost.enumeration.is_some()
        || prost.oneof.is_some()
    {
        return Err(syn::Error::new(
            field.span(),
            "ProtoDecodeValue requires a singular scalar or bytes payload",
        ));
    }
    let source = &input.ident;
    let field_ident = field.ident.as_ref().expect("named field");
    let name = ident_name(field_ident);
    let ty = &field.ty;
    Ok(quote! {
        impl #source {
            /// Parses the borrowed payload, attaching its schema field name to any error.
            /// This does not verify domain invariants.
            pub fn decode_value<T, E>(
                &self,
                parse: impl ::core::ops::FnOnce(&#ty) -> ::core::result::Result<T, E>,
            ) -> ::core::result::Result<T, #runtime::ConversionError>
            where
                E: ::core::error::Error + ::core::marker::Send + ::core::marker::Sync + 'static,
            {
                parse(&self.#field_ident)
                    .map_err(|error| #runtime::ConversionError::new(error).context(#name))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::parse_quote;

    use super::*;

    #[test]
    fn rejects_non_payload_shapes() {
        let inputs = [
            quote!(
                enum Value {
                    A,
                }
            ),
            quote!(
                struct Value(u32);
            ),
            quote!(
                struct Value {}
            ),
            quote!(
                struct Value {
                    a: u32,
                    b: u32,
                }
            ),
            quote!(
                struct Value<T> {
                    value: T,
                }
            ),
            quote!(
                struct Value {
                    #[prost(message, tag = "1")]
                    value: Message,
                }
            ),
            quote!(
                struct Value {
                    #[prost(uint32, optional, tag = "1")]
                    value: Option<u32>,
                }
            ),
            quote!(
                struct Value {
                    #[prost(uint32, repeated, tag = "1")]
                    value: Vec<u32>,
                }
            ),
            quote!(
                struct Value {
                    #[prost(enumeration = "Kind", tag = "1")]
                    value: i32,
                }
            ),
            quote!(
                struct Value {
                    #[prost(oneof = "Kind", tags = "1")]
                    value: Option<Kind>,
                }
            ),
            quote!(
                struct Value {
                    value: u32,
                }
            ),
        ];
        for input in inputs {
            assert!(expand(syn::parse2(input).unwrap(), quote!(runtime)).is_err());
        }
    }

    #[test]
    fn uses_unescaped_field_names() {
        let output = expand(
            parse_quote!(
                struct Value {
                    #[prost(uint32, tag = "1")]
                    r#type: u32,
                }
            ),
            quote!(runtime),
        )
        .unwrap()
        .to_string();
        assert!(output.contains("context (\"type\")"), "{output}");
    }
}
