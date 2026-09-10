use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Field, Fields, GenericArgument, PathArguments, Result, Type};

use super::{FieldKindOverride, ProstField, ident_name};

pub(super) fn expand(input: DeriveInput, runtime: TokenStream) -> Result<TokenStream> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(input.generics.span(), "generic messages are not supported"));
    }
    if let Some(attribute) = input.attrs.iter().find(|attr| attr.path().is_ident("proto_decode")) {
        return Err(syn::Error::new(
            attribute.span(),
            "ProtoDecodeFields has no message-level configuration; implement Verify on the record",
        ));
    }
    if let Data::Enum(data) = &input.data {
        return expand_oneof(&input, data, runtime);
    }
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(input.span(), "ProtoDecodeFields requires a named struct"));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new(data.fields.span(), "ProtoDecodeFields requires named fields"));
    };

    let source = &input.ident;
    let record = format_ident!("Decoded{}", ident_name(source));
    let visibility = &input.vis;
    let mut declarations = Vec::new();
    let mut initializers = Vec::new();
    for field in &fields.named {
        let ident = field.ident.as_ref().expect("named field");
        let name = ident_name(ident);
        let prost = ProstField::parse(field)?;
        if prost.map || prost.boxed {
            return Err(syn::Error::new(
                field.span(),
                "ProtoDecodeFields does not yet support maps or boxed messages",
            ));
        }
        let presence = FieldKindOverride::parse(&field.attrs)?;
        let bytes = bytes_adapter(&field.attrs, &prost)?;
        if presence.is_some()
            && prost.oneof.is_none()
            && (!prost.message || !prost.optional || prost.repeated)
        {
            return Err(syn::Error::new(
                field.span(),
                "presence overrides require a singular Option<Message> field",
            ));
        }

        let (ty, value) = if let Some(ty) = bytes {
            if prost.repeated {
                (
                    quote!(#runtime::Vec<#ty>),
                    quote!(#runtime::decode(#runtime::RepeatedField::new(#name, message.#ident))?),
                )
            } else if prost.optional {
                (
                    quote!(::core::option::Option<#ty>),
                    quote!(#runtime::decode(#runtime::OptionalField::new(#name, message.#ident))?),
                )
            } else {
                (
                    quote!(#ty),
                    quote!(#runtime::decode(#runtime::ValueField::new(#name, message.#ident))?),
                )
            }
        } else if let Some(oneof) = &prost.oneof {
            container_type(field, "Option")?;
            let decoded = quote!(<#oneof as #runtime::DecodeMessage>::Decoded);
            if matches!(presence, Some(FieldKindOverride::Optional)) {
                (
                    quote!(::core::option::Option<#decoded>),
                    quote!(#runtime::decode(#runtime::OptionalField::new(#name, message.#ident))?),
                )
            } else {
                (
                    decoded,
                    quote!(#runtime::decode(
                        #runtime::RequiredField::<#source, _>::new(#name, message.#ident)
                    )?),
                )
            }
        } else if let Some(enumeration) = &prost.enumeration {
            if prost.repeated {
                container_type(field, "Vec")?;
                (
                    quote!(#runtime::Vec<#enumeration>),
                    quote!(#runtime::decode(#runtime::RepeatedField::new(#name, message.#ident))?),
                )
            } else if prost.optional {
                container_type(field, "Option")?;
                (
                    quote!(::core::option::Option<#enumeration>),
                    quote!(#runtime::decode(#runtime::OptionalField::new(#name, message.#ident))?),
                )
            } else {
                (
                    quote!(#enumeration),
                    quote!(#runtime::decode(#runtime::ValueField::new(#name, message.#ident))?),
                )
            }
        } else if !prost.message {
            let ty = &field.ty;
            (quote!(#ty), quote!(message.#ident))
        } else if prost.repeated {
            let inner = container_type(field, "Vec")?;
            (
                quote!(#runtime::Vec<<#inner as #runtime::DecodeMessage>::Decoded>),
                quote!(#runtime::decode(#runtime::RepeatedField::new(#name, message.#ident))?),
            )
        } else if prost.optional {
            let inner = container_type(field, "Option")?;
            let decoded = quote!(<#inner as #runtime::DecodeMessage>::Decoded);
            if matches!(presence, Some(FieldKindOverride::Optional)) {
                (
                    quote!(::core::option::Option<#decoded>),
                    quote!(#runtime::decode(#runtime::OptionalField::new(#name, message.#ident))?),
                )
            } else {
                (
                    decoded,
                    quote!(#runtime::decode(
                        #runtime::RequiredField::<#source, _>::new(#name, message.#ident)
                    )?),
                )
            }
        } else {
            let inner = &field.ty;
            (
                quote!(<#inner as #runtime::DecodeMessage>::Decoded),
                quote!(#runtime::decode(#runtime::ValueField::new(#name, message.#ident))?),
            )
        };
        let docs = field.attrs.iter().filter(|attribute| attribute.path().is_ident("doc"));
        let visibility = &field.vis;
        declarations.push(quote!(#(#docs)* #visibility #ident: #ty));
        initializers.push(quote!(#ident: #value));
    }

    let doc = format!("Decoded fields of [`{source}`]. Domain invariants have not been verified.");
    Ok(quote! {
        #[doc = #doc]
        #[derive(Debug)]
        #[must_use = "decoded fields have not been verified"]
        #visibility struct #record {
            #(#declarations,)*
        }

        impl #runtime::DecodeMessage for #source {
            type Decoded = #record;
        }

        impl ::core::convert::TryFrom<#source> for #record {
            type Error = #runtime::ConversionError;

            fn try_from(message: #source) -> ::core::result::Result<Self, Self::Error> {
                ::core::result::Result::Ok(Self { #(#initializers,)* })
            }
        }
    })
}

fn expand_oneof(
    input: &DeriveInput,
    data: &syn::DataEnum,
    runtime: TokenStream,
) -> Result<TokenStream> {
    let source = &input.ident;
    let record = format_ident!("Decoded{}", ident_name(source));
    let visibility = &input.vis;
    let mut declarations = Vec::new();
    let mut arms = Vec::new();
    for variant in &data.variants {
        let Fields::Unnamed(fields) = &variant.fields else {
            return Err(syn::Error::new(variant.span(), "expected a Prost oneof payload"));
        };
        if fields.unnamed.len() != 1 {
            return Err(syn::Error::new(variant.span(), "expected one Prost oneof payload"));
        }
        let mut field = fields.unnamed[0].clone();
        field.attrs = variant.attrs.clone();
        let prost = ProstField::parse(&field)?;
        if prost.map || prost.boxed || prost.repeated || prost.optional || prost.oneof.is_some() {
            return Err(syn::Error::new(variant.span(), "unsupported Prost oneof payload"));
        }
        let mut name = None;
        let bytes = bytes_adapter(&variant.attrs, &prost)?;
        for attribute in variant.attrs.iter().filter(|attr| attr.path().is_ident("proto_decode")) {
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("bytes") {
                    meta.value()?.parse::<Type>()?;
                    return Ok(());
                }
                if !meta.path.is_ident("name") || name.is_some() {
                    return Err(meta.error("expected one descriptor-injected `name`"));
                }
                name = Some(meta.value()?.parse::<syn::LitStr>()?);
                Ok(())
            })?;
        }
        let name = name.ok_or_else(|| {
            syn::Error::new(
                variant.span(),
                "oneof variants require descriptor-injected #[proto_decode(name = \"wire_name\")]",
            )
        })?;
        let ident = &variant.ident;
        let ty = &field.ty;
        // Prost represents google.protobuf.Empty as (), which needs no decoding.
        let empty = matches!(ty, Type::Tuple(tuple) if tuple.elems.is_empty());
        let (decoded, value) = if let Some(ty) = bytes {
            (quote!(#ty), quote!(#runtime::decode(#runtime::ValueField::new(#name, value))?))
        } else if let Some(enumeration) = &prost.enumeration {
            (
                quote!(#enumeration),
                quote!(#runtime::decode(#runtime::ValueField::new(#name, value))?),
            )
        } else if prost.message && !empty {
            (
                quote!(<#ty as #runtime::DecodeMessage>::Decoded),
                quote!(#runtime::decode(#runtime::ValueField::new(#name, value))?),
            )
        } else {
            (quote!(#ty), quote!(value))
        };
        let docs = variant.attrs.iter().filter(|attr| attr.path().is_ident("doc"));
        declarations.push(quote!(#(#docs)* #ident(#decoded)));
        arms.push(quote!(#source::#ident(value) => Self::#ident(#value)));
    }
    Ok(quote! {
        /// Decoded oneof payload. Domain invariants have not been verified.
        #[derive(Debug)]
        #[must_use = "decoded fields have not been verified"]
        #visibility enum #record { #(#declarations,)* }
        impl #runtime::DecodeMessage for #source { type Decoded = #record; }
        impl ::core::convert::TryFrom<#source> for #record {
            type Error = #runtime::ConversionError;
            fn try_from(value: #source) -> ::core::result::Result<Self, Self::Error> {
                ::core::result::Result::Ok(match value { #(#arms,)* })
            }
        }
    })
}

fn bytes_adapter(attributes: &[syn::Attribute], prost: &ProstField) -> Result<Option<Type>> {
    let mut adapter = None;
    for attribute in attributes.iter().filter(|attr| attr.path().is_ident("proto_decode")) {
        attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("bytes") {
                if !prost.bytes || adapter.is_some() {
                    return Err(meta.error("configure at most one adapter on a Prost bytes field"));
                }
                adapter = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("name") {
                meta.value()?.parse::<syn::LitStr>()?;
            }
            Ok(())
        })?;
    }
    Ok(adapter)
}

fn container_type<'a>(field: &'a Field, container: &str) -> Result<&'a Type> {
    if let Type::Path(ty) = &field.ty
        && ty.qself.is_none()
        && let Some(segment) = ty.path.segments.last()
        && segment.ident == container
        && let PathArguments::AngleBracketed(args) = &segment.arguments
        && args.args.len() == 1
        && let Some(GenericArgument::Type(inner)) = args.args.first()
    {
        return Ok(inner);
    }
    Err(syn::Error::new(
        field.ty.span(),
        format!("expected a Prost {container}<T> field"),
    ))
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::parse_quote;

    use super::*;

    #[test]
    fn unsupported_fields_fail_explicitly() {
        for field in [
            quote!(#[prost(map = "string, uint32", tag = "1")] value: HashMap<String, u32>),
            quote!(#[prost(btree_map = "string, uint32", tag = "1")] value: BTreeMap<String, u32>),
            quote!(#[prost(message, optional, boxed, tag = "1")] value: Option<Box<Nested>>),
        ] {
            let input = syn::parse2(quote!(struct Message { #field })).unwrap();
            let error = expand(input, quote!(::runtime)).unwrap_err();
            assert!(error.to_string().contains("does not yet support"), "{error}");
        }
    }

    #[test]
    fn rejects_constructor_configuration() {
        let error = expand(
            parse_quote! {
                #[proto_decode(target(Domain), constructor(Domain::new(value)))]
                struct Message { #[prost(uint32, tag = "1")] value: u32 }
            },
            quote!(::runtime),
        )
        .unwrap_err();
        assert!(error.to_string().contains("implement Verify"));
    }

    #[test]
    fn oneof_requires_wire_names_and_single_payloads() {
        for input in [
            quote!(
                enum Choice {
                    #[prost(uint32, tag = "1")]
                    Value(u32),
                }
            ),
            quote!(
                enum Choice {
                    #[prost(uint32, tag = "1")]
                    Value,
                }
            ),
            quote!(
                enum Choice {
                    #[prost(uint32, tag = "1")]
                    Value(u32, u32),
                }
            ),
        ] {
            assert!(expand(syn::parse2(input).unwrap(), quote!(::runtime)).is_err());
        }
    }

    #[test]
    fn byte_adapters_reject_non_bytes_and_duplicates() {
        for field in [
            quote!(#[prost(uint32, tag = "1")] #[proto_decode(bytes = Adapter)] value: u32),
            quote!(#[prost(bytes = "vec", tag = "1")] #[proto_decode(bytes = Adapter, bytes = Adapter)] value: Vec<u8>),
        ] {
            let input = syn::parse2(quote!(struct Message { #field })).unwrap();
            assert!(expand(input, quote!(::runtime)).is_err());
        }
    }

    #[test]
    fn rejects_invalid_presence_overrides() {
        let error = expand(
            parse_quote! {
                struct Message {
                    #[prost(message, repeated, tag = "1")]
                    #[proto_decode(optional)]
                    value: Vec<Nested>,
                }
            },
            quote!(::runtime),
        )
        .unwrap_err();
        assert!(error.to_string().contains("singular Option<Message>"));
    }
}
