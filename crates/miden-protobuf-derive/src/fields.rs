use std::collections::BTreeSet;

use heck::ToSnakeCase;
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
        if prost.boxed && (!prost.message || prost.map) {
            return Err(syn::Error::new(field.span(), "boxed fields require a message value"));
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

        let (ty, value) = if prost.map {
            let (ty, value) = map_field(field, &prost, bytes, &runtime)?;
            (quote!(#runtime::MapField<#ty>), quote!(#runtime::MapField::new(#name, #value)))
        } else {
            let inner = if prost.repeated {
                container_type(&field.ty, "Vec")?
            } else if prost.optional || prost.oneof.is_some() {
                container_type(&field.ty, "Option")?
            } else {
                &field.ty
            };
            let inner = if prost.boxed {
                container_type(inner, "Box")?
            } else {
                inner
            };
            let empty = matches!(inner, Type::Tuple(tuple) if tuple.elems.is_empty());
            let convert = bytes.is_some()
                || prost.oneof.is_some()
                || prost.enumeration.is_some()
                || (prost.message && !empty);
            let ty = if let Some(ty) = bytes {
                quote!(#ty)
            } else if let Some(oneof) = &prost.oneof {
                quote!(<#oneof as #runtime::DecodeMessage>::Decoded)
            } else if let Some(enumeration) = &prost.enumeration {
                quote!(#enumeration)
            } else if prost.message && !empty {
                quote!(<#inner as #runtime::DecodeMessage>::Decoded)
            } else {
                quote!(#inner)
            };
            let ty = if prost.boxed { quote!(#runtime::Box<#ty>) } else { ty };
            // Presence is resolved during structural decoding. Only fields which remain
            // optional retain an OptionalField in the decoded record.
            let required = (prost.oneof.is_some() || (prost.message && prost.optional))
                && !matches!(presence, Some(FieldKindOverride::Optional));
            if prost.repeated {
                let values = if prost.boxed && convert {
                    quote!(#runtime::RepeatedField::new(#name, message.#ident).try_map(|value| {
                        <#inner as #runtime::DecodeMessage>::decode_fields(*value)
                            .map(#runtime::Box::new)
                    })?)
                } else if convert {
                    quote!(#runtime::decode(#runtime::RepeatedField::new(#name, message.#ident))?)
                } else {
                    quote!(message.#ident)
                };
                (
                    quote!(#runtime::RepeatedField<#ty>),
                    quote!(#runtime::RepeatedField::new(#name, #values)),
                )
            } else if required {
                let value = if prost.boxed && convert {
                    quote!(#runtime::Box::new(#runtime::decode(
                        #runtime::RequiredField::<#source, _>::new(
                            #name, message.#ident.map(|value| *value)
                        )
                    )?))
                } else {
                    quote!(#runtime::decode(
                        #runtime::RequiredField::<#source, _>::new(#name, message.#ident)
                    )?)
                };
                (ty, value)
            } else if prost.optional || prost.oneof.is_some() {
                let value = if prost.boxed && convert {
                    quote!(#runtime::OptionalField::new(#name, message.#ident).try_map(|value| {
                        <#inner as #runtime::DecodeMessage>::decode_fields(*value)
                            .map(#runtime::Box::new)
                    })?)
                } else if convert {
                    quote!(#runtime::decode(#runtime::OptionalField::new(#name, message.#ident))?)
                } else {
                    quote!(message.#ident)
                };
                (
                    quote!(#runtime::OptionalField<#ty>),
                    quote!(#runtime::OptionalField::new(#name, #value)),
                )
            } else if prost.boxed && convert {
                (
                    ty,
                    quote!(#runtime::Box::new(#runtime::decode(
                        #runtime::ValueField::new(#name, *message.#ident)
                    )?)),
                )
            } else if convert {
                (ty, quote!(#runtime::decode(#runtime::ValueField::new(#name, message.#ident))?))
            } else {
                (ty, quote!(message.#ident))
            }
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

fn map_field(
    field: &Field,
    prost: &ProstField,
    bytes: Option<Type>,
    runtime: &TokenStream,
) -> Result<(TokenStream, TokenStream)> {
    let mut ty = field.ty.clone();
    let Type::Path(path) = &mut ty else {
        return Err(syn::Error::new(ty.span(), "expected a Prost map field"));
    };
    let segment = path.path.segments.last_mut().expect("nonempty type path");
    if !matches!(segment.ident.to_string().as_str(), "HashMap" | "BTreeMap") {
        return Err(syn::Error::new(ty.span(), "expected HashMap<K, V> or BTreeMap<K, V>"));
    }
    let PathArguments::AngleBracketed(args) = &mut segment.arguments else {
        return Err(syn::Error::new(ty.span(), "expected map key and value types"));
    };
    if args.args.len() != 2 {
        return Err(syn::Error::new(args.span(), "expected map key and value types"));
    }
    let Some(GenericArgument::Type(value)) = args.args.iter_mut().nth(1) else {
        return Err(syn::Error::new(args.span(), "expected a map value type"));
    };
    let empty = matches!(value, Type::Tuple(tuple) if tuple.elems.is_empty());
    let ident = field.ident.as_ref().expect("named field");
    *value = if let Some(bytes) = bytes {
        bytes
    } else if let Some(enumeration) = &prost.enumeration {
        syn::parse_quote!(#enumeration)
    } else if prost.message && !empty {
        syn::parse_quote!(<#value as #runtime::DecodeMessage>::Decoded)
    } else {
        // Scalars (including bytes and google.protobuf.Empty) need no conversion.
        return Ok((quote!(#ty), quote!(message.#ident)));
    };
    let name = ident_name(ident);
    Ok((
        quote!(#ty),
        quote!(#runtime::decode(#runtime::MapField::new(#name, message.#ident))?),
    ))
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
    let mut variant_names = Vec::new();
    let mut wire_accessors = Vec::new();
    let mut decoded_accessors = Vec::new();
    let mut accessor_names = BTreeSet::new();
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
        if prost.map || prost.repeated || prost.optional || prost.oneof.is_some() {
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
        let accessor_name = format!("into_{}", name.value().to_snake_case());
        let accessor = syn::parse_str::<syn::Ident>(&accessor_name)
            .map_err(|_| syn::Error::new(name.span(), "invalid oneof accessor name"))?;
        if !accessor_names.insert(accessor_name) {
            return Err(syn::Error::new(name.span(), "duplicate oneof accessor name"));
        }
        let ty = &field.ty;
        // Prost emits Box<T> for recursive oneof payloads without a `boxed` attribute.
        let boxed = prost.boxed
            || matches!(ty, Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "Box"));
        if boxed && !prost.message {
            return Err(syn::Error::new(variant.span(), "boxed oneof payloads require a message"));
        }
        let inner = if boxed { container_type(ty, "Box")? } else { ty };
        // Prost represents google.protobuf.Empty as (), which needs no decoding.
        let empty = matches!(inner, Type::Tuple(tuple) if tuple.elems.is_empty());
        let (decoded, value) = if let Some(ty) = bytes {
            (quote!(#ty), quote!(#runtime::decode(#runtime::ValueField::new(#name, value))?))
        } else if let Some(enumeration) = &prost.enumeration {
            (
                quote!(#enumeration),
                quote!(#runtime::decode(#runtime::ValueField::new(#name, value))?),
            )
        } else if boxed && !empty {
            (
                quote!(#runtime::Box<<#inner as #runtime::DecodeMessage>::Decoded>),
                quote!(#runtime::Box::new(#runtime::decode(
                    #runtime::ValueField::new(#name, *value)
                )?)),
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
        variant_names.push(quote!(Self::#ident(_) => #name));
        let wire_doc = format!(
            "Extracts and structurally decodes the `{}` payload without verifying it. \
             Returns a wrong-variant error before decoding if another variant is present.",
            name.value()
        );
        let mismatch = (data.variants.len() > 1).then(|| {
            quote! {
                other => ::core::result::Result::Err(#runtime::ConversionError::wrong_variant(
                    #name, other.__proto_decode_variant_name()
                )),
            }
        });
        wire_accessors.push(quote! {
            #[doc = #wire_doc]
            pub fn #accessor(self) -> ::core::result::Result<#decoded, #runtime::ConversionError> {
                match self {
                    Self::#ident(value) => ::core::result::Result::Ok(#value),
                    #mismatch
                }
            }
        });
        let decoded_doc = format!(
            "Extracts the decoded `{}` payload without verifying it. \
             Returns a wrong-variant error if another variant is present.",
            name.value()
        );
        decoded_accessors.push(quote! {
            #[doc = #decoded_doc]
            pub fn #accessor(self) -> ::core::result::Result<#decoded, #runtime::ConversionError> {
                match self {
                    Self::#ident(value) => ::core::result::Result::Ok(value),
                    #mismatch
                }
            }
        });
    }
    let variant_name_helper = (data.variants.len() > 1).then(|| {
        quote! {
            fn __proto_decode_variant_name(&self) -> &'static str {
                match self { #(#variant_names,)* }
            }
        }
    });
    Ok(quote! {
        /// Decoded oneof payload. Domain invariants have not been verified.
        #[derive(Debug)]
        #[must_use = "decoded fields have not been verified"]
        #visibility enum #record { #(#declarations,)* }
        impl #source {
            #variant_name_helper
            #(#wire_accessors)*
        }
        impl #record {
            #variant_name_helper
            #(#decoded_accessors)*
        }
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

fn container_type<'a>(field_type: &'a Type, container: &str) -> Result<&'a Type> {
    if let Type::Path(ty) = field_type
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
        field_type.span(),
        format!("expected a Prost {container}<T> field"),
    ))
}

#[cfg(test)]
mod tests {
    use quote::quote;
    use syn::parse_quote;

    use super::*;

    #[test]
    fn malformed_boxed_fields_fail_explicitly() {
        for field in [
            quote!(#[prost(message, optional, boxed, tag = "1")] value: Option<Nested>),
            quote!(#[prost(uint32, boxed, tag = "1")] value: Box<u32>),
            quote!(#[prost(map = "string, message", boxed, tag = "1")] value: HashMap<String, Nested>),
        ] {
            let input = syn::parse2(quote!(struct Message { #field })).unwrap();
            assert!(expand(input, quote!(::runtime)).is_err());
        }
    }

    #[test]
    fn malformed_maps_fail_explicitly() {
        for field in [
            quote!(#[prost(map = "string", tag = "1")] value: HashMap<String, u32>),
            quote!(#[prost(map = "string, enumeration", tag = "1")] value: HashMap<String, i32>),
            quote!(#[prost(map = "string, message", tag = "1")] value: Vec<Nested>),
            quote!(#[prost(btree_map = "string, message", tag = "1")] value: BTreeMap<Nested>),
            quote!(#[prost(map = "string, message", btree_map = "string, message", tag = "1")] value: HashMap<String, Nested>),
        ] {
            let input = syn::parse2(quote!(struct Message { #field })).unwrap();
            assert!(expand(input, quote!(::runtime)).is_err());
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
    fn conflicting_accessor_names_fail_explicitly() {
        let input = parse_quote! {
            enum Choice {
                #[prost(uint32, tag = "1")]
                #[proto_decode(name = "http_response")]
                First(u32),
                #[prost(uint32, tag = "2")]
                #[proto_decode(name = "HTTPResponse")]
                Second(u32),
            }
        };
        let error = expand(input, quote!(::runtime)).unwrap_err();
        assert!(error.to_string().contains("duplicate oneof accessor name"), "{error}");
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
