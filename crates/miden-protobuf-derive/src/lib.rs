//! Derives schema-shaped decoded records from Prost messages.
use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::ext::IdentExt;
use syn::parse::ParseStream;
use syn::spanned::Spanned;
use syn::{
    Attribute,
    DeriveInput,
    Expr,
    Field,
    Ident,
    LitStr,
    Path,
    Result,
    Token,
    parenthesized,
    parse_macro_input,
};
mod fields;
mod value;

/// Generates `decode_value(&self, parser)` for a single scalar or bytes payload.
/// The parser handles representation decoding only; the generated method attaches the schema
/// field name and preserves the error source. No domain target or constructor is configured.
#[proc_macro_derive(ProtoDecodeValue)]
pub fn derive_proto_decode_value(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    runtime_path()
        .and_then(|runtime| value::expand(input, runtime))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
/// Generates a decoded record without domain construction.
/// Message cardinality and error paths come from Prost metadata and descriptor-injected presence.
/// Enum fields use Prost's named enums and reject unknown discriminants during decoding.
/// Oneofs produce decoded enums; descriptor metadata supplies exact wire variant names.
/// `#[proto_decode(bytes = Adapter)]` opts a bytes field into `TryFrom` conversion to a local
/// representation adapter. Cardinality and error paths are still generated; this is not a
/// constructor or verification hook.
/// Maps and boxed messages are not supported by this experimental derive.
#[proc_macro_derive(ProtoDecodeFields, attributes(proto_decode))]
pub fn derive_proto_decode_fields(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    runtime_path()
        .and_then(|runtime| fields::expand(input, runtime))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
fn ident_name(ident: &Ident) -> String {
    ident.unraw().to_string()
}
fn runtime_path() -> Result<TokenStream2> {
    match crate_name("miden-protobuf") {
        Ok(FoundCrate::Itself) => Ok(quote!(crate::__private)),
        Ok(FoundCrate::Name(name)) => {
            let name = Ident::new(&name, Span::call_site());
            Ok(quote!(::#name::__private))
        },
        Err(error) => Err(syn::Error::new(
            Span::call_site(),
            format!("protobuf decoding derives require a dependency on `miden-protobuf`: {error}"),
        )),
    }
}

struct ProstField {
    message: bool,
    optional: bool,
    repeated: bool,
    map: bool,
    boxed: bool,
    bytes: bool,
    enumeration: Option<Path>,
    oneof: Option<Path>,
}

impl ProstField {
    fn parse(field: &Field) -> Result<Self> {
        let mut parsed = Self {
            message: false,
            optional: false,
            repeated: false,
            map: false,
            boxed: false,
            bytes: false,
            enumeration: None,
            oneof: None,
        };
        let mut found = false;

        for attribute in field.attrs.iter().filter(|attribute| attribute.path().is_ident("prost")) {
            found = true;
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("oneof") {
                    if parsed.oneof.is_some() {
                        return Err(meta.error("duplicate Prost oneof setting"));
                    }
                    let value = meta.value()?;
                    let path: LitStr = value.parse()?;
                    parsed.oneof = Some(path.parse()?);
                    return Ok(());
                }

                if meta.path.is_ident("enumeration") {
                    if parsed.enumeration.is_some() {
                        return Err(meta.error("duplicate Prost enumeration setting"));
                    }
                    let value = meta.value()?;
                    let path: LitStr = value.parse()?;
                    parsed.enumeration = Some(path.parse()?);
                    return Ok(());
                }

                parsed.message |= meta.path.is_ident("message");
                parsed.optional |= meta.path.is_ident("optional");
                parsed.repeated |= meta.path.is_ident("repeated");
                parsed.map |= meta.path.is_ident("map") || meta.path.is_ident("btree_map");
                parsed.boxed |= meta.path.is_ident("boxed");
                parsed.bytes |= meta.path.is_ident("bytes");

                consume_meta_value(meta.input)
            })?;
        }

        if !found {
            return Err(syn::Error::new(
                field.span(),
                "ProtoDecode fields must have a `prost` attribute",
            ));
        }

        Ok(parsed)
    }
}

fn consume_meta_value(input: ParseStream<'_>) -> Result<()> {
    if input.peek(Token![=]) {
        let value = input.parse::<Token![=]>()?;
        let _ = value;
        input.parse::<Expr>()?;
    } else if input.peek(syn::token::Paren) {
        let content;
        parenthesized!(content in input);
        content.parse::<TokenStream2>()?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum FieldKindOverride {
    Required,
    Optional,
}

impl FieldKindOverride {
    fn parse(attributes: &[Attribute]) -> Result<Option<Self>> {
        let mut kind = None;

        for attribute in
            attributes.iter().filter(|attribute| attribute.path().is_ident("proto_decode"))
        {
            attribute.parse_nested_meta(|meta| {
                let parsed = if meta.path.is_ident("required") {
                    Self::Required
                } else if meta.path.is_ident("optional") {
                    Self::Optional
                } else if meta.path.is_ident("bytes") {
                    meta.value()?.parse::<syn::Type>()?;
                    return Ok(());
                } else {
                    return Err(meta.error("expected `required` or `optional`"));
                };
                if kind.is_some() {
                    return Err(meta.error("configure at most one field presence override"));
                }
                kind = Some(parsed);
                Ok(())
            })?;
        }

        Ok(kind)
    }
}
