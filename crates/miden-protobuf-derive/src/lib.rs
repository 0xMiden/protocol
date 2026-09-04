//! Derives conversions from Prost-generated messages into domain types.

use std::collections::{BTreeMap, BTreeSet};

use heck::ToSnakeCase;
use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::ext::IdentExt;
use syn::parse::ParseStream;
use syn::spanned::Spanned;
use syn::{
    Attribute,
    Data,
    DeriveInput,
    Expr,
    Field,
    Fields,
    Ident,
    LitStr,
    Path,
    Result,
    Token,
    Type,
    parenthesized,
    parse_macro_input,
};

/// Generates `TryFrom<ProtoMessage>` for a configured domain type.
///
/// The derive reads cardinality and presence information from Prost's field attributes. The
/// `proto_decode` attribute supplies the foreign target type and an explicit constructor call or
/// tuple expression whose fields define the conversion order. Optional field validators consume
/// fields before constructor arguments are decoded and must return `Result<(), E>`. Oneof fields
/// require explicit mappings from generated variants to infallible target constructors. Fallible
/// field decoders run after the field's cardinality-aware conversion.
#[proc_macro_derive(ProtoDecode, attributes(proto_decode))]
pub fn derive_proto_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let runtime = match runtime_path() {
        Ok(runtime) => runtime,
        Err(error) => return error.into_compile_error().into(),
    };

    expand(input, runtime).unwrap_or_else(syn::Error::into_compile_error).into()
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
            format!("ProtoDecode requires a dependency on `miden-protobuf`: {error}"),
        )),
    }
}

fn expand(input: DeriveInput, runtime: TokenStream2) -> Result<TokenStream2> {
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            input.generics.span(),
            "ProtoDecode does not support generic Protobuf messages",
        ));
    }

    let config = DecodeConfig::parse(&input.attrs, input.ident.span())?;
    let fields = parse_fields(&input)?;
    let constructor_fields = config.constructor.fields()?;
    validate_handled_fields(
        &fields,
        &config.validators,
        &constructor_fields,
        config.constructor.span(),
    )?;
    validate_field_decoders(&fields, &config.field_decoders, &constructor_fields)?;
    validate_oneof_mappings(&fields, &config.oneofs, &constructor_fields)?;

    let source = &input.ident;
    let target = &config.target;
    let validate_fields = config.validators.iter().map(|validator| validator.expression(&runtime));
    let decode_fields = constructor_fields
        .iter()
        .map(|field_name| {
            let name = ident_name(field_name);
            let field = fields.get(&name).expect("validated constructor field must exist");
            let field_decoder = config
                .field_decoders
                .iter()
                .find(|field_decoder| ident_name(&field_decoder.field) == name);
            let oneof = config.oneofs.iter().find(|oneof| ident_name(&oneof.field) == name);
            field.decoder(source, &runtime, field_decoder, oneof)
        })
        .collect::<Result<Vec<_>>>()?;
    let construct = config.constructor.expression(&runtime);

    Ok(quote! {
        impl ::core::convert::TryFrom<#source> for #target {
            type Error = #runtime::ConversionError;

            fn try_from(message: #source) -> ::core::result::Result<Self, Self::Error> {
                #(#validate_fields)*
                #(#decode_fields)*
                #construct
            }
        }
    })
}

struct DecodeConfig {
    target: Type,
    validators: Vec<FieldValidator>,
    field_decoders: Vec<FieldDecoder>,
    oneofs: Vec<OneofMapping>,
    constructor: Constructor,
}

impl DecodeConfig {
    fn parse(attributes: &[Attribute], span: Span) -> Result<Self> {
        let mut target = None;
        let mut validators = Vec::new();
        let mut field_decoders = Vec::new();
        let mut oneofs = Vec::new();
        let mut constructor = None;
        let mut found_attribute = false;

        for attribute in
            attributes.iter().filter(|attribute| attribute.path().is_ident("proto_decode"))
        {
            if found_attribute {
                return Err(syn::Error::new(
                    attribute.span(),
                    "duplicate `proto_decode` attribute",
                ));
            }
            found_attribute = true;

            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("target") {
                    if target.is_some() {
                        return Err(meta.error("duplicate `target` setting"));
                    }
                    let content;
                    parenthesized!(content in meta.input);
                    target = Some(content.parse()?);
                    return Ok(());
                }

                if meta.path.is_ident("decode") {
                    let content;
                    parenthesized!(content in meta.input);
                    let field = content.call(Ident::parse_any)?;
                    content.parse::<Token![,]>()?;
                    let decoder = content.parse()?;
                    if !content.is_empty() {
                        return Err(content.error("unexpected tokens after field decoder path"));
                    }
                    field_decoders.push(FieldDecoder { field, decoder });
                    return Ok(());
                }

                if meta.path.is_ident("validate") {
                    let content;
                    parenthesized!(content in meta.input);
                    let field = content.call(Ident::parse_any)?;
                    content.parse::<Token![,]>()?;
                    let validator = content.parse()?;
                    if !content.is_empty() {
                        return Err(content.error("unexpected tokens after validator path"));
                    }
                    validators.push(FieldValidator { field, validator });
                    return Ok(());
                }

                if meta.path.is_ident("oneof") {
                    let content;
                    parenthesized!(content in meta.input);
                    let field = content.call(Ident::parse_any)?;
                    content.parse::<Token![,]>()?;

                    let mut variants = Vec::new();
                    while !content.is_empty() {
                        let variant = content.call(Ident::parse_any)?;
                        content.parse::<Token![=>]>()?;
                        let constructor = content.parse()?;
                        variants.push(OneofVariantMapping { variant, constructor });

                        if !content.is_empty() {
                            content.parse::<Token![,]>()?;
                        }
                    }
                    if variants.is_empty() {
                        return Err(content.error("configure at least one oneof variant"));
                    }
                    oneofs.push(OneofMapping { field, variants });
                    return Ok(());
                }

                let kind = if meta.path.is_ident("constructor") {
                    ConstructorKind::Infallible
                } else if meta.path.is_ident("try_constructor") {
                    ConstructorKind::Fallible
                } else {
                    return Err(meta.error(
                        "expected `target`, `validate`, `decode`, `oneof`, `constructor`, or \
                         `try_constructor`",
                    ));
                };
                if constructor.is_some() {
                    return Err(meta.error("configure exactly one constructor"));
                }
                let content;
                parenthesized!(content in meta.input);
                constructor = Some(Constructor { expression: content.parse()?, kind });
                Ok(())
            })?;
        }

        if !found_attribute {
            return Err(syn::Error::new(span, "missing `proto_decode` attribute"));
        }

        Ok(Self {
            target: target.ok_or_else(|| syn::Error::new(span, "missing `target` setting"))?,
            validators,
            field_decoders,
            oneofs,
            constructor: constructor
                .ok_or_else(|| syn::Error::new(span, "missing constructor setting"))?,
        })
    }
}

struct FieldDecoder {
    field: Ident,
    decoder: Path,
}

struct OneofMapping {
    field: Ident,
    variants: Vec<OneofVariantMapping>,
}

impl OneofMapping {
    fn decoder(&self, source: &Ident, source_path: &Path, runtime: &TokenStream2) -> TokenStream2 {
        let field = &self.field;
        let field_name = LitStr::new(&ident_name(field), field.span());
        let arms = self.variants.iter().map(|mapping| {
            let variant = &mapping.variant;
            let variant_name =
                LitStr::new(&ident_name(variant).to_snake_case(), mapping.variant.span());
            let constructor = &mapping.constructor;

            quote! {
                #source_path::#variant(value) => {
                    let value = #runtime::decode(
                        #runtime::ValueField::new(#variant_name, value),
                    )
                    .map_err(|error| error.context(#field_name))?;
                    #constructor(value)
                }
            }
        });

        quote! {
            let #field = match message.#field
                .ok_or_else(|| #runtime::ConversionError::missing_field::<#source>(#field_name))
                .map_err(|error| error.context(#field_name))?
            {
                #(#arms),*
            };
        }
    }
}

struct OneofVariantMapping {
    variant: Ident,
    constructor: Path,
}

struct FieldValidator {
    field: Ident,
    validator: Path,
}

impl FieldValidator {
    fn expression(&self, runtime: &TokenStream2) -> TokenStream2 {
        let field = &self.field;
        let name = LitStr::new(&ident_name(field), field.span());
        let validator = &self.validator;

        quote! {
            let _: () = (#validator)(message.#field)
                .map_err(#runtime::ConversionError::new)
                .map_err(|error| error.context(#name))?;
        }
    }
}

struct Constructor {
    expression: Expr,
    kind: ConstructorKind,
}

impl Constructor {
    fn fields(&self) -> Result<Vec<Ident>> {
        if let Expr::Path(path) = &self.expression {
            if matches!(self.kind, ConstructorKind::Fallible) {
                return Err(syn::Error::new(
                    path.span(),
                    "`try_constructor` requires a function call",
                ));
            }
            if path.qself.is_none()
                && path.path.leading_colon.is_none()
                && path.path.segments.len() == 1
            {
                return Ok(vec![path.path.segments[0].ident.clone()]);
            }
        }

        let arguments = match &self.expression {
            Expr::Call(call) => &call.args,
            Expr::Tuple(tuple) if matches!(self.kind, ConstructorKind::Infallible) => &tuple.elems,
            Expr::Tuple(tuple) => {
                return Err(syn::Error::new(
                    tuple.span(),
                    "`try_constructor` requires a function call",
                ));
            },
            expression => {
                return Err(syn::Error::new(
                    expression.span(),
                    "constructor must be a function call, tuple expression, or bare Protobuf \
                     field name",
                ));
            },
        };

        arguments
            .iter()
            .map(|argument| match argument {
                Expr::Path(path)
                    if path.qself.is_none()
                        && path.path.leading_colon.is_none()
                        && path.path.segments.len() == 1 =>
                {
                    Ok(path.path.segments[0].ident.clone())
                },
                _ => Err(syn::Error::new(
                    argument.span(),
                    "constructor arguments must be bare Protobuf field names",
                )),
            })
            .collect()
    }

    fn expression(&self, runtime: &TokenStream2) -> TokenStream2 {
        let expression = &self.expression;
        match self.kind {
            ConstructorKind::Infallible => quote!(::core::result::Result::Ok(#expression)),
            ConstructorKind::Fallible => {
                quote!((#expression).map_err(#runtime::ConversionError::new))
            },
        }
    }

    fn span(&self) -> Span {
        self.expression.span()
    }
}

#[derive(Clone, Copy)]
enum ConstructorKind {
    Infallible,
    Fallible,
}

fn parse_fields(input: &DeriveInput) -> Result<BTreeMap<String, ProtoField>> {
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(input.ident.span(), "ProtoDecode only supports structs"));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new(data.fields.span(), "ProtoDecode requires named fields"));
    };

    fields
        .named
        .iter()
        .map(|field| {
            let field = ProtoField::parse(field)?;
            Ok((ident_name(&field.ident), field))
        })
        .collect()
}

fn validate_handled_fields(
    fields: &BTreeMap<String, ProtoField>,
    validators: &[FieldValidator],
    constructor_fields: &[Ident],
    span: Span,
) -> Result<()> {
    let mut configured = BTreeSet::new();
    for validator in validators {
        let name = ident_name(&validator.field);
        if !configured.insert(name.clone()) {
            return Err(syn::Error::new(
                validator.field.span(),
                format!("field `{name}` is used twice"),
            ));
        }
        if !fields.contains_key(&name) {
            return Err(syn::Error::new(
                validator.field.span(),
                format!("validator references unknown field `{name}`"),
            ));
        }
    }

    for field in constructor_fields {
        let name = ident_name(field);
        if !configured.insert(name.clone()) {
            return Err(syn::Error::new(field.span(), format!("field `{name}` is used twice")));
        }
        if !fields.contains_key(&name) {
            return Err(syn::Error::new(
                field.span(),
                format!("constructor references unknown field `{name}`"),
            ));
        }
    }

    let missing: Vec<_> =
        fields.keys().filter(|field| !configured.contains(*field)).cloned().collect();
    if !missing.is_empty() {
        return Err(syn::Error::new(
            span,
            format!("constructor does not handle fields: {}", missing.join(", ")),
        ));
    }

    Ok(())
}

fn validate_oneof_mappings(
    fields: &BTreeMap<String, ProtoField>,
    mappings: &[OneofMapping],
    constructor_fields: &[Ident],
) -> Result<()> {
    let constructor_fields: BTreeSet<_> = constructor_fields.iter().map(ident_name).collect();
    let mut configured = BTreeSet::new();

    for mapping in mappings {
        let name = ident_name(&mapping.field);
        if !configured.insert(name.clone()) {
            return Err(syn::Error::new(
                mapping.field.span(),
                format!("oneof field `{name}` is configured twice"),
            ));
        }

        let Some(field) = fields.get(&name) else {
            return Err(syn::Error::new(
                mapping.field.span(),
                format!("oneof mapping references unknown field `{name}`"),
            ));
        };
        if !matches!(&field.kind, FieldKind::Oneof(_)) {
            return Err(syn::Error::new(
                mapping.field.span(),
                format!("field `{name}` is not a oneof"),
            ));
        }
        if !constructor_fields.contains(&name) {
            return Err(syn::Error::new(
                mapping.field.span(),
                format!("oneof field `{name}` is not used by the constructor"),
            ));
        }

        let mut variants = BTreeSet::new();
        for variant in &mapping.variants {
            let name = ident_name(&variant.variant);
            if !variants.insert(name.clone()) {
                return Err(syn::Error::new(
                    variant.variant.span(),
                    format!("oneof variant `{name}` is configured twice"),
                ));
            }
        }
    }

    for name in constructor_fields {
        let field = fields.get(&name).expect("validated constructor field must exist");
        if matches!(&field.kind, FieldKind::Oneof(_)) && !configured.contains(&name) {
            return Err(syn::Error::new(
                field.ident.span(),
                format!("oneof field `{name}` requires an explicit variant mapping"),
            ));
        }
    }

    Ok(())
}

fn validate_field_decoders(
    fields: &BTreeMap<String, ProtoField>,
    decoders: &[FieldDecoder],
    constructor_fields: &[Ident],
) -> Result<()> {
    let constructor_fields: BTreeSet<_> = constructor_fields.iter().map(ident_name).collect();
    let mut configured = BTreeSet::new();

    for decoder in decoders {
        let name = ident_name(&decoder.field);
        if !configured.insert(name.clone()) {
            return Err(syn::Error::new(
                decoder.field.span(),
                format!("field `{name}` has multiple decoders"),
            ));
        }

        let Some(field) = fields.get(&name) else {
            return Err(syn::Error::new(
                decoder.field.span(),
                format!("decoder references unknown field `{name}`"),
            ));
        };
        if matches!(&field.kind, FieldKind::Oneof(_)) {
            return Err(syn::Error::new(
                decoder.field.span(),
                format!("oneof field `{name}` must use a variant mapping"),
            ));
        }
        if !constructor_fields.contains(&name) {
            return Err(syn::Error::new(
                decoder.field.span(),
                format!("decoded field `{name}` is not used by the constructor"),
            ));
        }
    }

    Ok(())
}

struct ProtoField {
    ident: Ident,
    kind: FieldKind,
}

impl ProtoField {
    fn parse(field: &Field) -> Result<Self> {
        let ident = field
            .ident
            .clone()
            .ok_or_else(|| syn::Error::new(field.span(), "ProtoDecode requires named fields"))?;
        let prost = ProstField::parse(field)?;
        let override_kind = FieldKindOverride::parse(&field.attrs)?;
        let kind = override_kind.map(FieldKind::from).unwrap_or_else(|| prost.kind());

        Ok(Self { ident, kind })
    }

    fn decoder(
        &self,
        source: &Ident,
        runtime: &TokenStream2,
        field_decoder: Option<&FieldDecoder>,
        oneof: Option<&OneofMapping>,
    ) -> Result<TokenStream2> {
        let ident = &self.ident;
        let name = LitStr::new(&ident_name(ident), ident.span());

        let decode = match &self.kind {
            FieldKind::Required => quote! {
                #runtime::decode(
                    #runtime::RequiredField::<#source, _>::new(#name, message.#ident),
                )
            },
            FieldKind::Optional => quote! {
                #runtime::decode(
                    #runtime::OptionalField::new(#name, message.#ident),
                )
            },
            FieldKind::Repeated => quote! {
                #runtime::decode(
                    #runtime::RepeatedField::new(#name, message.#ident),
                )
            },
            FieldKind::Value => quote! {
                #runtime::decode(
                    #runtime::ValueField::new(#name, message.#ident),
                )
            },
            FieldKind::Oneof(source_path) => {
                return Ok(oneof.expect("validated oneof field must have a mapping").decoder(
                    source,
                    source_path,
                    runtime,
                ));
            },
        };

        if let Some(field_decoder) = field_decoder {
            let decoder = &field_decoder.decoder;
            Ok(quote! {
                let #ident = (#decoder)(#decode?)
                    .map_err(#runtime::ConversionError::new)
                    .map_err(|error| error.context(#name))?;
            })
        } else {
            Ok(quote! {
                let #ident = #decode?;
            })
        }
    }
}

fn ident_name(ident: &Ident) -> String {
    ident.unraw().to_string()
}

enum FieldKind {
    Required,
    Optional,
    Repeated,
    Value,
    Oneof(Path),
}

struct ProstField {
    message: bool,
    optional: bool,
    repeated: bool,
    oneof: Option<Path>,
}

impl ProstField {
    fn parse(field: &Field) -> Result<Self> {
        let mut parsed = Self {
            message: false,
            optional: false,
            repeated: false,
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

                parsed.message |= meta.path.is_ident("message");
                parsed.optional |= meta.path.is_ident("optional");
                parsed.repeated |= meta.path.is_ident("repeated");

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

    fn kind(&self) -> FieldKind {
        if let Some(path) = &self.oneof {
            FieldKind::Oneof(path.clone())
        } else if self.repeated {
            FieldKind::Repeated
        } else if self.message {
            FieldKind::Required
        } else if self.optional {
            FieldKind::Optional
        } else {
            FieldKind::Value
        }
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

impl From<FieldKindOverride> for FieldKind {
    fn from(value: FieldKindOverride) -> Self {
        match value {
            FieldKindOverride::Required => Self::Required,
            FieldKindOverride::Optional => Self::Optional,
        }
    }
}

#[cfg(test)]
mod tests {
    use proc_macro2::TokenStream;
    use quote::quote;
    use syn::{DeriveInput, parse2};

    use super::expand;

    fn expand_input(input: TokenStream) -> syn::Result<String> {
        let input: DeriveInput = parse2(input)?;
        expand(input, quote!(::runtime)).map(|tokens| tokens.to_string())
    }

    #[test]
    fn generates_decoders_in_constructor_order() {
        let generated = expand_input(quote! {
            #[proto_decode(
                target(::domain::Example),
                try_constructor(::domain::Example::new(count, required_message, optional_value, items))
            )]
            struct ExampleMessage {
                #[prost(message, optional, tag = "1")]
                required_message: Option<Message>,
                #[prost(message, repeated, tag = "2")]
                items: Vec<Message>,
                #[prost(uint32, optional, tag = "3")]
                optional_value: Option<u32>,
                #[prost(uint32, tag = "4")]
                count: u32,
            }
        })
        .unwrap();

        let count = generated.find("let count").unwrap();
        let required = generated.find("let required_message").unwrap();
        let optional = generated.find("let optional_value").unwrap();
        let items = generated.find("let items").unwrap();
        assert!(count < required && required < optional && optional < items);
        assert!(generated.contains("ValueField :: new (\"count\""));
        assert!(generated.contains("RequiredField :: < ExampleMessage , _ > :: new"));
        assert!(generated.contains("OptionalField :: new (\"optional_value\""));
        assert!(generated.contains("RepeatedField :: new (\"items\""));
    }

    #[test]
    fn generates_validators_before_constructor_field_decoders() {
        let generated = expand_input(quote! {
            #[proto_decode(
                target(::domain::Example),
                validate(version, ::domain::validate_version),
                try_constructor(::domain::Example::new(required_message))
            )]
            struct ExampleMessage {
                #[prost(uint32, tag = "1")]
                version: u32,
                #[prost(message, optional, tag = "2")]
                required_message: Option<Message>,
            }
        })
        .unwrap();

        let validator = generated.find("validate_version").unwrap();
        let decoder = generated.find("let required_message").unwrap();
        assert!(validator < decoder);
        assert!(generated.contains("message . version"));
        assert!(generated.contains("error . context (\"version\")"));
    }

    #[test]
    fn generates_fallible_field_decoders_after_cardinality_decoding() {
        let generated = expand_input(quote! {
            #[proto_decode(
                target(::domain::Example),
                decode(count, ::domain::decode_count),
                constructor(::domain::Example::new(count))
            )]
            struct ExampleMessage {
                #[prost(uint32, tag = "1")]
                count: u32,
            }
        })
        .unwrap();

        assert!(generated.contains("domain :: decode_count"));
        assert!(generated.contains("ValueField :: new (\"count\" , message . count)"));
        assert!(generated.contains("error . context (\"count\")"));
    }

    #[test]
    fn rejects_duplicate_field_decoders() {
        let error = expand_input(quote! {
            #[proto_decode(
                target(::domain::Example),
                decode(count, ::domain::decode_count),
                decode(count, ::domain::decode_count_again),
                constructor(::domain::Example::new(count))
            )]
            struct ExampleMessage {
                #[prost(uint32, tag = "1")]
                count: u32,
            }
        })
        .unwrap_err();

        assert_eq!(error.to_string(), "field `count` has multiple decoders");
    }

    #[test]
    fn rejects_fields_used_by_both_validator_and_constructor() {
        let error = expand_input(quote! {
            #[proto_decode(
                target(::domain::Example),
                validate(version, ::domain::validate_version),
                constructor(::domain::Example::new(version))
            )]
            struct ExampleMessage {
                #[prost(uint32, tag = "1")]
                version: u32,
            }
        })
        .unwrap_err();

        assert_eq!(error.to_string(), "field `version` is used twice");
    }

    #[test]
    fn generates_tuple_constructors_in_element_order() {
        let generated = expand_input(quote! {
            #[proto_decode(
                target((u16, ::domain::Message)),
                constructor((count, required_message))
            )]
            struct ExampleMessage {
                #[prost(message, optional, tag = "1")]
                required_message: Option<Message>,
                #[prost(uint32, tag = "2")]
                count: u32,
            }
        })
        .unwrap();

        let count = generated.find("let count").unwrap();
        let required = generated.find("let required_message").unwrap();
        assert!(count < required);
        assert!(generated.contains("Result :: Ok ((count , required_message))"));
    }

    #[test]
    fn generates_exhaustive_oneof_variant_mappings() {
        let generated = expand_input(quote! {
            #[proto_decode(
                target(::domain::Choice),
                oneof(
                    choice,
                    First => ::domain::Choice::First,
                    Second => ::domain::Choice::Second
                ),
                constructor(choice)
            )]
            struct ExampleMessage {
                #[prost(oneof = "choice::Value", tags = "1, 2")]
                choice: Option<choice::Value>,
            }
        })
        .unwrap();

        assert!(generated.contains("choice :: Value :: First (value)"));
        assert!(generated.contains("domain :: Choice :: First (value)"));
        assert!(generated.contains("choice :: Value :: Second (value)"));
        assert!(generated.contains("domain :: Choice :: Second (value)"));
        assert!(generated.contains("error . context (\"choice\")"));
        assert!(generated.contains("ValueField :: new (\"first"));
        assert!(generated.contains("Result :: Ok (choice)"));
    }

    #[test]
    fn rejects_fallible_tuple_constructors() {
        let error = expand_input(quote! {
            #[proto_decode(
                target((u16, u16)),
                try_constructor((first, second))
            )]
            struct ExampleMessage {
                #[prost(uint32, tag = "1")]
                first: u32,
                #[prost(uint32, tag = "2")]
                second: u32,
            }
        })
        .unwrap_err();

        assert_eq!(error.to_string(), "`try_constructor` requires a function call");
    }

    #[test]
    fn rejects_non_exhaustive_constructors() {
        let error = expand_input(quote! {
            #[proto_decode(
                target(::domain::Example),
                constructor(::domain::Example::new(first))
            )]
            struct ExampleMessage {
                #[prost(uint32, tag = "1")]
                first: u32,
                #[prost(uint32, tag = "2")]
                second: u32,
            }
        })
        .unwrap_err();

        assert_eq!(error.to_string(), "constructor does not handle fields: second");
    }

    #[test]
    fn rejects_oneof_fields_without_variant_mappings() {
        let error = expand_input(quote! {
            #[proto_decode(
                target(::domain::Example),
                constructor(::domain::Example::new(choice))
            )]
            struct ExampleMessage {
                #[prost(oneof = "choice::Value", tags = "1")]
                choice: Option<choice::Value>,
            }
        })
        .unwrap_err();

        assert_eq!(error.to_string(), "oneof field `choice` requires an explicit variant mapping");
    }

    #[test]
    fn rejects_duplicate_oneof_variant_mappings() {
        let error = expand_input(quote! {
            #[proto_decode(
                target(::domain::Choice),
                oneof(
                    choice,
                    First => ::domain::Choice::First,
                    First => ::domain::Choice::OtherFirst
                ),
                constructor(choice)
            )]
            struct ExampleMessage {
                #[prost(oneof = "choice::Value", tags = "1")]
                choice: Option<choice::Value>,
            }
        })
        .unwrap_err();

        assert_eq!(error.to_string(), "oneof variant `First` is configured twice");
    }

    #[test]
    fn field_presence_can_be_overridden_when_prost_erases_it() {
        let generated = expand_input(quote! {
            #[proto_decode(
                target(::domain::Example),
                constructor(::domain::Example::new(value))
            )]
            struct ExampleMessage {
                #[prost(message, optional, tag = "1")]
                #[proto_decode(optional)]
                value: Option<Message>,
            }
        })
        .unwrap();

        assert!(generated.contains("OptionalField :: new (\"value\""));
    }
}
