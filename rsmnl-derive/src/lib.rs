#![recursion_limit="256"]

extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate syn;

use proc_macro2:: { Span, TokenStream };
use quote:: { quote, ToTokens };
use syn:: {
    Lit, Data, Result, DeriveInput, Error, Ident, Attribute, Meta, Token, Type, TypeArray, TypePath,
    token,
    parse::{
        Parse, ParseStream,
    }
};

#[proc_macro_derive(NlaType, attributes(tbname, nla_type, nla_nest))]
pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    _derive(input)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

fn _derive(input: DeriveInput) -> Result<TokenStream> {
    let data = match &input.data {
        Data::Enum(d) => d,
        _ => return Err(Error::new(Span::call_site(), "expected enum")),
    };

    let ident = &input.ident;
    let mut ret = quote! {
        impl std::convert::TryFrom<u16> for #ident {
            type Error = Errno;

            fn try_from(v: u16) -> std::result::Result<Self, Self::Error> {
                if v >= Self::_MAX as u16 {
                    Err(Errno(libc::ERANGE))
                } else {
                    unsafe { Ok(::std::mem::transmute::<u16, Self>(v)) }
                }
            }
        }
        impl std::convert::Into<usize> for #ident {
            fn into(self) -> usize {
                self as usize
            }
        }
        impl std::convert::Into<u16> for #ident {
            fn into(self) -> u16 {
                self as u16
            }
        }
    };

    let mut getfns: Vec<TokenStream> = Vec::new();
    let mut putfns: Vec<TokenStream> = Vec::new();
    for var in data.variants.iter() {
        for attr in var.attrs.iter() {
            if let Some((getfn, putfn)) = parse_var_attr(&ident, &var.ident, attr)?  {
                getfns.push(getfn);
                putfns.push(putfn);
            }
        }
    }

    if putfns.len() > 0 {
        ret = quote! {
            #ret
            impl #ident {
                #(#putfns)*
            }
        };
    }

    let tb_idents: Vec<_> = input.attrs.iter()
        .map(|attr| { parse_attr(attr).ok()? })
        .filter(|x| { x.is_some() })
        .map(|x| x.unwrap())
        .collect();
    if tb_idents.len() == 0 {
        return Ok(ret);
    }

    // XXX: should check multiple tbname specified
    let tbid = &tb_idents[0];
    ret = quote! {
        #ret
        pub struct #tbid<'a> ([Option<&'a Attr<'a>>; #ident::_MAX as usize]);
        impl <'a> std::ops::Index<#ident> for #tbid<'a> {
            type Output = Option<&'a Attr<'a>>;

            fn index(&self, a: #ident) -> &Self::Output {
                &self.0[a as usize]
            }
        }
        impl <'a> std::ops::IndexMut<#ident> for #tbid<'a> {
            fn index_mut(&mut self, a: #ident) -> &mut Self::Output {
                &mut self.0[a as usize]
            }
        }
        impl <'a> AttrTbl<'a> for #tbid<'a> {
            type Index = #ident;
            fn new() -> Self {
                // Self(Default::default())
                Self([None; #ident::_MAX as usize])
            }
            fn _set(&mut self, i: #ident, attr: &'a Attr) {
                self[i] = Some(attr);
            }
        }
    };

    if getfns.len() == 0 {
        return Ok(ret);
    }

    return Ok(quote! {
        #ret
        impl <'a> #tbid<'a> {
            #(#getfns)*
        }
    });
}

fn parse_attr(attr: &Attribute) -> Result<Option<Ident>> {
    match &attr.path {
        path if path.is_ident("nla_type") => {
            return Err(Error::new_spanned(attr, "#[nla_ ...] is specified on variant"));
        },
        path if path.is_ident("nla_nest") => {
            return Err(Error::new_spanned(attr, "#[nla_ ...] is specified on variant"));
        },
        path if path.is_ident("tbname") => {
            match attr.parse_meta()? {
                Meta::NameValue(nv) => {
                    match nv.lit {
                        Lit::Str(lit_str) => {
                            return Ok(Some(Ident::new(&lit_str.value(), Span::call_site())));
                        },
                        _ => {
                            return Err(Error::new_spanned(attr, "#[tbname] must be a string"));
                        }
                    }
                },
                _ => {
                    return Err(Error::new_spanned(attr, "#[tbname] must be a name-value"));
                }
            }
        },
        _ => return Ok(None),
    }
}

fn parse_var_attr(ei: &Ident, vi: &Ident, attr: &Attribute) -> Result<Option<(TokenStream, TokenStream)>> {
    if attr.path.is_ident("nla_type") {
        parse_type_attr(ei, vi, attr)
    } else if attr.path.is_ident("nla_nest") {
        parse_nest_attr(ei, vi, attr)
    } else {
        // XXX: ignore tbname
        Ok(None)
    }
}

fn parse_type_attr(ei: &Ident, vi: &Ident, attr: &Attribute) -> Result<Option<(TokenStream, TokenStream)>> {
    #[derive(Debug)]
    enum SigType {
        Id(Ident),
        Str,
        NulStr,
        Bytes,
        Array(TypeArray),
        Path(TypePath),
        // Flag
    }
    impl ToTokens for SigType {
        fn to_tokens(&self, tokens: &mut TokenStream) {
            match self {
                Self::Id(i) => i.to_tokens(tokens),
                Self::Str => "str".to_tokens(tokens),
                Self::NulStr => "strz".to_tokens(tokens),
                Self::Bytes => "bytes".to_tokens(tokens),
                Self::Array(a) => a.to_tokens(tokens),
                Self::Path(p) => p.to_tokens(tokens),
            }
        }
    }
    impl Parse for SigType {
        fn parse(input: ParseStream) -> Result<Self> {
            if input.peek(token::Bracket) || input.peek2(Token![:]) {
                match input.parse::<Type>()? {
                    Type::Array(t) => return Ok(Self::Array(t)),
                    Type::Path(t) => return Ok(Self::Path(t)),
                    _ => return Err(input.error("expected identifier, array type or TypePath"))
                };
            }
            match input.parse::<Ident>()? {
                s if s == "bytes" => { Ok(Self::Bytes) },
                s if s == "str" => { Ok(Self::Str) },
                s if s == "nulstr" => { Ok(Self::NulStr) },
                s @ _ => Ok(Self::Id(s))
            }
        }
    }

    #[derive(Debug)]
    struct Signature {
        rtype: SigType,
        name: Ident,
    }
    impl Parse for Signature {
        fn parse(input: ParseStream) -> Result<Self> {
            let rtype = input.parse()?;
            input.parse::<Token![,]>()?;
            let name = input.parse()?;
            Ok(Signature {
                rtype: rtype,
                name: name
            })
        }
    }

    let args = attr.parse_args::<Signature>()?;
    let name = args.name;
    let pushfn = Ident::new(&format!("push_{}", name), Span::call_site());
    let tid = args.rtype;
    match tid {
        SigType::Str => Ok(Some((
            quote! {
                pub fn #name(&self) -> Result<Option<&str>> {
                    if let Some(attr) = self[#ei::#vi] {
                        Ok(Some(attr.str_ref()?))
                    } else {
                        Ok(None)
                    }
                }
            },
            quote! {
                pub fn #pushfn<'a>(nlv: &'a mut MsgVec, data: &str) -> Result<&'a mut MsgVec> {
                    nlv.push_str(#ei::#vi, data)
                }
            }
        ))),
        SigType::NulStr => Ok(Some((
            quote! {
                pub fn #name(&self) -> Result<Option<&str>> {
                    if let Some(attr) = self[#ei::#vi] {
                        Ok(Some(attr.strz_ref()?))
                    } else {
                        Ok(None)
                    }
                }
            },
            quote! {
                pub fn #pushfn<'a>(nlv: &'a mut MsgVec, data: &str) -> Result<&'a mut MsgVec> {
                    nlv.push_strz(#ei::#vi, data)
                }
            }
        ))),
        SigType::Bytes => Ok(Some((
            quote! {
                pub fn #name(&self) -> Result<Option<&[u8]>> {
                    if let Some(attr) = self[#ei::#vi] {
                        Ok(Some(attr.bytes_ref()))
                    } else {
                        Ok(None)
                    }
                }
            },
            quote! {
                pub fn #pushfn<'a>(nlv: &'a mut MsgVec, data: &[u8]) -> Result<&'a mut MsgVec> {
                    nlv.push_bytes(#ei::#vi, data)
                }
            }
        ))),
        SigType::Id(_) | SigType::Array(_) | SigType::Path(_) =>
            Ok(Some((
            quote! {
                pub fn #name(&self) -> Result<Option<&#tid>> {
                    if let Some(attr) = self[#ei::#vi] {
                        Ok(Some(attr.value_ref::<#tid>()?))
                    } else {
                        Ok(None)
                    }
                }
            },
            quote! {
                pub fn #pushfn<'a>(nlv: &'a mut MsgVec, data: &#tid) -> Result<&'a mut MsgVec> {
                    nlv.push(#ei::#vi, data)
                }
            }
        ))),
    }
}

fn parse_nest_attr(ei: &Ident, vi: &Ident, attr: &Attribute) -> Result<Option<(TokenStream, TokenStream)>> {
    #[derive(Debug)]
    enum SigType {
        Id(Ident),
        Path(TypePath),
        ArrayId(Ident),
        ArrayPath(TypePath),
    }
    impl Parse for SigType {
        fn parse(input: ParseStream) -> Result<Self> {
            if input.peek(token::Bracket) {
                let content;
                let _bracket_token = syn::bracketed!(content in input);
                if content.peek2(Token![:]) {
                    return Ok(Self::ArrayPath(content.parse::<TypePath>()?));
                }
                match content.parse::<Ident>() {
                    Ok(t)=> return Ok(Self::ArrayId(t)),
                    Err(_) => return Err(input.error("expected identifier or TypePath"))
                }
            } else {
                if input.peek2(Token![:]) {
                    return Ok(Self::Path(input.parse::<TypePath>()?));
                }
                match input.parse::<Ident>() {
                    Ok(t)=> return Ok(Self::Id(t)),
                    Err(_) => return Err(input.error("expected identifier or TypePath"))
                }
            }
        }
    }
    impl ToTokens for SigType {
        fn to_tokens(&self, tokens: &mut TokenStream) {
            match self {
                Self::Id(i) | Self::ArrayId(i) => i.to_tokens(tokens),
                Self::Path(p) | Self::ArrayPath(p) => p.to_tokens(tokens),
            }
        }
    }

    struct Signature {
        rtype: SigType,
        name: Ident,
    }
    impl Parse for Signature {
        fn parse(input: ParseStream) -> Result<Self> {
            let rtype = input.parse()?;
            input.parse::<Token![,]>()?;
            let name = input.parse()?;
            Ok(Signature {
                rtype: rtype,
                name: name
            })
        }
    }

    let args = attr.parse_args::<Signature>()?;
    let name = args.name;
    let tid = args.rtype;
    let startfn = Ident::new(&format!("{}_start", name), Span::call_site());
    match tid {
        SigType::ArrayId(_) | SigType::ArrayPath(_) =>
            Ok(Some((
                quote! {
                    pub fn #name(&self) -> Result<Option<Vec<#tid>>> {
                        if let Some(attr) = self[#ei::#vi] {
                            Ok(Some(attr.nest_array::<#tid>()?))
                        } else {
                            Ok(None)
                        }
                    }
                },
                quote! {
                    pub fn #startfn(nlv: &mut MsgVec) -> Result<&mut MsgVec> {
                        nlv.nest_start(#ei::#vi)
                    }
                }
            ))),
        SigType::Id(_) | SigType::Path(_) =>
            Ok(Some((
                quote! {
                    pub fn #name(&self) -> Result<Option<#tid>> {
                        if let Some(attr) = self[#ei::#vi] {
                            Ok(Some(#tid::from_nest(attr)?))
                        } else {
                            Ok(None)
                        }
                    }
                },
                quote! {
                    pub fn #startfn(nlv: &mut MsgVec) -> Result<&mut MsgVec> {
                        nlv.nest_start(#ei::#vi)
                    }
                }
            )))
    }
}
