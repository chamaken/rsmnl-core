#![recursion_limit="256"]

extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate syn;

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    Lit, Data, Result, DeriveInput, Error, Ident, Attribute, Meta, Token, TypeArray,
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
        impl <'a> AttrTbl<'a, #ident> for #tbid<'a> {
            fn new() -> Self {
                // Self(Default::default())
                Self([None; #ident::_MAX as usize])
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
        Bytes,
        Array(TypeArray)
    }
    impl Parse for SigType {
        fn parse(input: ParseStream) -> Result<Self> {
            let lookahead = input.lookahead1();
            if lookahead.peek(Ident) {
                return Ok(match input.parse::<Ident>().unwrap() {
                    s if s == "bytes" => { Self::Bytes },
                    s if s == "str" => { Self::Str },
                    s @ _ => Self::Id(s)
                })
            }
            match input.parse::<TypeArray>() {
                Ok(t) => Ok(Self::Array(t)),
                Err(_) => Err(input.error("expected identifier or array type"))
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
    let putfn = Ident::new(&format!("put_{}", name), Span::call_site());
    match args.rtype {
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
                pub fn #putfn<'a, 'b>(nlh: &'a mut Msghdr<'b>, data: &str) -> Result<&'a mut Msghdr<'b>> {
                    nlh.put_str(#ei::#vi, data)
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
                pub fn #putfn<'a, 'b>(nlh: &'a mut Msghdr<'b>, data: &[u8]) -> Result<&'a mut Msghdr<'b>> {
                    nlh.put_bytes(#ei::#vi, data)
                }
            }
        ))),
        SigType::Id(tid) => Ok(Some((
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
                pub fn #putfn<'a, 'b>(nlh: &'a mut Msghdr<'b>, data: &#tid) -> Result<&'a mut Msghdr<'b>> {
                    nlh.put(#ei::#vi, data)
                }
            }
        ))),
        SigType::Array(tid) => Ok(Some(( // XXX: just same as below
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
                pub fn #putfn<'a, 'b>(nlh: &'a mut Msghdr<'b>, data: &#tid) -> Result<&'a mut Msghdr<'b>> {
                    nlh.put(#ei::#vi, data)
                }
            }
        ))),
    }
}

fn parse_nest_attr(ei: &Ident, vi: &Ident, attr: &Attribute) -> Result<Option<(TokenStream, TokenStream)>> {
    #[derive(Debug)]
    struct Signature {
        rtype: Ident,
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
            pub fn #startfn<'b>(nlh: &'b mut Msghdr<'b>) -> Result<&'b mut Attr<'b>> {
                nlh.nest_start(#ei::#vi)
            }
        }
    )))
}
