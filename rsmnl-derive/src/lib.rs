#![recursion_limit="256"]

extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate syn;

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{Lit, Data, Result, DeriveInput, Error, Ident, Attribute, Meta, NestedMeta};

#[proc_macro_derive(NlaType, attributes(tbname, nla_type, nla_nest))]
pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
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
    let impl_enum = quote! {
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

    let tb_idents: Vec<_> = input.attrs.iter()
        .map(|attr| { parse_attr(attr).ok()? })
        .filter(|x| { x.is_some() })
        .map(|x| x.unwrap())
        .collect();

    if tb_idents.len() == 0 {
        return Ok(impl_enum);
    }
    // XXX: should check multiple tbname specified
    let tbid = &tb_idents[0];

    let impl_enum2 = quote! {
        #impl_enum
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
    let fns: Vec<TokenStream> = data.variants.iter()
        .map(|var| var.attrs.iter()
            .map(|attr| { parse_var_attr(&ident, &var.ident, attr).ok()? })
            .filter(|x| x.is_some())
            .map(|x| x.unwrap())
             .collect()
        ).collect();
    if fns.len() == 0 {
        return Ok(impl_enum2);
    }

    return Ok(quote! {
        #impl_enum2
        impl <'a> #tbid<'a> {
            #(#fns)*
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

fn extract_ident(nm: &NestedMeta) -> Result<&Ident> {
    match nm {
        NestedMeta::Meta(m) => match m {
            Meta::Path(p) =>
                Ok(&p.segments[0].ident),
            _ =>
                Err(Error::new(Span::call_site(), "not a Meta::Path"))
        },
        _ => Err(Error::new(Span::call_site(), "not a NestedMeta::Meta"))
    }
}

fn parse_var_attr(ei: &Ident, vi: &Ident, attr: &Attribute) -> Result<Option<TokenStream>> {
    let args = match attr.parse_meta()? {
        Meta::List(list) if list.nested.len() == 2 => list.nested,
        _ => {
            return Err(Error::new_spanned(attr, "#[nla_ ...] requires list with two elements"));
        }
    };
    let (tid, sid) = (extract_ident(&args[0])?, extract_ident(&args[1])?);
    if attr.path.is_ident("nla_type") {
        // XXX: messy part ;-(
        if tid.to_string() == "str" {
            return Ok(Some(quote! {
                pub fn #sid(&self) -> Result<Option<&str>> {
                    if let Some(attr) = self[#ei::#vi] {
                        Ok(Some(attr.str_ref()?))
                    } else {
                        Ok(None)
                    }
                }
            }))
        } else if tid.to_string() == "bytes" {
            return Ok(Some(quote! {
                pub fn #sid(&self) -> Result<Option<&[u8]>> {
                    if let Some(attr) = self[#ei::#vi] {
                        Ok(Some(attr.bytes_ref()))
                    } else {
                        Ok(None)
                    }
                }
            }))
        }

        let putfn = Ident::new(&format!("put_{}", sid), Span::call_site());
        return Ok(Some(quote! {
            pub fn #sid(&self) -> Result<Option<&#tid>> {
                if let Some(attr) = self[#ei::#vi] {
                    Ok(Some(attr.value_ref::<#tid>()?))
                } else {
                    Ok(None)
                }
            }
            pub fn #putfn<'b>(nlh: &'b mut Msghdr<'b>, data: &#tid) -> Result<&'b mut Msghdr<'b>> {
                // let attr = unsafe { nlh.payload_tail::<Attr>() };
                nlh.put(#ei::#vi, data)
                // .map(|| self[#ei::#vi] = Some(attr))
            }
        }))
    } else if attr.path.is_ident("nla_nest") {
        let startfn = Ident::new(&format!("{}_start", sid), Span::call_site());
        return Ok(Some(quote! {
            pub fn #sid(&self) -> Result<Option<#tid>> {
                if let Some(attr) = self[#ei::#vi] {
                    Ok(Some(#tid::from_nest(attr)?))
                } else {
                    Ok(None)
                }
            }
            pub fn #startfn<'b>(nlh: &'b mut Msghdr<'b>) -> Result<&'b mut Attr<'b>> {
                nlh.nest_start(#ei::#vi)
            }
        }))
    }

    Ok(None)
}
