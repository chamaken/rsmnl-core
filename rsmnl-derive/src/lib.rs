extern crate proc_macro;
extern crate syn;

#[macro_use]
extern crate quote;
extern crate proc_macro2;

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use syn::DeriveInput;


#[proc_macro_derive(MnlAttrConvert)]
pub fn mnl_attr_from(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();
    if let syn::Data::Enum(_) = ast.data {
        // TODO: check whether
        // [repr(u16)]ed and _UNSPEC and _MAX exists.
    } else {
        panic!("[derive(MnlAttrFrom)] is only defined for repr(u16)ed enums.");
    }

    let name = &ast.ident;
    let unspec = Ident::new("UNSPEC", Span::call_site());
    let max = Ident::new("_MAX", Span::call_site());

    let expanded = quote! {
        impl From<u16> for #name {
            fn from(v: u16) -> Self {
                unsafe {
                    ::std::mem::transmute::<u16, Self>(
                        if v >= #name::#max as u16 {
                            #name::#unspec as u16
                        } else { v }
                    )
                }
            }
        }
        impl From<usize> for #name {
            fn from(v: usize) -> Self {
                Self::from(v as u16)
            }
        }

        impl From<#name> for u16 {
            fn from(v: #name) -> u16 { v as u16 }
        }
        impl From<#name> for usize {
            fn from(v: #name) -> usize { v as usize }
        }
    };
    expanded.into()
}
