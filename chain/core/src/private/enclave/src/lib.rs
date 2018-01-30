// Copyright (c) 2017 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#![crate_name = "enclave"]
#![crate_type = "staticlib"]

#![no_std]

extern crate sgx_types;
#[macro_use]
extern crate sgx_tstd as std;

use sgx_types::*;
// use std::string::String;
// use std::vec::Vec;
// use std::io::{self, Write};
use std::slice;

// =================== simple contract sample====================

trait Simple_contract { 
    fn exec(&mut self,opt: u8, param: u32) -> u32; 

}

pub struct SimpleStorage {
    uint_value: u32,
}

impl Simple_contract for SimpleStorage {
    fn exec(&mut self,opt: u8, param: u32) -> u32 {
        match opt {
            0 => self.get(),    //get
            1 => self.set(param), //set
            _ => 0,
        }
    }
}

impl SimpleStorage {

    fn get(&mut self, ) -> u32 {
        return self.uint_value;
    }
    fn set(&mut self, param: u32) -> u32 {
        self.uint_value = param;
        return 0;
    }

}

//===============================================================


static mut sample: SimpleStorage = SimpleStorage {
    uint_value: 10,
};



#[no_mangle]
pub extern "C" fn exec(opt: u8, param: u32, res:*mut u32) -> sgx_status_t {
    
    unsafe{
        *res = sample.exec(opt, param);
        
    }
    sgx_status_t::SGX_SUCCESS
   
}