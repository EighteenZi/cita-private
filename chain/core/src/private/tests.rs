
use private::enclave_manager::*;
use private::sgx_types::*;

extern {
    fn exec(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     opt: u8, param: u32, res: *mut u32) -> u32;
}

#[test]
fn test_create_enclave() {

    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful!!! {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };
    println!("##########hey#############");

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let mut get_result = 0;
    // test get 

    unsafe {
        exec(enclave.geteid(),
                      &mut retval,
                      0,
                      0,
                      &mut get_result)
    };
    println!("[+] get success... result: {}", get_result);

    let mut set_reseult = 0;
    // test set
    unsafe {
        exec(enclave.geteid(),
                      &mut retval,
                      1,
                      100,
                      &mut set_reseult)
    };

    unsafe {
        exec(enclave.geteid(),
                      &mut retval,
                      0,
                      0,
                      &mut set_reseult)
    };
    println!("[+] get success... result: {}", set_reseult);

    enclave.destroy();

}