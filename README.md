
## 暂存代码，之后会删掉这个库

## 简介

  在cita中实现了合约的隐私执行环境，将主要合约逻辑和相关内存放入sgx enclave中，对外提供一个执行接口，我主要实现了一个简单的例子，没有完全跟cita本身的设计接轨，只是作为一个参考，为后续的设计开发做个铺垫。
  
  依赖的cita版本还比较老，大约是11月末拷贝下来的develop分支代码。
  
  利用了baidu x-lab开源的[rust-sgx-sdk](https://github.com/baidu/rust-sgx-sdk)进行sgx编程，编程模型和sgx官方提供的没有太大差异。
  
 
## 主要改动

  首先在share-libs中添加了rust-sgx-sdk。
  改动集中在 chain/core这个package:
  
- 在core目录下添加了build.rs和lib目录，并且修改了cargo.toml（添加了指定build.rs的声明)
- 在core/src下面添加了一个private目录，并在core/src/lib.rs添加了private这个mod。主要代码都放在private这个mod中，代码分为两部分，一部分是可信部分，即跑在enclave中的代码，这里主要是需要保护的合约本身的逻辑，另一部分是不可信部分，主要是一些外部逻辑，例如对合约发起的调用，参数返回值处理等等。两者之间的接口定义在enclave/Enclave.edl中
  - 可信部分： 写在private/enclave中，是一个独立的crate, 主要逻辑在private/enclave/src/lib.rs中，非常简单，主要是编译过程比较复杂，除了需要编译cargo，还需要将生成的库进行签名(用于验证代码是否被改动过)，另外还需要根据Enclave.edl文件生成相应的静态库作为接口，这整个过程我都写在了private/enclave/Makefile中。
  - 不可信部分：主要是外部调用的逻辑，比较简单，主要是一些sdk的接口调用，写在private/enclave_manager.rs和test.rs中，可以参考下。

## 运行环境
  
  因为rust-sgx-sdk的环境配置比较复杂，所以我直接采用了他们提供的一个docker环境，具体可以参照其[github主页](https://github.com/baidu/rust-sgx-sdk)，并在其中根据cita的文档进行相关依赖的安装。当然也可以根据rust-sgx-sdk提供的dockerfile配置其需要的依赖。
  另外，需要支持sgx的CPU，并且参照官方文档安装[相关驱动](https://github.com/intel/linux-sgx-driver)，以及[官方sdk](https://github.com/intel/linux-sgx)。

## 使用方式

首先编写相关的代码并且定义好通信接口(即edl文件)。以我的为例：
```shell
    cd /your/path/to/core/src/private/enclave
    make    
    cd /your/path/to/core
    cargo test test_create_enclave -- --nocapture
```
这里make会产生相应的库放到core/lib中去，同时会产生一个签过名的.so动态库，包含了实际的enclave代码，放在core/下面（出于测试方便，我直接放在core目录下了）





