# Applied PKCS#11 (HSM) in Python

### Prerequisites
* Install SoftHSM from [https://www.opendnssec.org/softhsm/](https://www.opendnssec.org/softhsm/) or build from source [https://github.com/opendnssec/SoftHSMv2](https://github.com/opendnssec/SoftHSMv2)
* Install Python PKCS#11 (v2.4.0)
 ```sh
 pip install python-pkcs11
 ```
 
 ### Getting Started
 * Setup Environments
 ```sh
 export SOFTHSM2_CONF=$HOME/softhsm/softhsm2.conf
 export PKCS11_MODULE=/usr/local/lib/softhsm/libsofthsm2.so
 source ~/.bashrc
 ```
 * Documentation: [https://python-pkcs11.readthedocs.io/en/latest/index.html](https://python-pkcs11.readthedocs.io/en/latest/index.html)
