#A Triple Diffie-Hellman implementation

This is a triple DH exchange implementation in C and Python.

##C implementation
The C implementation uses libgcrypt and a "classic" diffie hellman implementation
of [libotr](https://otr.cypherpunks.ca/) with some additional functions.

##Python implementation
The Python implementation uses code from [PyDHE](https://github.com/lowazo/pyDHE).
It is intended to be used as a tool in order to forge a triple-DH secret and
make it look as though a specific user participated in a key exchange.


**This code is *NOT* tested and therefore it is *NOT* suitable for any application
that needs to be even remotely secure**
