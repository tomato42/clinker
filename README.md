clinker
=======

SSL and TLS security checker.

This firefox extension takes information about used cipher suite, certificates
and tries to estimate the security of the connection.

Features
--------

 1. Easy to read icon indicating overall level of security of the site
    (green, blue - ok, yellow - not so good, red - bad)
 2. Analysis of the used cipher suite, part by part (used cipher, mac, etc.)
    with level of security provided by each part separately
 3. Security of the certificate chain estimated certificate by certificate
    with key type, key size and signature algorithm used together with
    security estimate for each.
 4. Separate estimation of long term security (confidentiality) and
    authentication.

Usage
-----

Compress the contents of xpi folder as a zip file:

    cd xpi/
    zip -r /tmp/clinker.zip *

Import to Firefox, this will install it as an extension and add an icon to the
address bar.
