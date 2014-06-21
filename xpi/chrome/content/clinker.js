/**
 * Clinker TLS validator
 * https://github.com/tomato42/clinker
 *
 * Previously
 * Calomel SSL Validation
 *    https://calomel.org
 */

/*
 * class used to estimate the overall security of connection
 */
var clinkerCryptoEstimator = function() {
    // key exchange algorithm used in TLS
    this.kex = null;
    // bulk cipher used to provide secrecy
    this.bulkCipher = "Unknown";
    // mechanism used to provide integrity of transmitted data
    this.integrity = null;
    // level of security of used integrity mechanism
    this.integrityLoS = null;
    // pseudo random function, used to generate keying material
    this.prf = null;
    // RSA, ECDSA or DSA
    this.serverKeyType = null;
    // length of public key used by server
    this.serverKeySize = null;
    // information about key size in certificate
    this.certChainSize = [];
    // information about the type/algorithm (RSA, ECDSA, DSA)
    this.certChainAlg = [];
    // information about the hash used for signing (SHA1, SHA224, etc.)
    this.certChainHash = [];
    // cert stats for easy printing
    this.certChainLabels = [];
}

clinkerCryptoEstimator.prototype.setServerCertificate = function(clinker_cert) {
    var cert_chain = clinker_cert.getChain().enumerate();

    var count=0
    while (cert_chain.hasMoreElements()) {
        var cert = cert_chain.getNext().QueryInterface(Ci.nsIX509Cert2);

        var cert_dump =
            Cc['@mozilla.org/security/nsASN1Tree;1']
            .createInstance(Ci.nsIASN1Tree);
        cert_dump.loadASN1Structure(cert.ASN1Structure);

        var certOrg = cert.organization?cert.organization:cert.commonName;
        var certCn  = cert.commonName  ?cert.commonName  :cert.organization;

        var certAlg = null;
        if (cert_dump.getDisplayData(11).indexOf("RSA") >= 0) {
            certAlg = "RSA";
        }
        if (!certAlg) {
            if (cert_dump.getDisplayData(12).indexOf("Elliptic") >= 0) {
                certAlg = "ECDSA";
            } else {
                certAlg = "DSA";
            }
        }

        var keySize = null;
        try {
            switch (certAlg) {
                case 'RSA':
                    keySize = cert_dump.getDisplayData(12).split('\n')[0];
                    keySize = keySize.split(' ')[1];
                    keySize = keySize.split('(')[1];
                    break;
                case 'DSA':
                    keySize = cert_dump.getDisplayData(14);
                    keySize = keySize.replace(key.split('\n')[0], '');
                    keySize = keySize.replace(/\n|(\s$)/g, '').split(/\s/);
                    if (keySize[0] === '02' && keySize[1] === '81') {
                        keySize.splice(0,3);
                    }
                    if (keySize[0] === '00') {
                        keySize.splice(0,1);
                    }
                    keySize = (8 * keySize.length);
                    break;
                case 'ECDSA':
                    keySize = cert_dump.getDisplayData(14).split(' ')[2];
                    break;
            }
            //return keySize;
        } catch (e) {}

        var certHash = null;
        try {
            var tmp = cert_dump.getDisplayData(4);
            if (tmp.indexOf("SHA-1") >= 0) {
                certHash = "SHA1";
            } else if (tmp.indexOf("SHA-224") >= 0) {
                certHash = "SHA224";
            } else if (tmp.indexOf("SHA-256") >= 0) {
                certHash = "SHA256";
            } else if (tmp.indexOf("SHA-384") >= 0) {
                certHash = "SHA384";
            } else if (tmp.indexOf("SHA-512") >= 0) {
                certHash = "SHA512";
                // ECDSA signatures are not translated by FF
            } else if (tmp.indexOf("1 2 840 10045 4 1") >= 0) {
                certHash = "SHA1";
            } else if (tmp.indexOf("1 2 840 10045 4 3 1") >= 0) {
                certHash = "SHA224";
            } else if (tmp.indexOf("1 2 840 10045 4 3 2") >= 0) {
                certHash = "SHA256";
            } else if (tmp.indexOf("1 2 840 10045 4 3 3") >= 0) {
                certHash = "SHA384";
            } else if (tmp.indexOf("1 2 840 10045 4 3 4") >= 0) {
                certHash = "SHA512";
            } else {
                certHash = tmp;
            }
        } catch (e) {}


        this.certChainSize[count] = keySize;
        this.certChainAlg[count] = certAlg;
        this.certChainHash[count] = certHash;

        if (count == 0) {
            this.setServerKey(certAlg, keySize);
        }

        var certLoS = null;
        if (cert_chain.hasMoreElements()) {
            certLoS = this.getCertLoS(certAlg, keySize, certHash);
            this.certChainLabels[count] = String(
                    String(certOrg +
                        "                        ").slice(0,19) +
                    " [" +
                    keySize +
                    " bit " +
                    certAlg +
                    ", " +
                    certHash +
                    "]" +
                    "                                          ").slice(0,43) +
                " (" + certLoS + " bit)";

        } else {
            // last certificate must be in cert store, that means its
            // hash is as secure as the cert store, so we can assume sha512
            certLoS = this.getCertLoS(certAlg, keySize, "SHA512");
            this.certChainLabels[count] = String(
                    String(certOrg +
                        "                          ").slice(0,19) +
                    " [" +
                    keySize +
                    " bit " + certAlg + "]" +
                    "                                          ").slice(0,43) +
                " (" + certLoS + " bit)";
        }

        count=count+1;
    }
}

clinkerCryptoEstimator.prototype.getChainLabel = function() {
    var label = "";
    var i = this.certChainLabels.length - 1;

    while (i >= 0) {
        label = label + "\n" + this.certChainLabels[i];
        i -= 1;
    }

    return label;
}

clinkerCryptoEstimator.prototype.getCertLoS = function(alg, size, hash) {
    var los = null;

    if (alg == "ECDSA") {
        los = size / 2;
    } else {
        los = this.rsaLoSEstimator(size);
    }

    var hashLoS = this.hashSecurityEstimator(hash);

    if (hashLoS < los) {
        return hashLoS;
    } else {
        return los;
    }
}

clinkerCryptoEstimator.prototype.setPseudoRandomFunction = function(val) {
    this.prf = val;
}

clinkerCryptoEstimator.prototype.getPseudoRandomFunctionLoS = function() {
    if (this.prf == "MD5") {
        return 128;
    } else if (this.prf == "SHA1") {
        return 160;
    } else if (this.prf == "SHA224") {
        return 224;
    } else if (this.prf == "SHA256") {
        return 256;
    } else if (this.prf == "SHA384") {
        return 384;
    } else if (this.prf == "SHA512") {
        return 512;
    }
    return 0;
}

clinkerCryptoEstimator.prototype.setKeyExchange = function(val) {
    this.kex = val;
}

clinkerCryptoEstimator.prototype.getKeyExchange = function() {
    return this.kex
}

clinkerCryptoEstimator.prototype.setBulkCipher = function(val) {
    this.bulkCipher = val;
}

clinkerCryptoEstimator.prototype.hashSecurityEstimator = function(val) {
    if (val == "MD5") {
        return 64;
    } else if (val == "SHA1") {
        return 80;
    } else if (val == "SHA224") {
        return 112;
    } else if (val == "SHA256") {
        return 128;
    } else if (val == "SHA384") {
        return 192;
    } else if (val == "SHA512") {
        return 256;
    } else {
        return 0;
    }
}

clinkerCryptoEstimator.prototype.rsaLoSEstimator = function(val) {
    var keyLoS;

    // the difference in complexity of attack on RSA primes of
    // n and n-10 bit size are minimal and certificates that use
    // nonstandard sizes are quite common, so average the sizes
    // 512 == 40 bit LoS
    if (val < 760) { // 768 == 64 bit LoS
        keyLoS = 40;
    } else if (val < 1020) { // 1024 == 80 bit
        keyLoS = 64;
    } else if (val < 2040) { // 2048 == 112 bit
        keyLoS = 80;
    } else if (val < 3068) { // 3072 == 128 bit
        keyLoS = 112;
    } else if (val < 4094) { // 4096 == 152 bit
        keyLoS = 128;
    } else if (val < 7660) { // 7680 == 192 bit
        keyLoS = 152;
    } else if (val < 15300) { // 15360 == 256 bit
        keyLoS = 192;
    } else {
        keyLoS = 256;
    }
    return keyLoS;
}

clinkerCryptoEstimator.prototype.setServerKey = function(type, size) {
    this.serverKeyType = type;
    this.serverKeySize = size;
}

clinkerCryptoEstimator.prototype.getServerKeyLoS = function() {
    if (this.serverKeyType == "ECDSA") {
        return this.serverKeySize / 2;
    } else if (this.serverKeyType == "RSA" || this.serverKeyType == "DSA") {
        return this.rsaLoSEstimator(this.serverKeySize);
    }
    return 0;
}

clinkerCryptoEstimator.prototype.getServerKeyType = function() {
    if (this.serverKeyType == null) {
        return "Unknown";
    } else {
        return this.serverKeyType;
    }
}

clinkerCryptoEstimator.prototype.getServerKeySize = function() {
    if (this.serverKeySize == null) {
        return 0;
    } else {
        return this.serverKeySize;
    }
}

clinkerCryptoEstimator.prototype.setIntegrityMechanism = function(type, los) {
    this.integrity = type;
    this.integrityLoS = los;
}

clinkerCryptoEstimator.prototype.getIntegrityMechanismType = function() {
    return this.integrity;
}

clinkerCryptoEstimator.prototype.getIntegrityMechanismLoS = function() {
    return this.integrityLoS;
}

// return estimated level of security for used bulk cipher
clinkerCryptoEstimator.prototype.getCipherLoS = function() {
    // AES and Camellia have no known significant weaknesses
    if ( this.bulkCipher == "AES-128" || this.bulkCipher == "CAMELLIA-128" ) {
        return 128;
    } else if ( this.bulkCipher == "AES-256"
        || this.bulkCipher == "CAMELLIA-256" ) {
            return 256;
    } else if ( this.bulkCipher == "3DES" ) {
        // because of meet in the middle, the security is reduced from 168 bits
        return 112;
    } else if ( this.bulkCipher == "RC4" ) {
        // because of biases in output, the security is reduced from 128 bits
        return 56;
    }
    return 0;
}

// estimate the long term security of transmitted data
clinkerCryptoEstimator.prototype.getEncryptionLoS = function() {
    var minLoS = null;

    if ( this.isKeyExchangeForwardSecure ) {
        // should be the LoS of the (EC)DHE exchange, but no API yet
        // so assume it's not a weak point (it requires a targeted
        // attack anyway)
        // TODO open a RFE on bugzilla
        minLos = null;
    } else {
        if (this.serverKeyType == "RSA" ||
                this.serverKeyType == "DSA") {
            minLoS = this.rsaLoSEstimator(this.serverKeySize);
        } else if (this.serverKeyType == "ECDSA") {
            minLoS = this.serverKeySize / 2;
        }
    }

    cipherLoS = this.getCipherLoS();
    if (minLoS == null || minLoS > cipherLoS) {
        minLoS = cipherLoS;
    }

    if (this.integrity != "AEAD") {
        if (minLoS > this.integrityLoS) {
            minLoS = this.integrityLoS;
        }
    }

    return minLoS;
}

clinkerCryptoEstimator.prototype.getEncryptionCipher = function() {
    return this.bulkCipher;
}

clinkerCryptoEstimator.prototype.isKeyExchangeForwardSecure = function() {
    if (this.kex == "ECDHE" || this.kex == "DHE") {
        return true;
    }
    return false;
}

clinkerCryptoEstimator.prototype.getAuthenticationLoS = function() {
    var los = null;

    // the position in cert chain (starts with server cert)
    var count = 0;
    var lastCert = this.certChainAlg.length - 1;

    if (this.certChainAlg[count] == "ECDSA") {
        los = this.certChainSize[count] / 2;
    } else {
        los = this.rsaLoSEstimator(this.certChainSize[count]);
    }

    while (count < this.certChainAlg.length) {
        var keyLoS = null;
        if (this.certChainAlg[count] == "ECDSA") {
            keyLoS = this.certChainSize[count] / 2;
        } else {
            keyLoS = this.rsaLoSEstimator(this.certChainSize[count]);
        }

        if (keyLoS < los) {
            los = keyLoS;
        }

        if (count != lastCert) {
            var hashLoS = null;
            hashLoS = this.hashSecurityEstimator(this.certChainHash[count]);
            if (hashLoS < los) {
                los = hashLoS;
            }
        }

        count += 1;
    }

    return los;
}

clinkerCryptoEstimator.prototype.isRecommendedPractice = function() {
    if (this.integrity == "AEAD"
        && this.getEncryptionLoS() >= 128
        && this.getAuthenticationLoS() >= 112
        && this.isKeyExchangeForwardSecure()) {
            return true;
    }
    return false;
}

clinkerCryptoEstimator.prototype.setCipherSuite = function(ciphersuite) {

    // grade the key exchange
    if ( ciphersuite.contains("TLS_ECDHE_") ) {
        this.setKeyExchange("ECDHE");
    } else if ( ciphersuite.contains("TLS_DHE_") ) {
        this.setKeyExchange("DHE");
    } else if ( ciphersuite.contains("TLS_ECDH_") ) {
        this.setKeyExchange("ECDH");
    } else if ( ciphersuite.contains("TLS_DH_") ) {
        this.setKeyExchange("DH");
    } else if ( ciphersuite.contains("TLS_RSA_WITH_") ) {
        this.setKeyExchange("RSA");
    } else if ( ciphersuite.contains("SSL_RSA_WITH_") ) {
        this.setKeyExchange("RSA");
    }

    // extract bulk cipher
    if ( ciphersuite.contains("_AES_256_") ) {
        this.setBulkCipher("AES-256");
    } else if ( ciphersuite.contains("_AES_128_") ) {
        this.setBulkCipher("AES-128");
    } else if ( ciphersuite.contains("_RC4_128_") ) {
        this.setBulkCipher("RC4");
    } else if ( ciphersuite.contains("_3DES_") ) {
        this.setBulkCipher("3DES");
    } else if ( ciphersuite.contains("_CAMELLIA_256_") ) {
        this.setBulkCipher("CAMELLIA-256");
    } else if ( ciphersuite.contains("_CAMELLIA_128_") ) {
        this.setBulkCipher("CAMELLIA-128");
    }

    // extract server key type
    if ( ciphersuite.contains("_ECDSA_WITH_") ) {
        this.serverKeyType = "ECDSA";
    } else if ( ciphersuite.contains("_RSA_WITH_") ) {
        this.serverKeyType = "RSA";
    } else if ( ciphersuite.contains("_DSS_WITH_") ) {
        this.serverKeyType = "DSA";
    }

    // save the integrity mechanism
    if ( ciphersuite.contains("_GCM_SHA256") ) {
        this.setPseudoRandomFunction("SHA256");
        this.setIntegrityMechanism("AEAD",
            this.getCipherLoS());
    } else if ( ciphersuite.contains("_GCM_SHA384") ) {
        this.setPseudoRandomFunction("SHA384");
        this.setIntegrityMechanism("AEAD",
            this.getCipherLoS());
    } else if ( ciphersuite.contains("_SHA384") ) {
        this.setPseudoRandomFunction("SHA384");
        this.setIntegrityMechanism("SHA384 HMAC",
            this.getPseudoRandomFunctionLoS());
    } else if ( ciphersuite.contains("_SHA256") ) {
        this.setPseudoRandomFunction("SHA256");
        this.setIntegrityMechanism("SHA256 HMAC",
            this.getPseudoRandomFunctionLoS());
    } else if ( ciphersuite.contains("_MD5") ) {
        this.setPseudoRandomFunction("MD5");
        this.setIntegrityMechanism("MD5 HMAC",
            this.getPseudoRandomFunctionLoS());
    } else if ( ciphersuite.contains("_SHA") ) {
        this.setPseudoRandomFunction("SHA1");
        this.setIntegrityMechanism("SHA1 HMAC",
            this.getPseudoRandomFunctionLoS());
    }
}

var clinker = {

    startFirefox: function() {

        const cc = Components.classes;
        const ci = Components.interfaces;
        const prefs =
            cc["@mozilla.org/preferences-service;1"]
            .getService(ci.nsIPrefBranch);

        // retrieve user preference
        var clinker_prefAnimMode =
            prefs.getBoolPref("extensions.clinker.animations");
        var clinker_prefCipher256pfs =
            prefs.getBoolPref("extensions.clinker.ciphers_256pfs");
        var clinker_prefCipher128pfs =
            prefs.getBoolPref("extensions.clinker.ciphers_128pfs");
        var clinker_prefCipher128 =
            prefs.getBoolPref("extensions.clinker.ciphers_128");
        var clinker_prefCipherAll =
            prefs.getBoolPref("extensions.clinker.ciphers_all");
        var clinker_prefOCSP =
            prefs.getBoolPref("extensions.clinker.ocsp");
        var clinker_prefTLS =
            prefs.getBoolPref("extensions.clinker.tls");
        var clinker_prefProxyDns =
            prefs.getBoolPref("extensions.clinker.proxy_dns");
        var clinker_prefToolTips =
            prefs.getBoolPref("extensions.clinker.tool_tips");
        var clinker_prefPaintDelay =
            prefs.getBoolPref("extensions.clinker.paint_delay");
        var clinker_prefSafeBrowsing =
            prefs.getBoolPref("extensions.clinker.safe_browsing");
        var clinker_prefPrefetch =
            prefs.getBoolPref("extensions.clinker.prefetch");
        var clinker_prefDnsPrefetch =
            prefs.getBoolPref("extensions.clinker.dns_prefetch");
        var clinker_prefGeoLocate =
            prefs.getBoolPref("extensions.clinker.geo_locate");
        var clinker_prefSpelling =
            prefs.getBoolPref("extensions.clinker.spelling");
        var clinker_prefTabTitle =
            prefs.getBoolPref("extensions.clinker.tab_title");
        var clinker_prefMemCache =
            prefs.getBoolPref("extensions.clinker.mem_cache");
        var clinker_prefUrlGuess =
            prefs.getBoolPref("extensions.clinker.url_guess");
        var clinker_prefDnsCache =
            prefs.getBoolPref("extensions.clinker.dns_cache");
        var clinker_prefSendReferer =
            prefs.getBoolPref("extensions.clinker.send_referer");
        var clinker_prefUserAgent =
            prefs.getBoolPref("extensions.clinker.user_agent");

        // set cipher toggle on start of firefox
        prefs.setBoolPref("extensions.clinker.ciphers_256pfs",
                clinker_prefCipher256pfs);
        prefs.setBoolPref("extensions.clinker.ciphers_128pfs",
                clinker_prefCipher128pfs);
        prefs.setBoolPref("extensions.clinker.ciphers_128",
                clinker_prefCipher128);
        prefs.setBoolPref("extensions.clinker.ciphers_all",
                clinker_prefCipherAll);

        // call method setting all user prefs
        clinker.clinker_toggleAnimMode(clinker_prefAnimMode, prefs);
        clinker.clinker_toggleCipherUser();
        clinker.clinker_toggleOCSP(clinker_prefOCSP, prefs);
        clinker.clinker_toggleTLS(clinker_prefTLS, prefs);
        clinker.clinker_toggleProxyDns(clinker_prefProxyDns, prefs);
        clinker.clinker_toggleToolTips(clinker_prefToolTips, prefs);
        clinker.clinker_togglePaintDelay(clinker_prefPaintDelay, prefs);
        clinker.clinker_toggleSafeBrowsing(clinker_prefSafeBrowsing, prefs);
        clinker.clinker_togglePrefetch(clinker_prefPrefetch, prefs);
        clinker.clinker_toggleDnsPrefetch(clinker_prefDnsPrefetch, prefs);
        clinker.clinker_toggleGeoLocate(clinker_prefGeoLocate, prefs);
        clinker.clinker_toggleSpelling(clinker_prefSpelling, prefs);
        clinker.clinker_toggleMemCache(clinker_prefMemCache, prefs);
        clinker.clinker_toggleUrlGuess(clinker_prefUrlGuess, prefs);
        clinker.clinker_toggleDnsCache(clinker_prefDnsCache, prefs);
        clinker.clinker_toggleSendReferer(clinker_prefSendReferer, prefs);
        clinker.clinker_toggleUserAgent(clinker_prefUserAgent, prefs);
    },


    // enable or disable Online Certificate Status Protocol (OCSP)
    clinker_toggleOCSP: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.ocsp.state") == true) {
                prefs.clearUserPref("security.OCSP.require");
                prefs.clearUserPref("security.OCSP.enabled");
                prefs.clearUserPref("extensions.clinker.ocsp.state", true);
        }
        if (param == true) {
            prefs.setBoolPref("security.OCSP.require", false);
            prefs.setIntPref("security.OCSP.enabled", "0");
            prefs.setBoolPref("extensions.clinker.ocsp.state", true);
        }
    },

    // enable or disable TLSv1.2 and TLSv1.1, disable anything lower
    clinker_toggleTLS: function(param, prefs) {
         if (param == false
             && prefs.getBoolPref("extensions.clinker.tls.state") == true) {
                 prefs.clearUserPref("security.tls.version.min");
                 prefs.clearUserPref("security.tls.version.max");
                 prefs.clearUserPref("extensions.clinker.tls.state", true);
         }
         if (param == true) {
             prefs.setIntPref("security.tls.version.min", 2);
             prefs.setIntPref("security.tls.version.max", 3);
             prefs.setBoolPref("extensions.clinker.tls.state", true);
         }
    },

    // enable or disable sending full referer info to server after a link
    // is clicked
    clinker_toggleSendReferer: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.send_referer.state")
            == true) {
                prefs.clearUserPref("network.http.sendRefererHeader");
                prefs.clearUserPref("network.http.sendSecureXSiteReferrer");
                prefs.clearUserPref("extensions.clinker.send_referer.state");
        }
        if (param == true) {
            prefs.setIntPref("network.http.sendRefererHeader", 0);
            prefs.setBoolPref("network.http.sendSecureXSiteReferrer", false);
            prefs.setBoolPref("extensions.clinker.send_referer.state", true);
        }
    },

    // send a more generic user agent string for privacy. No need for servers
    // to know our OS or other info.
    clinker_toggleUserAgent: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.user_agent.state")
            == true) {
                prefs.clearUserPref("general.useragent.override");
                prefs.clearUserPref("extensions.clinker.user_agent.state");
        }
        if (param == true) {
            prefs.setCharPref("general.useragent.override",
                "Mozilla/5.0 (Gecko) Firefox/64");
            prefs.setBoolPref("extensions.clinker.user_agent.state", true);
        }
    },

    // enable or disable internal firefox dns cache
    clinker_toggleDnsCache: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.dns_cache.state")
            == true) {
                prefs.clearUserPref("network.dnsCacheEntries");
                prefs.clearUserPref("network.dnsCacheExpiration");
                prefs.clearUserPref("extensions.clinker.dns_cache.state");
        }
        if (param == true) {
            prefs.setIntPref("network.dnsCacheEntries", 0);
            prefs.setIntPref("network.dnsCacheExpiration", 0);
            prefs.setBoolPref("extensions.clinker.dns_cache.state", true);
        }
    },

    // enable or disable caching to memory only, no disk and increase cache
    // size to 128meg
    clinker_toggleMemCache: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.mem_cache.state")
            == true ) {
                prefs.clearUserPref("browser.cache.disk.enable");
                prefs.clearUserPref("browser.cache.disk.capacity");
                prefs.clearUserPref("browser.cache.memory.enable");
                prefs.clearUserPref("browser.sessionhistory.cache_subframes");
                prefs.clearUserPref("browser.cache.check_doc_frequency");
                prefs.clearUserPref("browser.cache.memory.capacity");
                prefs.clearUserPref("extensions.clinker.mem_cache.state");
        }
        if (param == true) {
            prefs.setBoolPref("browser.cache.disk.enable", false);
            prefs.setIntPref("browser.cache.disk.capacity", 0);
            prefs.setBoolPref("browser.cache.memory.enable", true);
            prefs.setBoolPref("browser.sessionhistory.cache_subframes", true);
            prefs.setIntPref("browser.cache.check_doc_frequency", 3);
            prefs.setIntPref("browser.cache.memory.capacity",  131072);
            prefs.setBoolPref("extensions.clinker.mem_cache.state",true);
        }
    },

    // enable or disable spell checking
    clinker_toggleSpelling: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.spelling.state") == true) {
                prefs.clearUserPref("layout.spellcheckDefault");
                prefs.clearUserPref("extensions.clinker.spelling.state");
        }
        if (param == true) {
            prefs.setIntPref("layout.spellcheckDefault", 2);
            prefs.setBoolPref("extensions.clinker.spelling.state", true);
        }
    },

    // enable or disable geo location reporting to websites
    clinker_toggleGeoLocate: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.geo_locate.state")
            == true) {
                prefs.clearUserPref("geo.enabled");
                prefs.clearUserPref("extensions.clinker.geo_locate.state");
        }
        if (param == true) {
            prefs.setBoolPref("geo.enabled", false);
            prefs.setBoolPref("extensions.clinker.geo_locate.state", true);
        }
    },

    // enable or disable short URL keyword guessing
    clinker_toggleUrlGuess: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.url_guess.state")
            == true) {
                prefs.clearUserPref("browser.fixup.alternate.enabled");
                prefs.clearUserPref("keyword.enabled");
                prefs.clearUserPref("extensions.clinker.url_guess.state");
        }
        if (param == true) {
            prefs.setBoolPref("browser.fixup.alternate.enabled", false);
            prefs.setBoolPref("keyword.enabled", false);
            prefs.setBoolPref("extensions.clinker.url_guess.state", true);
        }
    },

    // enable or disable prefetch of unvisted sites
    clinker_toggleDnsPrefetch: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.dns_prefetch.state")
            == true ) {
                prefs.clearUserPref("network.dns.disablePrefetch");
                prefs.clearUserPref("network.dns.disablePrefetchFromHTTPS");
                prefs.clearUserPref("extensions.clinker.dns_prefetch.state")
        }
        if (param == true) {
            prefs.setBoolPref("network.dns.disablePrefetch", true);
            prefs.setBoolPref("network.dns.disablePrefetchFromHTTPS", true);
            prefs.setBoolPref("extensions.clinker.dns_prefetch.state", true);
        }
    },

    // enable or disable the prefetching of unvisited links
    clinker_togglePrefetch: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.prefetch.state") == true) {
                prefs.clearUserPref("network.prefetch-next");
                prefs.clearUserPref("extensions.clinker.prefetch.state");
        }
        if (param == true) {
            prefs.setBoolPref("network.prefetch-next", false);
            prefs.setBoolPref("extensions.clinker.prefetch.state", true);
        }
    },

    // enable or disable paint delay
    clinker_togglePaintDelay: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.paint_delay.state")
            == true) {
                prefs.clearUserPref("nglayout.initialpaint.delay");
                prefs.clearUserPref("content.notify.ontimer");
                prefs.clearUserPref("content.notify.backoffcount");
                prefs.clearUserPref("content.notify.interval");
                prefs.clearUserPref("extensions.clinker.paint_delay.state");
        }
        if (param == true) {
            prefs.setIntPref("nglayout.initialpaint.delay", "2000");
            prefs.setBoolPref("content.notify.ontimer", "true");
            prefs.setIntPref("content.notify.backoffcount", "5");
            prefs.setIntPref("content.notify.interval", "1000000");
            prefs.setBoolPref("extensions.clinker.paint_delay.state", true);
        }
    },

    // enable or disable animated images
    clinker_toggleAnimMode: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.animations.state")
            == true) {
                prefs.clearUserPref("image.animation_mode");
                prefs.clearUserPref("extensions.clinker.animations.state");
        }
        if (param == true) {
            prefs.setCharPref("image.animation_mode", "none");
            prefs.setBoolPref("extensions.clinker.animations.state", true);
        }
    },

    // enable or disable tool tips
    clinker_toggleToolTips: function (param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.tool_tips.state")
            == true) {
                prefs.clearUserPref("browser.chrome.toolbar_tips");
                prefs.clearUserPref("extensions.clinker.tool_tips.state");
        }
        if (param == true) {
            prefs.setBoolPref("browser.chrome.toolbar_tips", false);
            prefs.setBoolPref("extensions.clinker.tool_tips.state", true);
        }
    },

    // enable or disable dns lookups over a proxy
    clinker_toggleProxyDns: function (param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.proxy_dns.state")
            == true) {
                prefs.clearUserPref("network.proxy.socks_remote_dns");
                prefs.clearUserPref("extensions.clinker.proxy_dns.state");
        }
        if (param == true) {
            prefs.setBoolPref("network.proxy.socks_remote_dns", true);
            prefs.setBoolPref("extensions.clinker.proxy_dns.state", true);
        }
    },

    // enable or disable safe browsing
    clinker_toggleSafeBrowsing: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.safe_browsing.state")
            == true) {
                prefs.clearUserPref("browser.safebrowsing.enabled");
                prefs.clearUserPref("browser.safebrowsing.malware.enabled");
                prefs.clearUserPref("extensions.clinker.safe_browsing.state");
        }
        if (param == true) {
            prefs.setBoolPref("browser.safebrowsing.enabled", false);
            prefs.setBoolPref("browser.safebrowsing.malware.enabled", false);
            prefs.setBoolPref("extensions.clinker.safe_browsing.state", true);
        }
    },
/*
    // enable or disable the use of PFS ciphers
    clinker_togglePfsCiphers: function(param, prefs) {
        if (param == false
            && prefs.getBoolPref("extensions.clinker.pfs_ciphers.state")
            == true) {
                prefs.clearUserPref("extensions.clinker.pfs_ciphers.state");
        }
        if (param == true) {
            prefs.setBoolPref("extensions.clinker.pfs_ciphers.state", true);
        }
        if (prefs.getBoolPref("extensions.clinker.high_ciphers") == false) {
            prefs.clearUserPref("extensions.clinker.pfs_ciphers");
            prefs.clearUserPref("extensions.clinker.pfs_ciphers.state");
            prefs.clearUserPref("extensions.clinker.pfs_ciphers_toggle");
        }
    },
*/

    // enable or disable ciphers
    clinker_toggleCipherUser: function(param, prefs) {

        var cc = Components.classes;
        var ci = Components.interfaces;
        var prefs = cc["@mozilla.org/preferences-service;1"]
            .getService(ci.nsIPrefBranch);

        // Ciphers 256 bit Perfect Forward Secrecy (PFS)
        const clinker_listCipher256pfs = [
            "security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",
            "security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",
            "security.ssl3.ecdhe_rsa_aes_256_sha",
            "security.ssl3.ecdhe_ecdsa_aes_256_sha",
            "security.ssl3.dhe_rsa_camellia_256_sha",
            "security.ssl3.dhe_rsa_aes_256_sha",
            "security.ssl3.dhe_dss_camellia_256_sha",
            "security.ssl3.dhe_dss_aes_256_sha"
        ];

        // Ciphers 128 bit Perfect Forward Secrecy (PFS)
        const clinker_listCipher128pfs = [
            "security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",
            "security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",
            "security.ssl3.ecdhe_rsa_rc4_128_sha",
            "security.ssl3.ecdhe_rsa_aes_256_sha",
            "security.ssl3.ecdhe_rsa_aes_128_sha",
            "security.ssl3.ecdhe_ecdsa_rc4_128_sha",
            "security.ssl3.ecdhe_ecdsa_aes_256_sha",
            "security.ssl3.ecdhe_ecdsa_aes_128_sha",
            "security.ssl3.dhe_rsa_camellia_256_sha",
            "security.ssl3.dhe_rsa_camellia_128_sha",
            "security.ssl3.dhe_rsa_aes_256_sha",
            "security.ssl3.dhe_rsa_aes_128_sha",
            "security.ssl3.dhe_dss_camellia_256_sha",
            "security.ssl3.dhe_dss_camellia_128_sha",
            "security.ssl3.dhe_dss_aes_256_sha",
            "security.ssl3.dhe_dss_aes_128_sha"
        ];

        // Ciphers 128 bit
        const clinker_listCipher128 = [
            "security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",
            "security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",
            "security.ssl3.rsa_rc4_128_sha",
            "security.ssl3.rsa_rc4_128_md5",
            "security.ssl3.rsa_camellia_256_sha",
            "security.ssl3.rsa_camellia_128_sha",
            "security.ssl3.rsa_aes_256_sha",
            "security.ssl3.rsa_aes_128_sha",
            "security.ssl3.ecdhe_rsa_rc4_128_sha",
            "security.ssl3.ecdhe_rsa_aes_256_sha",
            "security.ssl3.ecdhe_rsa_aes_128_sha",
            "security.ssl3.ecdhe_ecdsa_rc4_128_sha",
            "security.ssl3.ecdhe_ecdsa_aes_256_sha",
            "security.ssl3.ecdhe_ecdsa_aes_128_sha",
            "security.ssl3.ecdh_rsa_rc4_128_sha",
            "security.ssl3.ecdh_rsa_aes_256_sha",
            "security.ssl3.ecdh_rsa_aes_128_sha",
            "security.ssl3.ecdh_ecdsa_rc4_128_sha",
            "security.ssl3.ecdh_ecdsa_aes_256_sha",
            "security.ssl3.ecdh_ecdsa_aes_128_sha",
            "security.ssl3.dhe_rsa_camellia_256_sha",
            "security.ssl3.dhe_rsa_camellia_128_sha",
            "security.ssl3.dhe_rsa_aes_256_sha",
            "security.ssl3.dhe_rsa_aes_128_sha",
            "security.ssl3.dhe_dss_camellia_256_sha",
            "security.ssl3.dhe_dss_camellia_128_sha",
            "security.ssl3.dhe_dss_aes_256_sha",
            "security.ssl3.dhe_dss_aes_128_sha"
        ];

        // list of all ciphers
        const clinker_listCipherAll = [
            "security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",
            "security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",
            "security.ssl3.rsa_seed_sha",
            "security.ssl3.rsa_rc4_128_sha",
            "security.ssl3.rsa_rc4_128_md5",
            "security.ssl3.rsa_fips_des_ede3_sha",
            "security.ssl3.rsa_des_ede3_sha",
            "security.ssl3.rsa_camellia_256_sha",
            "security.ssl3.rsa_camellia_128_sha",
            "security.ssl3.rsa_aes_256_sha",
            "security.ssl3.rsa_aes_128_sha",
            "security.ssl3.ecdhe_rsa_rc4_128_sha",
            "security.ssl3.ecdhe_rsa_des_ede3_sha",
            "security.ssl3.ecdhe_rsa_aes_256_sha",
            "security.ssl3.ecdhe_rsa_aes_128_sha",
            "security.ssl3.ecdhe_ecdsa_rc4_128_sha",
            "security.ssl3.ecdhe_ecdsa_des_ede3_sha",
            "security.ssl3.ecdhe_ecdsa_aes_256_sha",
            "security.ssl3.ecdhe_ecdsa_aes_128_sha",
            "security.ssl3.ecdh_rsa_rc4_128_sha",
            "security.ssl3.ecdh_rsa_des_ede3_sha",
            "security.ssl3.ecdh_rsa_aes_256_sha",
            "security.ssl3.ecdh_rsa_aes_128_sha",
            "security.ssl3.ecdh_ecdsa_rc4_128_sha",
            "security.ssl3.ecdh_ecdsa_des_ede3_sha",
            "security.ssl3.ecdh_ecdsa_aes_256_sha",
            "security.ssl3.ecdh_ecdsa_aes_128_sha",
            "security.ssl3.dhe_rsa_des_ede3_sha",
            "security.ssl3.dhe_rsa_camellia_256_sha",
            "security.ssl3.dhe_rsa_camellia_128_sha",
            "security.ssl3.dhe_rsa_aes_256_sha",
            "security.ssl3.dhe_rsa_aes_128_sha",
            "security.ssl3.dhe_dss_des_ede3_sha",
            "security.ssl3.dhe_dss_camellia_256_sha",
            "security.ssl3.dhe_dss_camellia_128_sha",
            "security.ssl3.dhe_dss_aes_256_sha",
            "security.ssl3.dhe_dss_aes_128_sha",
            "security.enable_ssl3"
        ];

        // enable Ciphers 256 bit Perfect Forward Secrecy (PFS)
        if (prefs.getBoolPref("extensions.clinker.ciphers_256pfs")) {
            prefs.setBoolPref("security.enable_tls", true);
            prefs.setBoolPref("extensions.clinker.ciphers_256pfs", true);
            prefs.clearUserPref("extensions.clinker.ciphers_256pfs.state");
            prefs.clearUserPref("extensions.clinker.ciphers_128pfs");
            prefs.clearUserPref("extensions.clinker.ciphers_128pfs.state");
            prefs.clearUserPref("extensions.clinker.ciphers_128");
            prefs.clearUserPref("extensions.clinker.ciphers_128.state");
            prefs.clearUserPref("extensions.clinker.ciphers_all");
            prefs.clearUserPref("extensions.clinker.ciphers_all.state");
            for (var i=0; i<clinker_listCipherAll.length; i++)
                prefs.setBoolPref(clinker_listCipherAll[i], false);
            for (var i=0; i<clinker_listCipher256pfs.length; i++)
                prefs.setBoolPref(clinker_listCipher256pfs[i], true);
        }

        // enable Ciphers 128 bit Perfect Forward Secrecy (PFS)
        if (prefs.getBoolPref("extensions.clinker.ciphers_128pfs")) {
            prefs.setBoolPref("security.enable_tls", true);
            prefs.clearUserPref("extensions.clinker.ciphers_256pfs");
            prefs.clearUserPref("extensions.clinker.ciphers_256pfs.state");
            prefs.setBoolPref("extensions.clinker.ciphers_128pfs", true);
            prefs.clearUserPref("extensions.clinker.ciphers_128pfs.state");
            prefs.clearUserPref("extensions.clinker.ciphers_128");
            prefs.clearUserPref("extensions.clinker.ciphers_128.state");
            prefs.clearUserPref("extensions.clinker.ciphers_all");
            prefs.clearUserPref("extensions.clinker.ciphers_all.state");
            for (var i=0; i<clinker_listCipherAll.length; i++)
                prefs.setBoolPref(clinker_listCipherAll[i], false);
            for (var i=0; i<clinker_listCipher128pfs.length; i++)
                prefs.setBoolPref(clinker_listCipher128pfs[i], true);
        }

        // enable Ciphers 128 bit
        if (prefs.getBoolPref("extensions.clinker.ciphers_128")) {
            prefs.setBoolPref("security.enable_tls", true);
            prefs.clearUserPref("extensions.clinker.ciphers_256pfs");
            prefs.clearUserPref("extensions.clinker.ciphers_256pfs.state");
            prefs.clearUserPref("extensions.clinker.ciphers_128pfs");
            prefs.clearUserPref("extensions.clinker.ciphers_128pfs.state");
            prefs.setBoolPref("extensions.clinker.ciphers_128", true);
            prefs.clearUserPref("extensions.clinker.ciphers_128.state");
            prefs.clearUserPref("extensions.clinker.ciphers_all");
            prefs.clearUserPref("extensions.clinker.ciphers_all.state");
            for (var i=0; i<clinker_listCipherAll.length; i++)
                prefs.setBoolPref(clinker_listCipherAll[i], false);
            for (var i=0; i<clinker_listCipher128.length; i++)
                prefs.setBoolPref(clinker_listCipher128[i], true);
        }

        // Enable ALL ciphers (firefox defaults)
        if (prefs.getBoolPref("extensions.clinker.ciphers_all")) {
            prefs.clearUserPref("security.enable_tls");
            for (var i=0; i<clinker_listCipherAll.length; i++)
                prefs.clearUserPref(clinker_listCipherAll[i]);
            prefs.clearUserPref("extensions.clinker.ciphers_256pfs");
            prefs.clearUserPref("extensions.clinker.ciphers_256pfs.state");
            prefs.clearUserPref("extensions.clinker.ciphers_128pfs");
            prefs.clearUserPref("extensions.clinker.ciphers_128pfs.state");
            prefs.clearUserPref("extensions.clinker.ciphers_128.state");
            prefs.clearUserPref("extensions.clinker.ciphers_128");
            prefs.clearUserPref("extensions.clinker.ciphers_all.state");
            prefs.setBoolPref("extensions.clinker.ciphers_all", true);
        }

    },

    // open the cache summary. May be helpful for diagnostics.
    clinker_summaryCacheUsage: function(event) {
        openUILink("about:cache", event, false, true);
    },

    // open the memory cache device. May be helpful for diagnostics.
    clinker_memoryCacheUsage: function(event) {
        openUILink("about:cache?device=memory", event, false, true);
    },

    // open the disk cache device. May be helpful for diagnostics.
    clinker_diskCacheUsage: function(event) {
        openUILink("about:cache?device=disk", event, false, true);
    },

    // open the memory cache device. May be helpful for diagnostics.
    clinker_offlineCacheUsage: function(event) {
        openUILink("about:cache?device=offline", event, false, true);
    },

    // open a link to our home page
    openHomePageLink: function(event) {
        openUILink("https://github.com/tomato42/clinker", event, false, true);
    },

    //
    // popup window section
    //

    // events for mouse button clicks on the toolbar button. 0=left,
    // 1=middle and 2=right mouse button
    clinkerButtonEvent: function(event) {
        if (event.type == "click" && event.button == 0) {
            this._clinkerPopup.openPopup(
                this._clinkerPopupContentUrlImage, 'after_start');
        }
        if (event.type == "click" && event.button == 1) {
            window.openDialog('chrome://clinker/content/options.xul');
        }
        if (event.type == "click" && event.button == 2) {
            clinker.startFirefox();
        }
    },

    // collect the elements from xul
    get _clinkerPopup () {
        return document.getElementById("clinker-popup");
    },
    get _clinkerPopupContentUrlImage () {
        return document.getElementById("clinker-urlicon");
    },
    get _clinkerPopupContentHost () {
        return document.getElementById("clinker-popup-content-host");
    },
    get _clinkerPopupContentSecure () {
        return document.getElementById("clinker-popup-content-secure");
    },
    get _clinkerPopupContentCertificate () {
        return document.getElementById("clinker-popup-content-certificate");
    },
    get _clinkerPopupContentPfs () {
        return document.getElementById("clinker-popup-content-pfs");
    },
    get _clinkerPopupContentCiphersuite () {
        return document.getElementById("clinker-popup-content-ciphersuite");
    },
    get _clinkerPopupContentKeyExchange () {
        return document.getElementById("clinker-popup-content-key_exchange");
    },
    get _clinkerPopupContentSignature () {
        return document.getElementById("clinker-popup-content-signature");
    },
    get _clinkerPopupContentBulkCipher () {
        return document.getElementById("clinker-popup-content-bulk_cipher");
    },
    get _clinkerPopupContentMAC () {
        return document.getElementById("clinker-popup-content-mac");
    },
    get _clinkerPopupContentHomePage () {
        return document.getElementById("clinker-popup-content-homepage");
    },
    get _clinkerPopupContentCommonName () {
        return document.getElementById("clinker-popup-content-commonname");
    },
    get _clinkerPopupContentCertType () {
        return document.getElementById("clinker-popup-content-cert-type");
    },
    get _clinkerPopupContentOrganization () {
        return document.getElementById("clinker-popup-content-organization");
    },
    get _clinkerPopupContentOrganizationSubCert () {
        return document.getElementById(
            "clinker-popup-content-organization-subcert");
    },
    get _clinkerPopupContentOrganizationCaCert () {
        return document.getElementById(
            "clinker-popup-content-organization-cacert");
    },
    get _clinkerPopupContentOrganizationLocation () {
        return document.getElementById(
            "clinker-popup-content-organization-location");
    },
    get _clinkerPopupContentIssuerOrganization () {
        return document.getElementById("clinker-popup-content-issuer");
    },
    get _clinkerPopupContentIssuerLocation () {
        return document.getElementById("clinker-popup-content-issuer-location");
    },
    get _clinkerPopupContentValidBeforeDate () {
        return document.getElementById("clinker-popup-content-before-date");
    },
    get _clinkerPopupContentValidAfterDate () {
        return document.getElementById("clinker-popup-content-after-date");
    },
    get _clinkerPopupContentCurrentDate () {
        return document.getElementById("clinker-popup-content-current-date");
    },

    //
    // page load section
    //

    onPageLoad: function() {

        const ci = Components.interfaces;
        const cc = Components.classes;
        const gb = window.getBrowser();
        const prefs = cc["@mozilla.org/preferences-service;1"]
            .getService(ci.nsIPrefBranch);

        // initilize the popup window
        const clinker_current_greeting = "version 0.0.2";
        clinker._clinkerPopupContentSecure.textContent =
            clinker_current_greeting;
        clinker._clinkerPopupContentCurrentDate.textContent = (new Date());

        // Install the toolbar button on first install ONLY (mozilla code)
        var clinker_prefFirstInstall =
            prefs.getBoolPref("extensions.clinker.first_install");
        if (clinker_prefFirstInstall) {
            prefs.setBoolPref("extensions.clinker.first_install", false);
            try {
                var firefoxnav = document.getElementById("nav-bar");
                var curSet = firefoxnav.currentSet;
                if (curSet.indexOf("clinker-urlicon") == -1) {
                    var set;
                    // Place the button before the urlbar
                    if (curSet.indexOf("urlbar-container") != -1) {
                        set = curSet.replace(/urlbar-container/,
                            "clinker-urlicon,urlbar-container");
                    } else { // at the end
                        set = curSet + ",clinker-urlicon";
                    }
                    firefoxnav.setAttribute("currentset", set);
                    firefoxnav.currentSet = set;
                    document.persist("nav-bar", "currentset");
                    // If you don't do the following call, funny things happen
                    try {
                        BrowserToolboxCustomizeDone(true);
                    }
                    catch (e) { }
                }
            }
            catch(e) { }
        }

        var clinker_updateListener = {
            onStateChange: function(aWebProgress, aRequest, aFlag, aStatus) {
                clinker.onPageUpdate();
            },
            onLocationChange: function(aWebProgress, aRequest, aURI) {
                clinker.onPageUpdate();
            },
            onSecurityChange: function(aWebProgress, aRequest, aState) {
                clinker.onPageUpdate();
            },
            onStatusChange: function(aWebProgress) {
                return;
            },
            onProgressChange: function(aWebProgress) {
                return;
            }
        };

        //gb.addProgressListener(clinker_updateListener,
        //    ci.nsIWebProgress.NOTIFY_STATE_DOCUMENT);
        gb.addProgressListener(clinker_updateListener);
    },


    //
    // page loads, tab changed
    //
    onPageUpdate: function() {

        // CURRENT VERSION
        const clinker_current_version = 1;
        const clinker_current_greeting = "version 0.0.2";

        // global constants
        const cc = Components.classes;
        const ci = Components.interfaces;
        const gb = window.getBrowser();
        const prefs = cc["@mozilla.org/preferences-service;1"]
            .getService(ci.nsIPrefBranch);
        var currentBrowser = gb.selectedBrowser;
        var ui = currentBrowser.securityUI;
        var insecureSSL = (ui.state
            & ci.nsIWebProgressListener.STATE_IS_INSECURE);
        var clinker_url_protocol = window.content.location.protocol;
        var clinker_prefTabTitle =
            prefs.getBoolPref("extensions.clinker.tab_title");
        var estimator = new clinkerCryptoEstimator();

        // open the clinker help page on update or install
        var clinker_prefHomeOnUpdate =
            prefs.getBoolPref("extensions.clinker.home_on_update");
        var clinker_prefVersion =
            prefs.getIntPref("extensions.clinker.version");
        if (clinker_prefHomeOnUpdate
            && clinker_prefVersion < clinker_current_version) {
                gBrowser.addTab("https://github.com/tomato42/clinker");
                prefs.setIntPref("extensions.clinker.version",
                    clinker_current_version);
        }

        // if the toolbar button is not used on any toolbar just return
        if (document.getElementById("clinker-urlicon") == null ) {
            return;
        }

        // reset strings
        clinker._clinkerPopupContentHost.textContent = null;
        clinker._clinkerPopupContentSecure.textContent =
            clinker_current_greeting;
        clinker._clinkerPopupContentCiphersuite.textContent = null;
        clinker._clinkerPopupContentPfs.textContent = null;
        clinker._clinkerPopupContentKeyExchange.textContent = null;
        clinker._clinkerPopupContentSignature.textContent = null;
        clinker._clinkerPopupContentBulkCipher.textContent = null;
        clinker._clinkerPopupContentMAC.textContent = null;
        clinker._clinkerPopupContentCommonName.textContent = null;
        clinker._clinkerPopupContentCertType.textContent = null;
        clinker._clinkerPopupContentOrganization.textContent = null;
        clinker._clinkerPopupContentOrganizationSubCert.textContent = null;
        clinker._clinkerPopupContentOrganizationCaCert.textContent = null;
        clinker._clinkerPopupContentOrganizationLocation.textContent = null;
        clinker._clinkerPopupContentIssuerOrganization.textContent = null;
        clinker._clinkerPopupContentIssuerLocation.textContent = null;
        clinker._clinkerPopupContentValidBeforeDate.textContent = null;
        clinker._clinkerPopupContentValidAfterDate.textContent = null;
        clinker._clinkerPopupContentCurrentDate.textContent = (new Date());
        clinker._clinkerPopupContentCertificate.textContent = null;
        document.getElementById("clinker-urlicon")
            .image="chrome://clinker/skin/clinker_grey_button.png";

        // clear the title and icon from the tab if the user prefers it
        if (clinker_prefTabTitle) {
            var current_tab =
                window.document.getElementById("content").selectedTab;
            current_tab.label = "";
            current_tab.setAttribute("image", " ");
        }

        // https ssl connections
        if (clinker_url_protocol == "https:") {

            // collect the certificate information
            if (ui && !insecureSSL)  {
                ui.QueryInterface(ci.nsISSLStatusProvider);
                var clinker_url_hostname = window.content.location.hostname;
                var status = ui.SSLStatus;
                if (!status) return;
                var clinker_ssl_cert = status.serverCert;
                if (!(clinker_ssl_cert)) return;

                estimator.setServerCertificate(clinker_ssl_cert);

                var clinker_date_validity =
                    clinker_ssl_cert.validity
                    .QueryInterface(ci.nsIX509CertValidity);
                if (status && !insecureSSL) {
                    status.QueryInterface(ci.nsISSLStatus);
                }

                // does the url hostname and certificate common name match?
                var clinker_hosts_match = " (DOMAIN MISMATCH!)";
                if (! clinker_ssl_cert.isDomainMismatch) {
                    clinker_hosts_match = " (matched) ";
                }

                // print out the certificate info
                clinker._clinkerPopupContentHost.textContent =
                    ("\nURL Host        : "+ clinker_url_hostname);
                clinker._clinkerPopupContentCommonName.textContent =
                    ("Common Name (CN): " + clinker_ssl_cert.commonName
                     + clinker_hosts_match);
                var label = estimator.getChainLabel();
                clinker._clinkerPopupContentOrganization.textContent = label;
                clinker._clinkerPopupContentValidBeforeDate.textContent =
                    ("Valid from : "
                     + clinker_date_validity.notBeforeLocalTime);
                clinker._clinkerPopupContentValidAfterDate.textContent =
                    ("Valid until: " + clinker_date_validity.notAfterLocalTime);
                clinker._clinkerPopupContentCurrentDate.textContent =
                    ("\n" + new Date());
            }

            // type of certificate validation EV or DV, OV seems unused
            if (ui.state
                & ci.nsIWebProgressListener.STATE_IDENTITY_EV_TOPLEVEL) {
                    clinker._clinkerPopupContentCertType.textContent =
                        ("Class           : Extended Validation (EV)");
            } else if (ui.state & ci.nsIWebProgressListener.STATE_IS_SECURE) {
                clinker._clinkerPopupContentCertType.textContent =
                    ("Class           : Domain Validation (DV)");
            } else {
                clinker._clinkerPopupContentCertType.textContent =
                    ("Class           : Untrusted");
            }

            // retrive the ssl cipher and key length
            if (status instanceof ci.nsISSLStatus) {
              var symetricCipher = status.cipherName;
              var symetricKeyLength = status.secretKeyLength;
            }

            // popup the ssl information if the connection is encrypted
            if (symetricCipher && symetricKeyLength ) {

                // parse ciphersuite used by connection
                estimator.setCipherSuite(symetricCipher);

                // set used ciphersuite
                clinker._clinkerPopupContentCiphersuite.textContent =
                    ("\nCiphersuite : " + symetricCipher );

                // set PFS status and key exchange algorithm
                if (estimator.isKeyExchangeForwardSecure()) {
                    clinker._clinkerPopupContentPfs.textContent =
                        ("\nPerfect Forward Secrecy [PFS]:  yes");
                    clinker._clinkerPopupContentKeyExchange.textContent =
                        String("Key Exchange: " +
                                estimator.getKeyExchange() +
                                "                      ").slice(0,31)
                        + "(? bit)";
                } else {
                    clinker._clinkerPopupContentPfs.textContent =
                        ("\nPerfect Forward Secrecy [PFS]:  no");
                    var kexSize = String(estimator.getServerKeySize()
                        + " bit ");
                    var kexName = String(kexSize
                        + estimator.getKeyExchange()
                        + "              ").slice(0,17);
                    clinker._clinkerPopupContentKeyExchange.textContent =
                        ("Key Exchange: "
                         + kexName
                         + "("
                         + estimator.getServerKeyLoS()
                         + " bit)");
                }

                // set server key type
                var keyType = String(estimator.getServerKeySize()
                    + " bit " + estimator.getServerKeyType()
                    + "                 ").slice(0,17);
                clinker._clinkerPopupContentSignature.textContent =
                    "Server key  : " + keyType + "("
                    + estimator.getServerKeyLoS() + " bit)";

                // set bulk cipher info
                var cipher_name = String(estimator.getEncryptionCipher()
                    + "                 ").slice(0,16);
                var cipher_los = estimator.getCipherLoS();
                clinker._clinkerPopupContentBulkCipher.textContent =
                    ("Bulk Cipher : ").concat(cipher_name).concat(" (")
                    .concat(cipher_los).concat(" bit)");

                // set the used integrity mechanism
                var mechanismName = String(estimator.getIntegrityMechanismType()
                    + "                 ").slice(0,17);
                var mechanismLoS = ("(").concat(
                    estimator.getIntegrityMechanismLoS()).concat(" bit)");
                clinker._clinkerPopupContentMAC.textContent =
                    ("Integrity   : ").concat(mechanismName)
                    .concat(mechanismLoS);
            }

            // Is the connection secure?
            if (estimator.isRecommendedPractice() ) {
                document.getElementById("clinker-urlicon")
                    .image="chrome://clinker/skin/clinker_green_button.png";
            } else if (estimator.isKeyExchangeForwardSecure()
                && estimator.getEncryptionLoS() >= 128
                && estimator.getAuthenticationLoS() >= 112 ) {
                    document.getElementById("clinker-urlicon")
                        .image="chrome://clinker/skin/clinker_blue_button.png";
            } else if (estimator.getEncryptionLoS() >= 80
                && estimator.getAuthenticationLoS() >= 80) {
                    document.getElementById("clinker-urlicon").image=
                        "chrome://clinker/skin/clinker_yellow_button.png";
            } else {
                document.getElementById("clinker-urlicon")
                    .image="chrome://clinker/skin/clinker_red_button.png";
            }

            // provide information about long term confidentiality of
            // connection
            var longTerm = estimator.getEncryptionLoS();
            var encryptionComment;
            if (longTerm < 80) {
                encryptionComment = "(BROKEN)";
            } else if (longTerm < 112) {
                encryptionComment = "(insecure)";
            } else if (longTerm < 128) {
                encryptionComment = "(secure up to 2030)";
            } else if (longTerm < 192) {
                encryptionComment = "(secure)";
            } else {
                encryptionComment = "(overkill)"
            }
            clinker._clinkerPopupContentSecure.textContent =
                ("Confidentiality : ").concat(longTerm).concat(" bit ")
                .concat(encryptionComment);

            // provide information about authentication level
            var authenticationLoS = estimator.getAuthenticationLoS();
            var authenticationComment;
            if (authenticationLoS < 80) {
                authenticationComment = "(BROKEN)";
            } else if (authenticationLoS < 112) {
                authenticationComment = "(insecure)";
            } else if (authenticationLoS < 128) {
                authenticationComment = "(secure up to 2030)";
            } else if (authenticationLoS < 192) {
                authenticationComment = "(secure)";
            } else {
                authenticationLoS = "(overkill)";
            }
            clinker._clinkerPopupContentCertificate.textContent =
                ("Authentication  : ").concat(authenticationLoS)
                .concat(" bit ").concat(authenticationComment);

            // if the ssl connection is just plain broke
            if (ui.state & ci.nsIWebProgressListener.STATE_IS_INSECURE
                || ui.state & ci.nsIWebProgressListener.STATE_IS_BROKEN) {
                    clinker._clinkerPopupContentSecure.textContent =
                        ("Security   : " + "WARNING! BROKEN or UNTRUSTED");
                    document.getElementById("clinker-urlicon").image=
                        "chrome://clinker/skin/clinker_redbroke_button.png";
            }
        }

        // http clear connections
        if (clinker_url_protocol == "http:") {
            var clinker_url_hostname = window.content.location.hostname;
            clinker._clinkerPopupContentHost.textContent =
                ("URL Host   : " + clinker_url_hostname);
            clinker._clinkerPopupContentSecure.textContent =
                ("Security   : " + "None - Unsecured");
            clinker._clinkerPopupContentCurrentDate.textContent = (new Date());
            document.getElementById("clinker-urlicon").image =
                "chrome://clinker/skin/clinker_grey_button.png";
        }

    },

};
