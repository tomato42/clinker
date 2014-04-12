/**
 * Clinker TLS validator
 * https://github.com/tomato42/clinker
 *
 * Previously
 * Calomel SSL Validation
 *    https://clinker.org
 */

var clinker = {

  startFirefox: function() {

    const cc = Components.classes;
    const ci = Components.interfaces;
    const prefs = cc["@mozilla.org/preferences-service;1"].getService(ci.nsIPrefBranch);

    // retrieve user preference
    var clinker_prefAnimMode     = prefs.getBoolPref("extensions.clinker.animations");
    var clinker_prefCipher256pfs = prefs.getBoolPref("extensions.clinker.ciphers_256pfs");
    var clinker_prefCipher128pfs = prefs.getBoolPref("extensions.clinker.ciphers_128pfs");
    var clinker_prefCipher128    = prefs.getBoolPref("extensions.clinker.ciphers_128");
    var clinker_prefCipherAll    = prefs.getBoolPref("extensions.clinker.ciphers_all");
    var clinker_prefOCSP         = prefs.getBoolPref("extensions.clinker.ocsp");
    var clinker_prefTLS          = prefs.getBoolPref("extensions.clinker.tls");
    var clinker_prefProxyDns     = prefs.getBoolPref("extensions.clinker.proxy_dns");
    var clinker_prefToolTips     = prefs.getBoolPref("extensions.clinker.tool_tips");
    var clinker_prefPaintDelay   = prefs.getBoolPref("extensions.clinker.paint_delay");
    var clinker_prefSafeBrowsing = prefs.getBoolPref("extensions.clinker.safe_browsing");
    var clinker_prefPrefetch     = prefs.getBoolPref("extensions.clinker.prefetch");
    var clinker_prefDnsPrefetch  = prefs.getBoolPref("extensions.clinker.dns_prefetch");
    var clinker_prefGeoLocate    = prefs.getBoolPref("extensions.clinker.geo_locate");
    var clinker_prefSpelling     = prefs.getBoolPref("extensions.clinker.spelling");
    var clinker_prefTabTitle     = prefs.getBoolPref("extensions.clinker.tab_title");
    var clinker_prefMemCache     = prefs.getBoolPref("extensions.clinker.mem_cache");
    var clinker_prefUrlGuess     = prefs.getBoolPref("extensions.clinker.url_guess");
    var clinker_prefDnsCache     = prefs.getBoolPref("extensions.clinker.dns_cache");
    var clinker_prefSendReferer  = prefs.getBoolPref("extensions.clinker.send_referer");
    var clinker_prefUserAgent    = prefs.getBoolPref("extensions.clinker.user_agent");

    // set cipher toggle on start of firefox
    prefs.setBoolPref("extensions.clinker.ciphers_256pfs", clinker_prefCipher256pfs);
    prefs.setBoolPref("extensions.clinker.ciphers_128pfs", clinker_prefCipher128pfs);
    prefs.setBoolPref("extensions.clinker.ciphers_128", clinker_prefCipher128);
    prefs.setBoolPref("extensions.clinker.ciphers_all", clinker_prefCipherAll);

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


   //enable or disable Online Certificate Status Protocol (OCSP)
   clinker_toggleOCSP: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.ocsp.state") == true)
                         { prefs.clearUserPref("security.OCSP.require");
                           prefs.clearUserPref("security.OCSP.enabled");
                           prefs.clearUserPref("extensions.clinker.ocsp.state", true); }
     if (param == true) {  prefs.setBoolPref("security.OCSP.require", false);
                           prefs.setIntPref("security.OCSP.enabled", "0");
                           prefs.setBoolPref("extensions.clinker.ocsp.state", true); }
   },

   //enable or disable TLSv1.2 and TLSv1.1, disable anything lower
   clinker_toggleTLS: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.tls.state") == true)
                         { prefs.clearUserPref("security.tls.version.min");
                           prefs.clearUserPref("security.tls.version.max");
                           prefs.clearUserPref("extensions.clinker.tls.state", true); }
     if (param == true) {  prefs.setIntPref("security.tls.version.min", 2);
                           prefs.setIntPref("security.tls.version.max", 3); 
                           prefs.setBoolPref("extensions.clinker.tls.state", true); }
   },

   //enable or disable sending full referer info to server after a link is clicked
   clinker_toggleSendReferer: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.send_referer.state") == true)
                         { prefs.clearUserPref("network.http.sendRefererHeader");
                           prefs.clearUserPref("network.http.sendSecureXSiteReferrer");
                           prefs.clearUserPref("extensions.clinker.send_referer.state"); }
     if (param == true) {  prefs.setIntPref("network.http.sendRefererHeader", 0); 
                           prefs.setBoolPref("network.http.sendSecureXSiteReferrer", false);
                           prefs.setBoolPref("extensions.clinker.send_referer.state", true); }
   },

   //send a more generic user agent string for privacy. No need for servers to know our OS or other info.
   clinker_toggleUserAgent: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.user_agent.state") == true)
                         { prefs.clearUserPref("general.useragent.override");
                           prefs.clearUserPref("extensions.clinker.user_agent.state"); }
     if (param == true) {  prefs.setCharPref("general.useragent.override", "Mozilla/5.0 (Gecko) Firefox/64");
                           prefs.setBoolPref("extensions.clinker.user_agent.state", true); }
   },

   //enable or disable internal firefox dns cache 
   clinker_toggleDnsCache: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.dns_cache.state") == true)
                         { prefs.clearUserPref("network.dnsCacheEntries"); 
                           prefs.clearUserPref("network.dnsCacheExpiration");
                           prefs.clearUserPref("extensions.clinker.dns_cache.state"); }
     if (param == true) {  prefs.setIntPref("network.dnsCacheEntries", 0); 
                           prefs.setIntPref("network.dnsCacheExpiration", 0);
                           prefs.setBoolPref("extensions.clinker.dns_cache.state", true); }
   },

   //enable or disable caching to memory only, no disk and increase cache size to 128meg 
   clinker_toggleMemCache: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.mem_cache.state") == true )
                         { prefs.clearUserPref("browser.cache.disk.enable");
                           prefs.clearUserPref("browser.cache.disk.capacity"); 
                           prefs.clearUserPref("browser.cache.memory.enable");
                           prefs.clearUserPref("browser.sessionhistory.cache_subframes");
                           prefs.clearUserPref("browser.cache.check_doc_frequency"); 
                           prefs.clearUserPref("browser.cache.memory.capacity");
                           prefs.clearUserPref("extensions.clinker.mem_cache.state"); }
     if (param == true) { prefs.setBoolPref("browser.cache.disk.enable", false);
                          prefs.setIntPref("browser.cache.disk.capacity", 0); 
                          prefs.setBoolPref("browser.cache.memory.enable", true);
                          prefs.setBoolPref("browser.sessionhistory.cache_subframes", true);
                          prefs.setIntPref("browser.cache.check_doc_frequency", 3); 
                          prefs.setIntPref("browser.cache.memory.capacity",  131072);
                          prefs.setBoolPref("extensions.clinker.mem_cache.state",true); }
   },

   //enable or disable spell checking 
   clinker_toggleSpelling: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.spelling.state") == true)
                        { prefs.clearUserPref("layout.spellcheckDefault");
                          prefs.clearUserPref("extensions.clinker.spelling.state"); }
     if (param == true) { prefs.setIntPref("layout.spellcheckDefault", 2);
                          prefs.setBoolPref("extensions.clinker.spelling.state", true); }
   },

   //enable or disable geo location reporting to websites 
   clinker_toggleGeoLocate: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.geo_locate.state") == true)
                        { prefs.clearUserPref("geo.enabled");
                          prefs.clearUserPref("extensions.clinker.geo_locate.state"); }
     if (param == true) { prefs.setBoolPref("geo.enabled", false); 
                          prefs.setBoolPref("extensions.clinker.geo_locate.state", true); }
   },

   //enable or disable short URL keyword guessing 
   clinker_toggleUrlGuess: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.url_guess.state") == true)
                        { prefs.clearUserPref("browser.fixup.alternate.enabled");
                          prefs.clearUserPref("keyword.enabled");
                          prefs.clearUserPref("extensions.clinker.url_guess.state"); }
     if (param == true) { prefs.setBoolPref("browser.fixup.alternate.enabled", false);
                          prefs.setBoolPref("keyword.enabled", false);
                          prefs.setBoolPref("extensions.clinker.url_guess.state", true); }
   },

   //enable or disable prefetch of unvisted sites 
   clinker_toggleDnsPrefetch: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.dns_prefetch.state") == true )
                        { prefs.clearUserPref("network.dns.disablePrefetch");
                          prefs.clearUserPref("network.dns.disablePrefetchFromHTTPS");
                          prefs.clearUserPref("extensions.clinker.dns_prefetch.state") }
     if (param == true) { prefs.setBoolPref("network.dns.disablePrefetch", true);
                          prefs.setBoolPref("network.dns.disablePrefetchFromHTTPS", true);
                          prefs.setBoolPref("extensions.clinker.dns_prefetch.state", true); }
   },

   //enable or disable the prefetching of unvisited links
   clinker_togglePrefetch: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.prefetch.state") == true)
                        { prefs.clearUserPref("network.prefetch-next");
                          prefs.clearUserPref("extensions.clinker.prefetch.state"); }
     if (param == true) { prefs.setBoolPref("network.prefetch-next", false);
                          prefs.setBoolPref("extensions.clinker.prefetch.state", true); }
   },

   //enable or disable paint delay
   clinker_togglePaintDelay: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.paint_delay.state") == true)
                        { prefs.clearUserPref("nglayout.initialpaint.delay");
                           prefs.clearUserPref("content.notify.ontimer");
                           prefs.clearUserPref("content.notify.backoffcount"); 
                           prefs.clearUserPref("content.notify.interval");
                           prefs.clearUserPref("extensions.clinker.paint_delay.state"); }
     if (param == true) { prefs.setIntPref("nglayout.initialpaint.delay", "2000");
                          prefs.setBoolPref("content.notify.ontimer", "true");
                          prefs.setIntPref("content.notify.backoffcount", "5"); 
                          prefs.setIntPref("content.notify.interval", "1000000");
                          prefs.setBoolPref("extensions.clinker.paint_delay.state", true); }
   },

   //enable or disable animated images
   clinker_toggleAnimMode: function(param, prefs) {
     if (param == false && prefs.getBoolPref("extensions.clinker.animations.state") == true)
                        { prefs.clearUserPref("image.animation_mode");
                          prefs.clearUserPref("extensions.clinker.animations.state"); }
     if (param == true) { prefs.setCharPref("image.animation_mode", "none");
                          prefs.setBoolPref("extensions.clinker.animations.state", true); }
   },

   // enable or disable tool tips
   clinker_toggleToolTips: function (param, prefs) {
      if (param == false && prefs.getBoolPref("extensions.clinker.tool_tips.state") == true)
                         { prefs.clearUserPref("browser.chrome.toolbar_tips");
                           prefs.clearUserPref("extensions.clinker.tool_tips.state"); }
      if (param == true) { prefs.setBoolPref("browser.chrome.toolbar_tips", false);
                           prefs.setBoolPref("extensions.clinker.tool_tips.state", true); }
   },

   // enable or disable dns lookups over a proxy
   clinker_toggleProxyDns: function (param, prefs) {
      if (param == false && prefs.getBoolPref("extensions.clinker.proxy_dns.state") == true)
                         { prefs.clearUserPref("network.proxy.socks_remote_dns");
                           prefs.clearUserPref("extensions.clinker.proxy_dns.state"); }
      if (param == true) { prefs.setBoolPref("network.proxy.socks_remote_dns", true);
                           prefs.setBoolPref("extensions.clinker.proxy_dns.state", true); }
   },

   // enable or disable safe browsing
   clinker_toggleSafeBrowsing: function(param, prefs) {
      if (param == false && prefs.getBoolPref("extensions.clinker.safe_browsing.state") == true)
                         { prefs.clearUserPref("browser.safebrowsing.enabled");
                           prefs.clearUserPref("browser.safebrowsing.malware.enabled");
                           prefs.clearUserPref("extensions.clinker.safe_browsing.state"); }
      if (param == true) { prefs.setBoolPref("browser.safebrowsing.enabled", false);
                           prefs.setBoolPref("browser.safebrowsing.malware.enabled", false);
                           prefs.setBoolPref("extensions.clinker.safe_browsing.state", true); }
   },
/*
   // enable or disable the use of PFS ciphers
   clinker_togglePfsCiphers: function(param, prefs) {
      if (param == false && prefs.getBoolPref("extensions.clinker.pfs_ciphers.state") == true)
                         { prefs.clearUserPref("extensions.clinker.pfs_ciphers.state"); }
      if (param == true) { prefs.setBoolPref("extensions.clinker.pfs_ciphers.state", true); }
      if (prefs.getBoolPref("extensions.clinker.high_ciphers") == false)
                         { prefs.clearUserPref("extensions.clinker.pfs_ciphers");
                           prefs.clearUserPref("extensions.clinker.pfs_ciphers.state");
                           prefs.clearUserPref("extensions.clinker.pfs_ciphers_toggle");
      }
   },
*/

   // enable or disable ciphers
   clinker_toggleCipherUser: function(param, prefs) {

   var cc = Components.classes;
   var ci = Components.interfaces;
   var prefs = cc["@mozilla.org/preferences-service;1"].getService(ci.nsIPrefBranch);

   // Ciphers 256 bit Perfect Forward Secrecy (PFS)
   const clinker_listCipher256pfs = ("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256;security.ssl3.ecdhe_rsa_aes_128_gcm_sha256;security.ssl3.ecdhe_rsa_aes_256_sha;security.ssl3.ecdhe_ecdsa_aes_256_sha;security.ssl3.dhe_rsa_camellia_256_sha;security.ssl3.dhe_rsa_aes_256_sha;security.ssl3.dhe_dss_camellia_256_sha;security.ssl3.dhe_dss_aes_256_sha").split(';');

   // Ciphers 128 bit Perfect Forward Secrecy (PFS)
   const clinker_listCipher128pfs = ("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256;security.ssl3.ecdhe_rsa_aes_128_gcm_sha256;security.ssl3.ecdhe_rsa_rc4_128_sha;security.ssl3.ecdhe_rsa_aes_256_sha;security.ssl3.ecdhe_rsa_aes_128_sha;security.ssl3.ecdhe_ecdsa_rc4_128_sha;security.ssl3.ecdhe_ecdsa_aes_256_sha;security.ssl3.ecdhe_ecdsa_aes_128_sha;security.ssl3.dhe_rsa_camellia_256_sha;security.ssl3.dhe_rsa_camellia_128_sha;security.ssl3.dhe_rsa_aes_256_sha;security.ssl3.dhe_rsa_aes_128_sha;security.ssl3.dhe_dss_camellia_256_sha;security.ssl3.dhe_dss_camellia_128_sha;security.ssl3.dhe_dss_aes_256_sha;security.ssl3.dhe_dss_aes_128_sha").split(';');

   // Ciphers 128 bit 
   const clinker_listCipher128 = ("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256;security.ssl3.ecdhe_rsa_aes_128_gcm_sha256;security.ssl3.rsa_rc4_128_sha;security.ssl3.rsa_rc4_128_md5;security.ssl3.rsa_camellia_256_sha;security.ssl3.rsa_camellia_128_sha;security.ssl3.rsa_aes_256_sha;security.ssl3.rsa_aes_128_sha;security.ssl3.ecdhe_rsa_rc4_128_sha;security.ssl3.ecdhe_rsa_aes_256_sha;security.ssl3.ecdhe_rsa_aes_128_sha;security.ssl3.ecdhe_ecdsa_rc4_128_sha;security.ssl3.ecdhe_ecdsa_aes_256_sha;security.ssl3.ecdhe_ecdsa_aes_128_sha;security.ssl3.ecdh_rsa_rc4_128_sha;security.ssl3.ecdh_rsa_aes_256_sha;security.ssl3.ecdh_rsa_aes_128_sha;security.ssl3.ecdh_ecdsa_rc4_128_sha;security.ssl3.ecdh_ecdsa_aes_256_sha;security.ssl3.ecdh_ecdsa_aes_128_sha;security.ssl3.dhe_rsa_camellia_256_sha;security.ssl3.dhe_rsa_camellia_128_sha;security.ssl3.dhe_rsa_aes_256_sha;security.ssl3.dhe_rsa_aes_128_sha;security.ssl3.dhe_dss_camellia_256_sha;security.ssl3.dhe_dss_camellia_128_sha;security.ssl3.dhe_dss_aes_256_sha;security.ssl3.dhe_dss_aes_128_sha").split(';');

   // list of all ciphers 
   const clinker_listCipherAll = ("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256;security.ssl3.ecdhe_rsa_aes_128_gcm_sha256;security.ssl3.rsa_seed_sha;security.ssl3.rsa_rc4_128_sha;security.ssl3.rsa_rc4_128_md5;security.ssl3.rsa_fips_des_ede3_sha;security.ssl3.rsa_des_ede3_sha;security.ssl3.rsa_camellia_256_sha;security.ssl3.rsa_camellia_128_sha;security.ssl3.rsa_aes_256_sha;security.ssl3.rsa_aes_128_sha;security.ssl3.ecdhe_rsa_rc4_128_sha;security.ssl3.ecdhe_rsa_des_ede3_sha;security.ssl3.ecdhe_rsa_aes_256_sha;security.ssl3.ecdhe_rsa_aes_128_sha;security.ssl3.ecdhe_ecdsa_rc4_128_sha;security.ssl3.ecdhe_ecdsa_des_ede3_sha;security.ssl3.ecdhe_ecdsa_aes_256_sha;security.ssl3.ecdhe_ecdsa_aes_128_sha;security.ssl3.ecdh_rsa_rc4_128_sha;security.ssl3.ecdh_rsa_des_ede3_sha;security.ssl3.ecdh_rsa_aes_256_sha;security.ssl3.ecdh_rsa_aes_128_sha;security.ssl3.ecdh_ecdsa_rc4_128_sha;security.ssl3.ecdh_ecdsa_des_ede3_sha;security.ssl3.ecdh_ecdsa_aes_256_sha;security.ssl3.ecdh_ecdsa_aes_128_sha;security.ssl3.dhe_rsa_des_ede3_sha;security.ssl3.dhe_rsa_camellia_256_sha;security.ssl3.dhe_rsa_camellia_128_sha;security.ssl3.dhe_rsa_aes_256_sha;security.ssl3.dhe_rsa_aes_128_sha;security.ssl3.dhe_dss_des_ede3_sha;security.ssl3.dhe_dss_camellia_256_sha;security.ssl3.dhe_dss_camellia_128_sha;security.ssl3.dhe_dss_aes_256_sha;security.ssl3.dhe_dss_aes_128_sha;security.enable_ssl3").split(';');

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
         for (var i=0; i<clinker_listCipherAll.length; i++) prefs.setBoolPref(clinker_listCipherAll[i], false);
         for (var i=0; i<clinker_listCipher256pfs.length; i++) prefs.setBoolPref(clinker_listCipher256pfs[i], true);
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
         for (var i=0; i<clinker_listCipherAll.length; i++) prefs.setBoolPref(clinker_listCipherAll[i], false);
         for (var i=0; i<clinker_listCipher128pfs.length; i++) prefs.setBoolPref(clinker_listCipher128pfs[i], true);
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
         for (var i=0; i<clinker_listCipherAll.length; i++) prefs.setBoolPref(clinker_listCipherAll[i], false);
         for (var i=0; i<clinker_listCipher128.length; i++) prefs.setBoolPref(clinker_listCipher128[i], true);
     }

     // Enable ALL ciphers (firefox defaults)
     if (prefs.getBoolPref("extensions.clinker.ciphers_all")) {
         prefs.clearUserPref("security.enable_tls");
         for (var i=0; i<clinker_listCipherAll.length; i++) prefs.clearUserPref(clinker_listCipherAll[i]);
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

  // events for mouse button clicks on the toolbar button. 0=left , 1=middle and 2=right mouse button
  clinkerButtonEvent: function(event) {
     if (event.type == "click" && event.button == 0) { this._clinkerPopup.openPopup(this._clinkerPopupContentUrlImage, 'after_start'); }
     if (event.type == "click" && event.button == 1) { window.openDialog('chrome://clinker/content/options.xul'); }
     if (event.type == "click" && event.button == 2) { clinker.startFirefox(); }
  },

  // collect the elements from xul 
  get _clinkerPopup () { return document.getElementById("clinker-popup"); },
  get _clinkerPopupContentUrlImage () { return document.getElementById("clinker-urlicon"); },
  get _clinkerPopupContentHost () { return document.getElementById("clinker-popup-content-host"); },
  get _clinkerPopupContentSecure () { return document.getElementById("clinker-popup-content-secure"); },
  get _clinkerPopupContentCertificate () { return document.getElementById("clinker-popup-content-certificate"); },
  get _clinkerPopupContentPfs () { return document.getElementById("clinker-popup-content-pfs"); },
  get _clinkerPopupContentCiphersuite () { return document.getElementById("clinker-popup-content-ciphersuite"); },
  get _clinkerPopupContentKeyExchange () { return document.getElementById("clinker-popup-content-key_exchange"); },
  get _clinkerPopupContentSignature () { return document.getElementById("clinker-popup-content-signature"); },
  get _clinkerPopupContentBulkCipher () { return document.getElementById("clinker-popup-content-bulk_cipher"); },
  get _clinkerPopupContentMAC () { return document.getElementById("clinker-popup-content-mac"); },
  get _clinkerPopupContentHomePage () { return document.getElementById("clinker-popup-content-homepage"); },
  get _clinkerPopupContentCommonName () { return document.getElementById("clinker-popup-content-commonname"); },
  get _clinkerPopupContentCertType () { return document.getElementById("clinker-popup-content-cert-type"); },
  get _clinkerPopupContentOrganization () { return document.getElementById("clinker-popup-content-organization"); },
  get _clinkerPopupContentOrganizationSubCert () { return document.getElementById("clinker-popup-content-organization-subcert"); },
  get _clinkerPopupContentOrganizationCaCert () { return document.getElementById("clinker-popup-content-organization-cacert"); },
  get _clinkerPopupContentOrganizationLocation () { return document.getElementById("clinker-popup-content-organization-location"); },
  get _clinkerPopupContentIssuerOrganization () { return document.getElementById("clinker-popup-content-issuer"); },
  get _clinkerPopupContentIssuerLocation () { return document.getElementById("clinker-popup-content-issuer-location"); },
  get _clinkerPopupContentValidBeforeDate () { return document.getElementById("clinker-popup-content-before-date"); },
  get _clinkerPopupContentValidAfterDate () { return document.getElementById("clinker-popup-content-after-date"); },
  get _clinkerPopupContentCurrentDate () { return document.getElementById("clinker-popup-content-current-date"); },

  //
  // page load section
  //

   onPageLoad: function() {

     const ci = Components.interfaces;
     const cc = Components.classes;
     const gb = window.getBrowser();
     const prefs = cc["@mozilla.org/preferences-service;1"].getService(ci.nsIPrefBranch);

     // initilize the popup window
     const clinker_current_greeting = "version 0.70";
     clinker._clinkerPopupContentSecure.textContent = clinker_current_greeting;
     clinker._clinkerPopupContentCurrentDate.textContent = (new Date());

     // Install the toolbar button on first install ONLY (mozilla code)
     var clinker_prefFirstInstall = prefs.getBoolPref("extensions.clinker.first_install");
     if (clinker_prefFirstInstall) {
      prefs.setBoolPref("extensions.clinker.first_install", false);
       try {
          var firefoxnav = document.getElementById("nav-bar");
          var curSet = firefoxnav.currentSet;
          if (curSet.indexOf("clinker-urlicon") == -1)
          {
            var set;
            // Place the button before the urlbar
            if (curSet.indexOf("urlbar-container") != -1)
              set = curSet.replace(/urlbar-container/, "clinker-urlicon,urlbar-container");
            else  // at the end
              set = curSet + ",clinker-urlicon";
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
       onStateChange:    function(aWebProgress, aRequest, aFlag, aStatus) { clinker.onPageUpdate(); },
       onLocationChange: function(aWebProgress, aRequest, aURI) { clinker.onPageUpdate(); },
       onSecurityChange: function(aWebProgress, aRequest, aState) { clinker.onPageUpdate(); },
       onStatusChange: function(aWebProgress) { return; },
       onProgressChange: function(aWebProgress) { return; }
     };

     //gb.addProgressListener(clinker_updateListener, ci.nsIWebProgress.NOTIFY_STATE_DOCUMENT);
       gb.addProgressListener(clinker_updateListener);
    },


  //
  // page loads, tab changed
  //
   onPageUpdate: function() {

     // CURRENT VERSION
     const clinker_current_version = 70;
     const clinker_current_greeting = "version 0.70";

     // global constants
     const cc = Components.classes;
     const ci = Components.interfaces;
     const gb = window.getBrowser();
     const prefs = cc["@mozilla.org/preferences-service;1"].getService(ci.nsIPrefBranch);
     var currentBrowser = gb.selectedBrowser;
     var ui = currentBrowser.securityUI;
     var insecureSSL = (ui.state & ci.nsIWebProgressListener.STATE_IS_INSECURE);
     var clinker_url_protocol = window.content.location.protocol;
     var clinker_conn_score = 0;
     var clinker_prefTabTitle = prefs.getBoolPref("extensions.clinker.tab_title");
   
     // open the clinker help page on update or install
     var clinker_prefHomeOnUpdate = prefs.getBoolPref("extensions.clinker.home_on_update");
     var clinker_prefVersion = prefs.getIntPref("extensions.clinker.version");
     if (clinker_prefHomeOnUpdate && clinker_prefVersion < clinker_current_version) {
       gBrowser.addTab("https://github.com/tomato42/clinker");
       prefs.setIntPref("extensions.clinker.version", clinker_current_version);
     }

     // if the toolbar button is not used on any toolbar just return
     if (document.getElementById("clinker-urlicon") == null ) return;

     // reset strings
     clinker._clinkerPopupContentHost.textContent = null;
     clinker._clinkerPopupContentSecure.textContent = clinker_current_greeting;
     clinker._clinkerPopupContentCiphersuite.textContent = null;
     clinker._clinkerPopupContentPfs.textContent         = null;
     clinker._clinkerPopupContentKeyExchange.textContent = null;
     clinker._clinkerPopupContentSignature.textContent   = null;
     clinker._clinkerPopupContentBulkCipher.textContent  = null;
     clinker._clinkerPopupContentMAC.textContent         = null;
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
     document.getElementById("clinker-urlicon").image="chrome://clinker/skin/clinker_grey_button.png";

     // clear the title and icon from the tab if the user prefers it
       if (clinker_prefTabTitle) {
          var current_tab = window.document.getElementById("content").selectedTab;
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
          var clinker_date_validity = clinker_ssl_cert.validity.QueryInterface(ci.nsIX509CertValidity);
          var clinker_ssl_cert_verification;
          if (status && !insecureSSL) {
             status.QueryInterface(ci.nsISSLStatus);
      }

      // Check ssl certificate security state flags
      if (Ci.nsIWebProgressListener.STATE_IS_SECURE) {
           clinker_ssl_cert_verification = "Verified";
      } else if (Ci.nsIWebProgressListener.STATE_IS_INSECURE) {
           clinker_ssl_cert_verification = "WARNING! not trusted";
           clinker_conn_score -= 100;
      } else {
           clinker_ssl_cert_verification = "WARNING! broken";
           clinker_conn_score -= 100;
      }

      // does the url hostname and certificate common name match?
      var clinker_hosts_match = " (DOMAIN MISMATCH!)";
            clinker_conn_score -= 100;
      if (! clinker_ssl_cert.isDomainMismatch) {
            clinker_hosts_match = " (matched)";
            clinker_conn_score += 100;
      }

         // print out the certificate info
         clinker._clinkerPopupContentHost.textContent             = ("\nURL Host        : "+ clinker_url_hostname);
         clinker._clinkerPopupContentCommonName.textContent         = ("Common Name (CN): " + clinker_ssl_cert.commonName + clinker_hosts_match);
         clinker._clinkerPopupContentOrganization.textContent     = ("\nIssued to  : " + clinker_ssl_cert.organization);
         clinker._clinkerPopupContentIssuerOrganization.textContent = ("Issued by  : " + clinker_ssl_cert.issuerOrganization);
         clinker._clinkerPopupContentValidBeforeDate.textContent    = ("Valid from : " + clinker_date_validity.notBeforeLocalTime);
         clinker._clinkerPopupContentValidAfterDate.textContent     = ("Valid until: " + clinker_date_validity.notAfterLocalTime);
         clinker._clinkerPopupContentCurrentDate.textContent        = ("\n" + new Date());
      } 

      // type of certificate validation EV or DV, OV seems unused
       if (ui.state & ci.nsIWebProgressListener.STATE_IDENTITY_EV_TOPLEVEL) {
            clinker._clinkerPopupContentCertType.textContent = ("Class      : Extended Validation (EV)");
       } else if (ui.state & ci.nsIWebProgressListener.STATE_IS_SECURE) {
            clinker._clinkerPopupContentCertType.textContent = ("Class      : Domain Validation (DV)");
       }

       // retrive the ssl cipher and key length
       if (status instanceof ci.nsISSLStatus) {
          var symetricCipher = status.cipherName;
          var symetricKeyLength = status.secretKeyLength;
       }

       // popup the ssl information if the connection is properly encrypted
       if (symetricCipher && symetricKeyLength ) {
            var clinker_key_strength = null;
            var clinker_cipher_strength = null;

      // get extended certificate information
      var serverCert = status.serverCert;
      if (serverCert instanceof ci.nsIX509Cert) {
        var certificatesAll = cc["@mozilla.org/security/nsASN1Tree;1"].createInstance(ci.nsIASN1Tree);
        certificatesAll.loadASN1Structure(serverCert.ASN1Structure);
        var clinker_SubjectPublicKeyStrength = "";
        var clinker_CertificateSignatureStrength = "";
        var clinker_SubjectPublicKeyAlgorithm = certificatesAll.getDisplayData(4).replace(/PKCS #1/g,'').replace(/Encryption/g,'@');
        var clinker_SubjectsPublicKey = certificatesAll.getDisplayData(12).split(" ")[1].replace(/\(/g,'');
        var clinker_CertificateSignatureAlgrithm = certificatesAll.getDisplayData(certificatesAll.rowCount-2).replace(/PKCS #1/g,'').replace(/Encryption/g,'@');
        var clinker_CertificateSignatureValue = certificatesAll.getDisplayData(certificatesAll.rowCount-1).split(" ");

        var clinker_SubjectsPublicKeyLocationCity = "", clinker_SubjectsPublicKeyLocationState = "", clinker_SubjectsPublicKeyLocationCountry="";
        var clinker_SubjectsPublicKeyLocation = certificatesAll.getDisplayData(9).split("\n");
        for( i=0; i < clinker_SubjectsPublicKeyLocation.length; i++ ) {
           if (clinker_SubjectsPublicKeyLocation[i].substring(0,3) == "L =") {
               clinker_SubjectsPublicKeyLocationCity = clinker_SubjectsPublicKeyLocation[i].replace(/L =/g,'');
           }
           if (clinker_SubjectsPublicKeyLocation[i].substring(0,4) == "ST =") {
               clinker_SubjectsPublicKeyLocationState = clinker_SubjectsPublicKeyLocation[i].replace(/ST =/g,'');
           }
           if (clinker_SubjectsPublicKeyLocation[i].substring(0,3) == "C =") {
               clinker_SubjectsPublicKeyLocationCountry = clinker_SubjectsPublicKeyLocation[i].replace(/C =/g,'');
           }
        }

        var clinker_SubjectsCertificateLocationCity = "", clinker_SubjectsCertificateLocationState = "", clinker_SubjectsCertificateLocationCountry="";
        var clinker_SubjectsCertificateLocation = certificatesAll.getDisplayData(5).split("\n");
        for( var i=0; i < clinker_SubjectsCertificateLocation.length; i++ ) {
           if (clinker_SubjectsCertificateLocation[i].substring(0,3) == "L =") {
               clinker_SubjectsCertificateLocationCity = clinker_SubjectsCertificateLocation[i].replace(/L =/g,'');
           }
           if (clinker_SubjectsCertificateLocation[i].substring(0,4) == "ST =") {
               clinker_SubjectsCertificateLocationState = clinker_SubjectsCertificateLocation[i].replace(/ST =/g,'');
           }
           if (clinker_SubjectsCertificateLocation[i].substring(0,3) == "C =") {
               clinker_SubjectsCertificateLocationCountry = clinker_SubjectsCertificateLocation[i].replace(/C =/g,'');
           }
        }

        // grade the stength of the subject certificates hashes

         if  (clinker_SubjectPublicKeyAlgorithm.indexOf("SHA") && clinker_SubjectsPublicKey == "Curve" && ( clinker_SubjectPublicKeyAlgorithm.contains("SHA-256") || clinker_SubjectPublicKeyAlgorithm.contains("SHA-512") ) ) {
               clinker_SubjectPublicKeyStrength = " (10/10)";
               clinker_conn_score += 10;
         } else if  (clinker_SubjectPublicKeyAlgorithm.indexOf("SHA") && parseInt(clinker_SubjectsPublicKey) > 2047 && ( clinker_SubjectPublicKeyAlgorithm.contains("SHA-256") || clinker_SubjectPublicKeyAlgorithm.contains("SHA-512") ) ) {
               clinker_SubjectPublicKeyStrength = " (10/10)";
               clinker_conn_score += 10;
         } else if  (clinker_SubjectPublicKeyAlgorithm.indexOf("SHA") && clinker_SubjectsPublicKey == "Curve" && clinker_SubjectPublicKeyAlgorithm.contains("SHA-1") ) {
               clinker_SubjectPublicKeyStrength = " (4/10)";
               clinker_conn_score += 4;
         } else if  (clinker_SubjectPublicKeyAlgorithm.indexOf("SHA") && parseInt(clinker_SubjectsPublicKey) > 2047 && clinker_SubjectPublicKeyAlgorithm.contains("SHA-1") ) {
               clinker_SubjectPublicKeyStrength = " (4/10)";
               clinker_conn_score += 4;
         } else {
             clinker_SubjectPublicKeyStrength = " (0/10)";
         }

        // grade the stength of the certificate authorities hashes
         if (clinker_CertificateSignatureAlgrithm.indexOf("SHA") && clinker_CertificateSignatureValue[4] == "Curve" && (clinker_CertificateSignatureAlgrithm.contains("SHA-256") || clinker_CertificateSignatureAlgrithm.contains("SHA-512") ) ) {
               clinker_CertificateSignatureStrength = " (10/10)";
               clinker_conn_score += 10;
         } else if (clinker_CertificateSignatureAlgrithm.indexOf("SHA") && parseInt(clinker_CertificateSignatureValue[4]) > 2047 && (clinker_CertificateSignatureAlgrithm.contains("SHA-256") || clinker_CertificateSignatureAlgrithm.contains("SHA-512") ) ) {
               clinker_CertificateSignatureStrength = " (10/10)";
               clinker_conn_score += 10;
         } else if (clinker_CertificateSignatureAlgrithm.indexOf("SHA") && clinker_CertificateSignatureValue[4] == "Curve" && clinker_CertificateSignatureAlgrithm.contains("SHA-1") ) {
               clinker_CertificateSignatureStrength = " (4/10)";
               clinker_conn_score += 4;
         } else if (clinker_CertificateSignatureAlgrithm.indexOf("SHA") && parseInt(clinker_CertificateSignatureValue[4]) > 2047 && clinker_CertificateSignatureAlgrithm.contains("SHA-1") ) {
               clinker_CertificateSignatureStrength = " (4/10)";
               clinker_conn_score += 4;
         } else {
             clinker_CertificateSignatureStrength = " (0/10)";
         }

        // print the info
        clinker._clinkerPopupContentOrganizationSubCert.textContent = ("           :" + clinker_SubjectPublicKeyAlgorithm + " " + clinker_SubjectsPublicKey + " bit" + clinker_SubjectPublicKeyStrength);
        clinker._clinkerPopupContentOrganizationCaCert.textContent  = ("           :" + clinker_CertificateSignatureAlgrithm + " " + clinker_CertificateSignatureValue[4] + " bit" + clinker_CertificateSignatureStrength);
        clinker._clinkerPopupContentOrganizationLocation.textContent  = ("           :" + clinker_SubjectsPublicKeyLocationCity + clinker_SubjectsPublicKeyLocationState + clinker_SubjectsPublicKeyLocationCountry);
        clinker._clinkerPopupContentIssuerLocation.textContent  = ("           :" + clinker_SubjectsCertificateLocationCity + clinker_SubjectsCertificateLocationState + clinker_SubjectsCertificateLocationCountry);

    }

          // setup the default strings for the drop down menu cipher suite values
          clinker._clinkerPopupContentCertificate.textContent = ("Certificate: " + clinker_ssl_cert_verification );
          clinker._clinkerPopupContentCiphersuite.textContent =  ("\nCiphersuite : " + symetricCipher );
          clinker._clinkerPopupContentPfs.textContent         =  ("\nPerfect Forward Secrecy [PFS]:  NO  ( 0/20)");
          clinker._clinkerPopupContentKeyExchange.textContent =  ("Key Exchange: unknown");
          clinker._clinkerPopupContentSignature.textContent   =  ("Signature   : unknown");
          clinker._clinkerPopupContentBulkCipher.textContent  =  ("Bulk Cipher : unknown");
          clinker._clinkerPopupContentMAC.textContent         =  ("MAC         : unknown");

          // grade the key exchange
          if ( symetricCipher.contains("TLS_ECDHE_") ) {
          clinker._clinkerPopupContentPfs.textContent         =  ("\nPerfect Forward Secrecy [PFS]:  YES  (20/20)");
          clinker._clinkerPopupContentKeyExchange.textContent =  ("Key Exchange: ECDHE [PFS]      (25/25)");
          clinker_conn_score += 45;
          } else if ( symetricCipher.contains("TLS_DHE_") ) {
          clinker._clinkerPopupContentPfs.textContent         =  ("\nPerfect Forward Secrecy [PFS]:  YES  (20/20)");
          clinker._clinkerPopupContentKeyExchange.textContent =  ("Key Exchange: DHE [PFS]        (20/25)");
          clinker_conn_score += 40;
          } else if ( symetricCipher.contains("TLS_ECDH_") ) {
          clinker._clinkerPopupContentKeyExchange.textContent =  ("Key Exchange: ECDH             (10/25)");
          clinker_conn_score += 10;
          } else if ( symetricCipher.contains("TLS_DH_") ) {
          clinker._clinkerPopupContentKeyExchange.textContent =  ("Key Exchange: DH               ( 7/25)");
          clinker_conn_score += 7;
          } else if ( symetricCipher.contains("TLS_RSA_WITH_") ) {
          clinker._clinkerPopupContentKeyExchange.textContent =  ("Key Exchange: RSA/server key   ( 3/25)");
          clinker_conn_score += 3;
          } else if ( symetricCipher.contains("SSL_RSA_WITH_") ) {
          clinker._clinkerPopupContentKeyExchange.textContent =  ("Key Exchange: RSA/server key   ( 1/25)");
          clinker_conn_score += 1;
          }

          // grade the signature
          if ( symetricCipher.contains("_ECDSA_WITH_") ) {
          clinker._clinkerPopupContentSignature.textContent   =  ("Signature   : ECDSA");
       // clinker._clinkerPopupContentSignature.textContent   =  ("Signature   : ECDSA            (13/13)");
       // clinker_conn_score += 13;
          } else if ( symetricCipher.contains("_RSA_WITH_") ) {
          clinker._clinkerPopupContentSignature.textContent   =  ("Signature   : RSA");
       // clinker._clinkerPopupContentSignature.textContent   =  ("Signature   : RSA              (10/13)");
       // clinker_conn_score += 10;
          }
 
          // grade the bulk cipher and bit length
          if ( symetricCipher.contains("_AES_256_") ) {
          clinker._clinkerPopupContentBulkCipher.textContent  =  ("Bulk Cipher : AES 256 bit      (15/15)");
          clinker_conn_score += 15;
          } else if ( symetricCipher.contains("_AES_128_") ) {
          clinker._clinkerPopupContentBulkCipher.textContent  =  ("Bulk Cipher : AES 128 bit      (15/15)");
          clinker_conn_score += 15;
          } else if ( symetricCipher.contains("_RC4_128_") ) {
          clinker._clinkerPopupContentBulkCipher.textContent  =  ("Bulk Cipher : RC4 128 bit      ( 4/15)");
          clinker_conn_score += 4;
          } else if ( symetricCipher.contains("_3DES_") ) {
          clinker._clinkerPopupContentBulkCipher.textContent  =  ("Bulk Cipher : 3DES 168 bit     ( 4/15)");
          clinker_conn_score += 4;
          } else if ( symetricCipher.contains("_CAMELLIA_256_") ) {
          clinker._clinkerPopupContentBulkCipher.textContent  =  ("Bulk Cipher : Camellia 256 bit (15/15)");
          clinker_conn_score += 15;
          } else if ( symetricCipher.contains("_CAMELLIA_128_") ) {
          clinker._clinkerPopupContentBulkCipher.textContent  =  ("Bulk Cipher : Camellia 128 bit (15/15)");
          clinker_conn_score += 15;
          }

          // grade the a Message Authentication Code (MAC)
          if ( symetricCipher.contains("_GCM_SHA256") ) {
          clinker._clinkerPopupContentMAC.textContent         =  ("MAC         : SHA-256 AEAD GCM (20/20)");
          clinker_conn_score += 20;
          } else if ( symetricCipher.contains("_GCM_SHA384") ) {
          clinker._clinkerPopupContentMAC.textContent         =  ("MAC         : SHA-384 AEAD GCM (20/20)");
          clinker_conn_score += 20;
          } else if ( symetricCipher.contains("_SHA384") ) {
          clinker._clinkerPopupContentMAC.textContent         =  ("MAC         : SHA-384          (10/20)");
          clinker_conn_score += 10;
          } else if ( symetricCipher.contains("_SHA256") ) {
          clinker._clinkerPopupContentMAC.textContent         =  ("MAC         : SHA-256          (10/20)");
          clinker_conn_score += 10;
          } else if ( symetricCipher.contains("_MD5") ) {
          clinker._clinkerPopupContentMAC.textContent         =  ("MAC         : MD5              ( 1/20)");
          clinker_conn_score += 1;
          } else if ( symetricCipher.contains("_SHA") ) {
          clinker._clinkerPopupContentMAC.textContent         =  ("MAC         : SHA-1            ( 8/20)");
          clinker_conn_score += 8; }

       }


       // Is the connection secure? 
       if (clinker_conn_score >= 90 ) {
         clinker._clinkerPopupContentSecure.textContent = ("Security   : " + "Very Strong (green " + clinker_conn_score + "%)");
         document.getElementById("clinker-urlicon").image="chrome://clinker/skin/clinker_green_button.png";
       } else if (clinker_conn_score >= 80 && clinker_conn_score <= 89 ) {
         clinker._clinkerPopupContentSecure.textContent = ("Security   : " + "Strong (blue " + clinker_conn_score + "%)");
         document.getElementById("clinker-urlicon").image="chrome://clinker/skin/clinker_blue_button.png";
       } else if (clinker_conn_score >= 70 && clinker_conn_score <= 79 ) {
         clinker._clinkerPopupContentSecure.textContent = ("Security   : " + "Moderate (yellow " + clinker_conn_score + "%)");
         document.getElementById("clinker-urlicon").image="chrome://clinker/skin/clinker_yellow_button.png";
   //  } else if (clinker_conn_score >= 50 && clinker_conn_score <= 69 ) {
   //    clinker._clinkerPopupContentSecure.textContent = ("Security   : " + "Weak (orange " + clinker_conn_score + "%)");
   //    document.getElementById("clinker-urlicon").image="chrome://clinker/skin/clinker_orange_button.png";
       } else if (clinker_conn_score <= 69 ) {
         clinker._clinkerPopupContentSecure.textContent = ("Security   : " + "WARNING! Very Weak (red " + clinker_conn_score + "%)");
         document.getElementById("clinker-urlicon").image="chrome://clinker/skin/clinker_red_button.png";
       }

       // if the ssl connection is just plain broke
       if (ui.state & ci.nsIWebProgressListener.STATE_IS_INSECURE || ui.state & ci.nsIWebProgressListener.STATE_IS_BROKEN) {
         clinker_conn_score = 0;
         clinker._clinkerPopupContentSecure.textContent = ("Security   : " + "WARNING! BROKEN or UNTRUSTED (red " + clinker_conn_score + "%)");
         document.getElementById("clinker-urlicon").image="chrome://clinker/skin/clinker_redbroke_button.png";
       }
     }

     // http clear connections
     if (clinker_url_protocol == "http:") {
       var clinker_url_hostname = window.content.location.hostname;
       clinker._clinkerPopupContentHost.textContent   = ("URL Host   : " + clinker_url_hostname);
       clinker._clinkerPopupContentSecure.textContent = ("Security   : " + "None - Unsecured");
       clinker._clinkerPopupContentCurrentDate.textContent        = (new Date());
       document.getElementById("clinker-urlicon").image="chrome://clinker/skin/clinker_grey_button.png";
      }

   },

};
