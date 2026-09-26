# CVE-2019-5420

Ruby-on-Rails offers three different environments it can run in: development, test and production. You should obviously not have code running in development or test available on the internet but it (as always) happens (for example in staging environments).

Ruby-on-Rails uses “signed-sessions” to allow people to easily scale their applications. Over time, the way the sessions were handled changed. With 5.2.2, sessions are JSON encoded data that is protected using AES GCM (aes-256-gcm) by default.

CVE-2019–5420 is actually very simple. The key used to encrypt sessions can be guessed (or brute forced) in development mode as it is based on the name of the application. This issue can potentially be used to gain code execution (RCE) according to the advisory.

Simple pyton script exploits the above functionality.
