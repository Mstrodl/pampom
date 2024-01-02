# PamPom

A PAM module for running multiple PAM sessions at the same time. The first to return success is used.

It lets you do some pretty cool stuff like this:

```
# /etc/pam.d/sudo
auth sufficient pam_pampom.so nullok layer=pampom_fprint layer=pampom_unix layer=pampom_howdy
# (Truncated)
```

```
# /etc/pam.d/pampom_fprint
auth required pam_fprintd.so
```

```
# /etc/pam.d/pampom_unix
auth required pam_unix.so try_first_pass likeauth nullok debug audit
```

```
# /etc/pam.d/pampom_howdy
auth required pam_python.so /lib/security/howdy/pam.py
```

This configuration will let you attempt facial recognition, fingerprint, and normal password login all at the same time! In other words, you don't need to press enter at a password prompt to be allowed to use fingerprint login. And, if the fingerprint login isn't working well, you can still try the password login without needing to restart the login session! AND, while all this is happening, it's trying to recognize your face with howdy. Pretty cool, right?


## Installing

All you should need is:
```
cargo build --release
sudo cp target/release/libpam_pampom.so /usr/lib/security/pam_pampom.so
```
