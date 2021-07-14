package com.gray17.cipher;

// Each user has a unique salt
// This salt must be recomputed during password change
class UserInfo {
    String userEncryptedPassword;
    String userSalt;
    String userName;
}