#ifndef ABE_CRYPTO_H
#define ABE_CRYPTO_H
#include <string.h>
#include <fstream>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl/crypto.h"

using namespace oabe;
using namespace oabe::crypto;
using std::string;

#define ABE_ERROR(msg) std::cerr << "error: " << (msg) << std::endl;
#define ABE_ERROR2(msg,comment) std::cerr << (msg) << (comment) << std::endl;
#define ABE_LOG(msg) std::cout << (msg) << std::endl;

#define RSA_Encrypt_length 245
#define RSA_Decrypt_length 256

struct abe_user{
  string user_id;
  string user_key = "";
  string user_attr;
};

class abe_crypto{
public:

    abe_crypto(string name){user.user_id = name;}//name或者说user_id，即用户标识，一般和登录的数据库用户同名

    bool init(string mpk_path, string key_path, string kms_cert_path, string db_cert_path, string rsa_sk_path);
    void set_name(string namehost){user.user_id = namehost;}
    void set_att(string att) {user.user_attr = att;}
    bool import_mpk(string mpk_path);
    bool import_user_key(string key_path);
    bool save_user_key(string key_path, string key_str);
    bool check_abe_key();   //true: abe_key已存在

    bool encrypt(string pt, string policy, string &ct);
    bool decrypt(string ct, string &pt);

    bool import_db_cert(string db_cert_path);
    bool import_kms_cert(string kms_cert_path);
    bool import_sk(string rsa_sk_path);
    
    bool verify_db_sig(const string msg, const string sig_db_b64);
    bool verify_kms_sig(const string msg_b64, const string sig_kms_b64);

    struct abe_user user;
    ~abe_crypto();
private:
    string mpk;
    RSA *kms_pk = NULL;
    RSA *db_pk = NULL;
    RSA *sk = NULL;
    bool verify_sig(RSA *pk, unsigned char * msg, size_t msg_length, unsigned char * sig, size_t sig_length);
    bool rsa_decrypt(const string ct, string &pt);
    RSA * import_pk(const string cert_path, string &err_msg);
};
#endif