#ifndef ABE_CRYPTO_H
#define ABE_CRYPTO_H
#include <string.h>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl/crypto.h"

namespace mysqlx{
namespace abe{

#define ABE_ERROR(msg) std::cerr << "error: " << (msg) << std::endl;
#define ABE_ERROR2(msg,comment) std::cerr << (msg) << (comment) << std::endl;
#define ABE_LOG(msg) std::cout << (msg) << std::endl;

#define RSA_Encrypt_length 245
#define RSA_Decrypt_length 256

struct abe_user{
  std::string user_id;
  std::string user_key = "";
  std::string user_attr;
};

class abe_crypto{
public:

    abe_crypto(){}
    abe_crypto(std::string name){user.user_id = name;}//name或者说user_id，即用户标识，一般和登录的数据库用户同名

    bool init(std::string mpk_path, std::string key_path, std::string kms_cert_path, std::string db_cert_path, std::string rsa_sk_path);
    void set_name(std::string namehost){user.user_id = namehost;}
    void set_att(std::string att) {user.user_attr = att;}
    bool import_mpk(std::string mpk_path);
    bool import_user_key(std::string key_path);
    bool save_user_key(std::string key_path, std::string key_str);
    bool check_abe_key();   //true: abe_key已存在

    bool encrypt(std::string pt, std::string policy, std::string &ct);
    bool decrypt(std::string ct, std::string &pt);

    bool import_db_cert(std::string db_cert_path);
    bool import_kms_cert(std::string kms_cert_path);
    bool import_sk(std::string rsa_sk_path);
    
    bool verify_db_sig(const std::string msg, const std::string sig_db_b64);
    bool verify_kms_sig(const std::string msg_b64, const std::string sig_kms_b64);

    struct abe_user user;
    ~abe_crypto();
private:
    std::string mpk;
    RSA *kms_pk = NULL;
    RSA *db_pk = NULL;
    RSA *sk = NULL;
    bool verify_sig(RSA *pk, unsigned char * msg, size_t msg_length, unsigned char * sig, size_t sig_length);
    bool rsa_decrypt(const std::string ct, std::string &pt);
    RSA * import_pk(const std::string cert_path, std::string &err_msg);
};

}//namespace mysqlx::abe
}//namespace mysqlx

#endif