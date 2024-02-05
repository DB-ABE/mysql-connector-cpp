#ifndef ABE_CRYPTO_H
#define ABE_CRYPTO_H
#include <string.h>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl/crypto.h"
#include "../common/api.h"
#include "../common/error.h"

namespace mysqlx{
MYSQLX_ABI_BEGIN(2,0)
namespace abe{

//define the abe error class, maintain the independence of abe module
class PUBLIC_API Error : public common::Error
{
public:
  Error(const char *msg)
    : common::Error(msg)
  {}
};

inline
void throw_error(const char *msg)
{
  throw Error(msg);
}

inline void my_abe_throw_error2(const std::string msg, const std::string comment){
  std::string str = std::string(msg) + std::string(comment);
  throw_error(str.c_str());
}

inline void my_abe_throw_error3(const std::string msg, const std::string comment1, const std::string comment2){
  std::string str = std::string(msg) + std::string(comment1) + std::string(comment2);
  throw_error(str.c_str());
}

#define ABE_ERROR(msg) throw_error(msg);
#define ABE_ERROR2(msg,comment) my_abe_throw_error2(msg, comment);
#define ABE_ERROR3(msg,comment1, comment2) my_abe_throw_error3(msg, comment1, comment2);
// #define ABE_LOG(msg) std::cout << (msg) << std::endl;


#define RSA_Encrypt_length 245
#define RSA_Decrypt_length 256

struct abe_user{
  std::string user_id;
  std::string user_key = "";
  std::string user_attr;
};

class PUBLIC_API abe_crypto{
public:

    abe_crypto(){}
    abe_crypto(std::string name){user.user_id = name;}//name或者说user_id，即用户标识，一般和登录的数据库用户同名

    void init(std::string mpk_path, std::string key_path, std::string kms_cert_path, std::string db_cert_path, std::string rsa_sk_path);
    void set_name(std::string namehost){user.user_id = namehost;}
    void set_att(std::string att) {user.user_attr = att;}
    void import_mpk(std::string mpk_path);
    bool import_user_key(std::string key_path);
    void save_user_key(std::string key_path, std::string key_str);
    bool check_abe_key();   //true: abe_key已存在

    void encrypt(std::string pt, std::string policy, std::string &ct);
    void decrypt(const std::string ct, std::string &pt);

    void import_db_cert(std::string db_cert_path);
    void import_kms_cert(std::string kms_cert_path);
    void import_sk(std::string rsa_sk_path);
    
    void verify_db_sig(const std::string msg, const std::string sig_db_b64);
    void verify_kms_sig(const std::string msg_b64, const std::string sig_kms_b64);

    struct abe_user user;
    ~abe_crypto();
private:
    std::string mpk;
    RSA *kms_pk = NULL;
    RSA *db_pk = NULL;
    RSA *sk = NULL;
    void verify_sig(RSA *pk, unsigned char * msg, size_t msg_length, unsigned char * sig, size_t sig_length);
    bool rsa_decrypt(const std::string ct, std::string &pt);
    RSA * import_pk(const std::string cert_path, std::string &err_msg);
};

void PUBLIC_API _initialize_abe();
void PUBLIC_API _shutdown_abe();

}//namespace mysqlx::abe
MYSQLX_ABI_END(2,0)
}//namespace mysqlx

#endif