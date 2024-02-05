#include <fstream>
#include <cassert>
#include <iostream>
#include <unistd.h>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <mutex>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl/crypto.h"
#include "mysqlx/abe/abe_crypto.h"
#include "mysqlx/abe/base64.h"

namespace mysqlx{
MYSQLX_ABI_BEGIN(2,0)
namespace abe{

void abe_crypto::encrypt(std::string pt, std::string policy, std::string &ct){
  oabe::OpenABEStateContext thread_context;
  thread_context.initializeThread();
  oabe::OpenABECryptoContext cpabe("CP-ABE");
  cpabe.importPublicParams(mpk);
  cpabe.encrypt(policy.c_str(), pt, ct);
  thread_context.shutdownThread();
}

void abe_crypto::decrypt(const std::string ct, std::string &pt){
  
  if(!check_abe_key()){
    ABE_ERROR("no abe key!");
  }

  oabe::OpenABEStateContext thread_context;
  thread_context.initializeThread();
  oabe::OpenABECryptoContext cpabe("CP-ABE");
  cpabe.importPublicParams(mpk);
  cpabe.importUserKey(user.user_id.c_str(), user.user_key);
  if(!cpabe.decrypt(user.user_id.c_str(), ct, pt)){
    thread_context.shutdownThread();
    ABE_ERROR("abe: can't decrypt.");
  }
  thread_context.shutdownThread();
}

bool abe_crypto::check_abe_key(){
    if(user.user_key == ""){
        return false;
    }
    return true;
}


void abe_crypto::init(std::string mpk_path, std::string key_path, 
                        std::string kms_cert_path, std::string db_cert_path,
                        std::string rsa_sk_path){
    import_mpk(mpk_path);
    import_db_cert(db_cert_path);
    import_kms_cert(kms_cert_path);
    import_sk(rsa_sk_path);
    if(!import_user_key(key_path)){ //abe_user_key可以之后获取
        user.user_key = "";
    }
}

void abe_crypto::import_mpk(std::string mpk_path){
    //读入mpk
    std::ifstream ifs_mpk(mpk_path, std::ios::in);
    if(!ifs_mpk){
        ifs_mpk.close();
        ABE_ERROR2("error opening security pameter (mpk) file.\nmpk_path=", mpk_path);
    }
    ifs_mpk>>mpk;
    ifs_mpk.close();
}

bool abe_crypto::import_user_key(std::string key_path){
    //读入abe_user_key
    std::ifstream ifs_key(key_path, std::ios::in);
    if(!ifs_key){
        return false;
    }
    ifs_key>>user.user_key;
    ifs_key.close();
    return true;
}

void abe_crypto::save_user_key(std::string key_path, std::string key_str_b64){
    std::string pt;

    //key_str为base64编码
    size_t key_str_b64_length = key_str_b64.length();
    char * key_str = (char*)malloc(base64_utils::b64_dec_len(key_str_b64_length));
    size_t key_str_length = base64_utils::b64_decode(key_str_b64.c_str(), key_str_b64_length, (char*)key_str);
    // base64_utils::b64_decode(key_str_b64.c_str(), key_str_b64_length, (char*)key_str);

    std::string ct(key_str,key_str_length);
    if(!rsa_decrypt(ct, pt)){
        free(key_str);
        ABE_ERROR("failed to decrypt abe user key");
    }
    free(key_str);

    //写入abe_user_key
    std::ofstream ofs_key(key_path, std::ios::out);
    if(!ofs_key){
        ABE_ERROR2("error opening user key-file.\nkey_path=" , key_path);
    }
    ofs_key << pt;
    user.user_key = pt;
    ofs_key.close();
}

void abe_crypto::import_sk(std::string rsa_sk_path){
    // 导入rsa密钥文件并读取密钥
    FILE *hPriKeyFile = fopen(rsa_sk_path.c_str(), "rb");
    if (hPriKeyFile == NULL)
    {
        ABE_ERROR2("read file failed, file_path=", rsa_sk_path);
    }
    std::string strRet;
    RSA *pRSAPriKey = RSA_new();
    if (PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
    { // 密钥读取失败
        // assert(false);
        RSA_free(pRSAPriKey);
        fclose(hPriKeyFile);
        ABE_ERROR2("read rsa prikey failed, file_path=", rsa_sk_path);
    }
    sk = pRSAPriKey;
    fclose(hPriKeyFile);
}

RSA * abe_crypto::import_pk(const std::string cert_path, std::string &err_msg){
    RSA * pk;
    // 导入证书文件并读取公钥
    FILE *hPubKeyFile = fopen(cert_path.c_str(), "rb");
    if (hPubKeyFile == NULL)
    {
        err_msg = "failed to open cert file";
        return NULL;
    }
    X509 *cert = PEM_read_X509(hPubKeyFile, nullptr, nullptr, nullptr);
    if(cert == NULL){
        err_msg = "failed to read publib key from cert file";
        fclose(hPubKeyFile);
        return NULL;
    }
    fclose(hPubKeyFile);

    EVP_PKEY *evp_key = X509_get_pubkey(cert);
    if(evp_key == NULL){
        err_msg = "failed to get publib key from cert file";
        X509_free(cert);
        return NULL;
    }
    X509_free(cert);

    pk = EVP_PKEY_get1_RSA(evp_key);
    if(pk == NULL){
        err_msg = "failed to get rsa publib key from cert file";
        EVP_PKEY_free(evp_key);
        return NULL;
    }
    EVP_PKEY_free(evp_key);

    return pk;
}

void abe_crypto::import_db_cert(std::string db_cert_path){
    std::string err_msg;
    RSA *pk = import_pk(db_cert_path, err_msg);
    if(pk == NULL){
        err_msg += ":" + db_cert_path;
        ABE_ERROR(err_msg.c_str());
    }
    db_pk = pk;
}

void abe_crypto::import_kms_cert(std::string kms_cert_path){
    std::string err_msg;
    RSA *pk = import_pk(kms_cert_path, err_msg);
    if(pk == NULL){
        err_msg += ":" + kms_cert_path;
        ABE_ERROR(err_msg.c_str());
    }
    kms_pk = pk;
}

abe_crypto::~abe_crypto(){
    if(kms_pk!= NULL)   RSA_free(kms_pk);
    if(db_pk!= NULL)   RSA_free(db_pk);
    if(sk != NULL)  RSA_free(sk);
}

void abe_crypto::verify_sig(RSA *pk, unsigned char * msg, size_t msg_length, unsigned char * sig, size_t sig_length){
    unsigned char digest[SHA512_DIGEST_LENGTH];
    // 对输入进行hash
    SHA512(msg, msg_length, digest);

    // 对签名进行认证
    int ret = RSA_verify(NID_sha512, digest, SHA512_DIGEST_LENGTH, sig, sig_length, pk);
    if (ret != 1){
        unsigned long ulErr = ERR_get_error();
        char szErrMsg[1024] = {0};
        ERR_error_string(ulErr, szErrMsg); // 格式：error:errId:库:函数:原因
        ABE_ERROR2("abe_key verify error: ", szErrMsg);
    }

}

void abe_crypto::verify_db_sig(const std::string msg, const std::string sig_b64){
    //sig是base64编码，需要先解码
    size_t sig_b64_length = sig_b64.length();
    unsigned char * sig = (unsigned char*)malloc(base64_utils::b64_dec_len(sig_b64_length));
    size_t sig_length = base64_utils::b64_decode(sig_b64.c_str(), sig_b64_length, (char*)sig);

    try{
        verify_sig(db_pk, (unsigned char *)msg.c_str(), msg.length(), sig, sig_length);
        free(sig);
    }catch(const ::mysqlx::abe::Error& e){
        free(sig);
        ABE_ERROR2("db_sig:", e.what());
    }catch(...){
        free(sig);
        ABE_ERROR("nknown exception");
    }
}

void abe_crypto::verify_kms_sig(const std::string msg_b64, const std::string sig_b64){

    //msg和sig都是base64编码，需要先解码
    size_t msg_b64_length = msg_b64.length();
    unsigned char * msg = (unsigned char*)malloc(base64_utils::b64_dec_len(msg_b64_length));
    size_t msg_length = base64_utils::b64_decode(msg_b64.c_str(), msg_b64_length, (char*)msg);

    size_t sig_b64_length = sig_b64.length();
    unsigned char * sig = (unsigned char*)malloc(base64_utils::b64_dec_len(sig_b64_length));
    size_t sig_length = base64_utils::b64_decode(sig_b64.c_str(), sig_b64_length, (char*)sig);

    try{
        verify_sig(kms_pk, msg, msg_length, sig, sig_length);
        free(msg);
        free(sig);
    }catch(const ::mysqlx::abe::Error& e){
        free(msg);
        free(sig);
        ABE_ERROR2("kms_sig:", e.what());
    }catch(...){
        free(msg);
        free(sig);
        ABE_ERROR("nknown exception");
    }
}

//注意ct初始化时必须指定长度，否则ct.length会因为0x00而截断
bool abe_crypto::rsa_decrypt(const std::string ct, std::string &pt){
    int nLen = RSA_size(sk);
    char *pDecode = new char[nLen + 1];
    bool flag = true;
    // 解密，不限长度，但为RSA_Decrypt_length的整数倍
    if (ct.length() < RSA_Decrypt_length + 1)
    { // 一个分组的情况
        int ret = RSA_private_decrypt(ct.length(), (const unsigned char *)ct.c_str(),
                                      (unsigned char *)pDecode, sk, RSA_PKCS1_PADDING);
        if (ret >= 0)
        { // 解密成功
            pt = std::string((char *)pDecode, ret);
        }
        else
        { // 解密失败
            pt = "";
            flag = false;
        }
    }
    else
    { // 多个分组
        for (int i = 0; i < (int)ct.length() / (int)RSA_Decrypt_length; i++)
        {
            std::string Data = ct.substr(i * RSA_Decrypt_length, RSA_Decrypt_length);
            int ret = RSA_private_decrypt(Data.length(), (const unsigned char *)Data.c_str(),
                                          (unsigned char *)pDecode, sk, RSA_PKCS1_PADDING);
            if (ret >= 0)
            {
                pt += std::string(pDecode, ret);
            }
            else
            { // 解密失败
                pt = "";
                flag = false;
                break;
            }
        }
    }

    delete[] pDecode;
    CRYPTO_cleanup_all_ex_data();
    return flag;
}

void _initialize_abe(){
    oabe::InitializeOpenABE();
}

void _shutdown_abe(){
    oabe::ShutdownOpenABE();
}


}//namespace mysqlx::abe

MYSQLX_ABI_END(2,0)
}//namespace mysqlx