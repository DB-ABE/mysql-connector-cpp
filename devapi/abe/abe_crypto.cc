#include <fstream>
#include <cassert>
#include <iostream>
#include <unistd.h>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl/crypto.h"
#include "mysqlx/abe/abe_crypto.h"
#include "mysqlx/abe/base64.h"

namespace mysqlx{
namespace abe{

bool abe_crypto::encrypt(std::string pt, std::string policy, std::string &ct){
  
  oabe::InitializeOpenABE();
  oabe::OpenABECryptoContext cpabe("CP-ABE");
  cpabe.importPublicParams(mpk);
  cpabe.encrypt(policy.c_str(), pt, ct);
  oabe::ShutdownOpenABE();
  
//   std::cout<<"encrypt succefully!"<<std::endl;
  return true;
}

bool abe_crypto::decrypt(std::string ct, std::string &pt){
  
  if(!check_abe_key()){
    return false;
  }

  oabe::InitializeOpenABE();
  oabe::OpenABECryptoContext cpabe("CP-ABE");
  cpabe.importPublicParams(mpk);
  cpabe.importUserKey(user.user_id.c_str(), user.user_key);
  if(!cpabe.decrypt(user.user_id.c_str(), ct, pt)){
    pt = "can't decrypt.";
  }
//   std::cout << "Recovered message: " << pt << std::endl;
  oabe::ShutdownOpenABE();
  
  return true;
}

bool abe_crypto::check_abe_key(){
    if(user.user_key == ""){
        ABE_ERROR("there is no abe_key, please run:\n\tshow current_abe_key;\nto get from database");
        return false;
    }
    return true;
}


bool abe_crypto::init(std::string mpk_path, std::string key_path, 
                        std::string kms_cert_path, std::string db_cert_path,
                        std::string rsa_sk_path){
    if(!(import_mpk(mpk_path) 
        && import_db_cert(db_cert_path) && import_kms_cert(kms_cert_path)
        && import_sk(rsa_sk_path))){
        return false;
    }
    if(!import_user_key(key_path)){ //abe_user_key可以之后获取
        user.user_key = "";
    }
    return true;
}

bool abe_crypto::import_mpk(std::string mpk_path){
    //读入mpk
    std::ifstream ifs_mpk(mpk_path, std::ios::in);
    if(!ifs_mpk){
        ABE_ERROR2("error opening security pameter (mpk) file.\nmpk_path=", mpk_path);
        return false;
    }
    ifs_mpk>>mpk;
    ifs_mpk.close();
    return true;
}

bool abe_crypto::import_user_key(std::string key_path){
    //读入abe_user_key
    std::ifstream ifs_key(key_path, std::ios::in);
    if(!ifs_key){
        ABE_ERROR("there is no abe_key, please run:\n\tshow current_abe_key;\nto get from database");
        return false;
    }
    ifs_key>>user.user_key;
    ifs_key.close();
    return true;
}

bool abe_crypto::save_user_key(std::string key_path, std::string key_str_b64){
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
        return false;
    }
    free(key_str);

    if(pt == ""){
        //todo: 后续可以考虑增加一个参数决定每次启动是否更新abe_key
        //或者提供一个函数让程序员自行决定是否更新
        return false;
    }
    //写入abe_user_key
    std::ofstream ofs_key(key_path, std::ios::out);
    if(!ofs_key){
        ABE_ERROR2("error opening user key-file.\nkey_path=" , key_path);
        return false;
    }
    ofs_key << pt;
    user.user_key = pt;
    ofs_key.close();
    return true;
}

bool abe_crypto::import_sk(std::string rsa_sk_path){
    // 导入rsa密钥文件并读取密钥
    FILE *hPriKeyFile = fopen(rsa_sk_path.c_str(), "rb");
    if (hPriKeyFile == NULL)
    {
        // assert(false);
        return false;
    }
    std::string strRet;
    RSA *pRSAPriKey = RSA_new();
    if (PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
    { // 密钥读取失败
        // assert(false);
        RSA_free(pRSAPriKey);
        fclose(hPriKeyFile);
        return false;
    }
    sk = pRSAPriKey;
    fclose(hPriKeyFile);
    return true;
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

bool abe_crypto::import_db_cert(std::string db_cert_path){
    std::string err_msg;
    RSA *pk = import_pk(db_cert_path, err_msg);
    if(pk == NULL){
        err_msg += ":" + db_cert_path;
        ABE_ERROR(err_msg);
        return false;
    }
    db_pk = pk;
    return true;
}

bool abe_crypto::import_kms_cert(std::string kms_cert_path){
    std::string err_msg;
    RSA *pk = import_pk(kms_cert_path, err_msg);
    if(pk == NULL){
        err_msg += ":" + kms_cert_path;
        ABE_ERROR(err_msg);
        return false;
    }
    kms_pk = pk;
    return true;
}

abe_crypto::~abe_crypto(){
    if(kms_pk!= NULL)   RSA_free(kms_pk);
    if(db_pk!= NULL)   RSA_free(db_pk);
    if(sk != NULL)  RSA_free(sk);
}

bool abe_crypto::verify_sig(RSA *pk, unsigned char * msg, size_t msg_length, unsigned char * sig, size_t sig_length){
    unsigned char digest[SHA512_DIGEST_LENGTH];
    // 对输入进行hash
    SHA512(msg, msg_length, digest);

    // 对签名进行认证
    int ret = RSA_verify(NID_sha512, digest, SHA512_DIGEST_LENGTH, sig, sig_length, pk);
    if (ret != 1){
        ABE_ERROR("verify error");
        unsigned long ulErr = ERR_get_error();
        char szErrMsg[1024] = {0};
        ABE_ERROR2("error number:" , ulErr);
        ERR_error_string(ulErr, szErrMsg); // 格式：error:errId:库:函数:原因
        std::cout << szErrMsg << std::endl;
        return false;
    }
    return true;

}

bool abe_crypto::verify_db_sig(const std::string msg, const std::string sig_b64){
    //sig是base64编码，需要先解码
    size_t sig_b64_length = sig_b64.length();
    unsigned char * sig = (unsigned char*)malloc(base64_utils::b64_dec_len(sig_b64_length));
    size_t sig_length = base64_utils::b64_decode(sig_b64.c_str(), sig_b64_length, (char*)sig);

    if(!verify_sig(db_pk, (unsigned char *)msg.c_str(), msg.length(), sig, sig_length)){
        free(sig);
        ABE_ERROR("db_sig: verify failed");
        return false;
    }
    ABE_LOG("db_sig: verify success");
    free(sig);
    return true;
}

bool abe_crypto::verify_kms_sig(const std::string msg_b64, const std::string sig_b64){

    //msg和sig都是base64编码，需要先解码
    size_t msg_b64_length = msg_b64.length();
    unsigned char * msg = (unsigned char*)malloc(base64_utils::b64_dec_len(msg_b64_length));
    size_t msg_length = base64_utils::b64_decode(msg_b64.c_str(), msg_b64_length, (char*)msg);

    size_t sig_b64_length = sig_b64.length();
    unsigned char * sig = (unsigned char*)malloc(base64_utils::b64_dec_len(sig_b64_length));
    size_t sig_length = base64_utils::b64_decode(sig_b64.c_str(), sig_b64_length, (char*)sig);

    if(!verify_sig(kms_pk, msg, msg_length, sig, sig_length)){
        free(msg);
        free(sig);
        ABE_ERROR("kms_sig: verify failed");
        return false;
    }
    
    ABE_LOG("kms_sig: verify success");
    free(msg);
    free(sig);
    return true;
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

}//namespace mysqlx::abe
}//namespace mysqlx