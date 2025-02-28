#ifndef ABE_EXTERN_H
#define ABE_EXTERN_H
#include <string>  
#include <vector>
#include "abe/rewrite.h"
#include "abe/abe_crypto.h"
#include "xdevapi.h"
// #include "devapi/detail/result.h"
namespace mysqlx {
MYSQLX_ABI_BEGIN(2,0)

struct abe_parameters{
    std::string rsa_sk_path; //rsa私钥路径,用于解密
    std::string db_cert_path;  //db证书，用于验签
    std::string kms_cert_path;   //kms证书，用于验签

    std::string abe_key_path;    //abe密钥路径
    std::string abe_pp_path;     //abe公共参数路径，也可称mpk
};

class PUBLIC_API abe_query : public abe::rewrite_plan{
public:
    abe_query(Session * sess, abe::abe_crypto * abe, std::string sql): rewrite_plan(sql){
        this->sess = sess;
        set_crypto(abe);
    }

    //重写并执行
    RowResult execute();

    //解密
    std::string recover(const std::string &ct);

    //需要解密的列名
    std::vector<std::string> field_name_list;
    std::vector<unsigned int> field_num_list;
    std::vector<unsigned int> f_flag;//指示某列是否需要解密
private:
    Session * sess;
};

class PUBLIC_API abe_env{
public:
    abe_env(Session &sess){
        this->sess = &sess;
    }

    /*
        初始化abe的环境，包括所需abe密钥和证书、私钥等
    */
    void init(const abe_parameters &params);

    /*
        仿照原来的用法
        env.sql("select * ...").execute();
    */
    abe_query sql(std::string input){
        return abe_query(sess, &abe, input);
    }

    //解密
    std::string recover(const std::string &ct);

    bool check_abe_key(){
        return abe.check_abe_key();
    }

    /*
    init时如果存在abe_key则不重复下载，使用update_abe_key可以强制更新abe_key
    */
    void update_abe_key(std::string abe_key_path);


    Session * sess;
    abe::abe_crypto abe;

    void abe_prepare_queries(const abe_parameters &params);
    std::string get_current_user();
    std::string get_current_user_abe_attribute();
    std::string get_current_user_key();
};


void PUBLIC_API abe_encrypt(abe::abe_crypto &abe, std::string pt, std::string policy, std::string &ct );
void PUBLIC_API abe_decrypt(abe::abe_crypto &abe, std::string ct, std::string &pt);

void PUBLIC_API initialize_abe(){
    abe::_initialize_abe();
}
void PUBLIC_API shutdown_abe(){
    abe::_shutdown_abe();
}

MYSQLX_ABI_END(2,0)
}
// const std::string abe_rewrite(const std::string &query, const abe_crypto &abe);
#endif //ABE_EXTERN_H