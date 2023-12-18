#ifndef ABE_EXTERN_H
#define ABE_EXTERN_H
#include <string>  
#include <vector>
#include "abe/rewrite.h"
#include "abe/abe_crypto.h"
#include "xdevapi.h"
// #include "devapi/detail/result.h"
namespace mysqlx {

struct abe_parameters{
    string rsa_sk_path; //rsa私钥路径,用于解密
    string db_cert_path;  //db证书，用于验签
    string kms_cert_path;   //kms证书，用于验签

    string abe_key_path;    //abe密钥路径
    string abe_pp_path;     //abe公共参数路径，也可称mpk
};

class abe_query : public abe::rewrite_plan{
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

class abe_env{
public:
    abe_env(Session &sess){
        this->sess = &sess;
    }

    /*
        初始化abe的环境，包括所需abe密钥和证书、私钥等
    */
    bool init(const abe_parameters &params);

    /*
        仿照原来的用法
        env.sql("select * ...").execute();
    */
    abe_query sql(std::string input){
        return abe_query(sess, &abe, input);
    }

    bool check_abe_key(){
        return abe.check_abe_key();
    }

private:
    Session * sess;
    abe::abe_crypto abe;

    bool abe_prepare_queries(const abe_parameters &params);
    std::string get_current_user();
    std::string get_current_user_abe_attribute();
    std::string get_current_user_key();
};


bool abe_encrypt(abe::abe_crypto &abe, std::string pt, std::string policy, std::string &ct );
bool abe_decrypt(abe::abe_crypto &abe, std::string ct, std::string &pt);
}
// const std::string abe_rewrite(const std::string &query, const abe_crypto &abe);
#endif //ABE_EXTERN_H