#include "mysqlx/abe_extern.h"
#include <string>  
#include <vector>
#include "mysqlx/abe/rewrite.h"
#include "mysqlx/abe/abe_crypto.h"
#include "mysqlx/xdevapi.h"


namespace mysqlx{
using rewrite_plan = mysqlx::abe::rewrite_plan;
using abe_crypto = mysqlx::abe::abe_crypto;

RowResult abe_query::execute(){
    parse_and_rewrite();

    field_name_list = get_field_name_list();

    RowResult res = sess->sql(real_sql).execute();

    auto it = res.getColumns().begin();
    auto end = res.getColumns().end();
    unsigned int i=0;
    for (;it != end;++it){
        std::string field_name = (*it).getColumnName();
        auto temp = std::find(field_name_list.begin(), field_name_list.end(), field_name);
        if(temp != field_name_list.end()){
            //该列是使用了abe_dec的列
            f_flag.push_back(1);
            field_num_list.push_back(i);
        }else{
            //普通列
            f_flag.push_back(0);
        }
        i++;
    }
    return res;
}

std::string abe_query::recover(const std::string &ct){
    std::string pt;
    if(!crypto->decrypt(ct, pt)){
        return pt;
    }
    return "";
}


std::string abe_env::get_current_user_key(){
    std::string str = "select owner,encrypted_key,sig_db,sig_db_type,sig_kms,sig_kms_type from mysql.abe_user_key";
    str += " where owner = '" + abe.user.user_id + "';";

    RowResult res = sess->sql(str).execute();

    int field_num = res.count();
    int row_num = res.getColumnCount();
    if(row_num != 1){
        ABE_LOG("It seems that you don't have the abe key, please contact the admininistrator");
    }
    if(field_num != rewrite_plan::TABLE_ABE_UER_KEY_FIELD_NUM){
        ABE_ERROR("system table 'abe_user_key' error");
        return "";
    }

    auto it = res.begin();
    std::string key_str = (*it).get(rewrite_plan::F_KEY_NUM).get<string>();
    std::string sig_db = (*it).get(rewrite_plan::F_SIG_DB_NUM).get<string>();
    std::string sig_db_type = (*it).get(rewrite_plan::F_SIG_DB_TYPE_NUM).get<string>();
    std::string sig_kms = (*it).get(rewrite_plan::F_SIG_KMS_NUM).get<string>();
    std::string sig_kms_type = (*it).get(rewrite_plan::F_SIG_KMS_TYPE_NUM).get<string>();

    std::string namehost = abe.user.user_id;
    std::string attrlist = abe.user.user_attr;
    if(!(abe.verify_db_sig(namehost + attrlist,sig_db) 
        && abe.verify_kms_sig(key_str,sig_kms))){
            return "";
    }
    return key_str;

}

std::string abe_env::get_current_user(){

    RowResult res = sess->sql("select current_user()").execute();

    int field_num = res.count();
    int row_num = res.getColumnCount();
    if(row_num != 1 || field_num != 1)  return "";

    auto it = res.begin();
    auto str = (*it).get(1).get<string>();
    std::string namehost(str);
    return namehost;
}

std::string abe_env::get_current_user_abe_attribute(){

    RowResult res = sess->sql("select current_abe_attribute()").execute();

    int field_num = res.count();
    int row_num = res.getColumnCount();
    if(row_num != 1 || field_num != 1)  return "";

    auto it = res.begin();
    auto str = (*it).get(1).get<string>();
    std::string att(str);
    return att;
}

bool abe_env::abe_prepare_queries(const abe_parameters &params){
    std::string namehost = get_current_user();
    if(namehost == ""){
        // ABE_ERROR("can't get your username and host!");
        return false;
    }else{
        abe.set_name(namehost);
        
    }
    std::string attrlist = get_current_user_abe_attribute();
    if(attrlist == ""){
        // ABE_ERROR("can't get your attrlist, please contact adminastrator.");
        return false;
    }else{
        abe.set_att(attrlist);
    }

    if(!check_abe_key()){
        std::string abe_key = get_current_user_key();
        if(abe_key == ""){
            return false;
        }else{
            //todo:存储abe_key的逻辑
            abe.save_user_key(params.abe_key_path, abe_key);
        }
    }
    return true;

}

bool abe_env::init(const abe_parameters &params){
    if(!abe.init(params.abe_pp_path, params.abe_key_path, 
                    params.kms_cert_path, params.db_cert_path,
                    params.rsa_sk_path)
        || abe_prepare_queries(params)){
        // ABE_ERROR("failed to init abe system");
        return false;
    }
    return false;
}

bool abe_encrypt(abe_crypto &abe, std::string pt, std::string policy, std::string &ct ){
    abe.encrypt(pt, policy, ct);
    return true;
}

bool abe_decrypt(abe_crypto &abe, std::string ct, std::string &pt){
    abe.decrypt(ct, pt);
    return true;
}

}//namespace mysqlx
