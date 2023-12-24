#include "mysqlx/abe_extern.h"
#include <string>  
#include <vector>
#include "mysqlx/abe/rewrite.h"
#include "mysqlx/abe/abe_crypto.h"
#include "mysqlx/xdevapi.h"

#define SQL_CURRENT_USER_KEY_PRIFIX \
    "select owner,encrypted_key,sig_db,sig_db_type,sig_kms,sig_kms_type \
    from mysql.abe_user_key where owner = '"
#define SQL_CURRENT_USER_KEY_SUFFIX "'"
#define SQL_CURRENT_USER_ATT "select current_abe_attribute()"
#define SQL_CURRENT_USER "select current_user()"

namespace mysqlx{
MYSQLX_ABI_BEGIN(2,0)

using rewrite_plan = mysqlx::abe::rewrite_plan;
using abe_crypto = mysqlx::abe::abe_crypto;

RowResult abe_query::execute(){
    try{
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
    CATCH_AND_WRAP
}

std::string abe_query::recover(const std::string &ct){
    try{
        std::string pt;
        crypto->decrypt(ct, pt);
        return pt;
    }
    CATCH_AND_WRAP
}


std::string abe_env::get_current_user_key(){
    try{
        std::string str = std::string(SQL_CURRENT_USER_KEY_PRIFIX);
        str += abe.user.user_id;
        str += std::string(SQL_CURRENT_USER_KEY_SUFFIX);

        RowResult res = sess->sql(str).execute();

        int row_num = res.count();
        int field_num = res.getColumnCount();
        if(row_num != 1){
            throw_error("It seems that you don't have the abe key, please contact the admininistrator.");
        }
        if(field_num != rewrite_plan::TABLE_ABE_UER_KEY_FIELD_NUM){
            throw_error("system table 'abe_user_key' error");
        }

        auto it = res.begin();
        std::string key_str = (*it).get(rewrite_plan::F_KEY_NUM).get<string>();
        std::string sig_db = (*it).get(rewrite_plan::F_SIG_DB_NUM).get<string>();
        std::string sig_db_type = (*it).get(rewrite_plan::F_SIG_DB_TYPE_NUM).get<string>();
        std::string sig_kms = (*it).get(rewrite_plan::F_SIG_KMS_NUM).get<string>();
        std::string sig_kms_type = (*it).get(rewrite_plan::F_SIG_KMS_TYPE_NUM).get<string>();

        std::string namehost = abe.user.user_id;
        std::string attrlist = abe.user.user_attr;
        abe.verify_db_sig(namehost + attrlist,sig_db);
        abe.verify_kms_sig(key_str,sig_kms);
        return key_str;
    }
    CATCH_AND_WRAP
}

std::string abe_env::get_current_user(){
    try{
        RowResult res = sess->sql(SQL_CURRENT_USER).execute();

        int field_num = res.count();
        int row_num = res.getColumnCount();
        if(row_num != 1 || field_num != 1){
            throw_error("abe query failed: get current user.");
        }

        auto it = res.begin();
        auto str = (*it).get(0).get<string>();
        std::string namehost(str);
        return namehost;
    }
    CATCH_AND_WRAP
}

std::string abe_env::get_current_user_abe_attribute(){
    try{
        RowResult res = sess->sql(SQL_CURRENT_USER_ATT).execute();

        int field_num = res.count();
        int row_num = res.getColumnCount();
        if(row_num != 1 || field_num != 1){
            throw_error("abe query failed: get current user abe attribute.");
        }

        auto it = res.begin();
        auto str = (*it).get(0).get<string>();
        std::string att(str);
        return att;
    }
    CATCH_AND_WRAP
}

void abe_env::abe_prepare_queries(const abe_parameters &params){
    try{
        std::string namehost = get_current_user();
        abe.set_name(namehost);
        std::string attrlist = get_current_user_abe_attribute();
        abe.set_att(attrlist);
        if(!check_abe_key()){
            update_abe_key(params.abe_key_path);
        }
    }
    CATCH_AND_WRAP
}

void abe_env::update_abe_key(std::string abe_key_path){
    try{
        std::string abe_key = get_current_user_key();
        abe.save_user_key(abe_key_path, abe_key);
    }
    CATCH_AND_WRAP
}

void abe_env::init(const abe_parameters &params){
    try{
        abe.init(params.abe_pp_path, params.abe_key_path, 
                    params.kms_cert_path, params.db_cert_path,
                    params.rsa_sk_path);
        abe_prepare_queries(params);
    }
    CATCH_AND_WRAP
}

void abe_encrypt(abe_crypto &abe, std::string pt, std::string policy, std::string &ct ){
    try{
        abe.encrypt(pt, policy, ct);
    }
    CATCH_AND_WRAP
}

void abe_decrypt(abe_crypto &abe, std::string ct, std::string &pt){
    try{
        abe.decrypt(ct, pt);
    }
    CATCH_AND_WRAP
}

MYSQLX_ABI_END(2,0)
}//namespace mysqlx
