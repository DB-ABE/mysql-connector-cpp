// #include "SQLParser.h"
// #include "util/sqlhelper.h"
#ifndef REWRITE_H
#define REWRITE_H
#include <string>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <regex>
#include "abe_crypto.h"


namespace mysqlx{
namespace abe{
enum CommandType{
    BEGIN,
    COM_SELECT_CURRENT_USER,
    COM_GET_ABE_KEY,
    COM_SELECT,
    COM_INSERT,
    COM_SHOW,
    END,

    COM_OTHER,
    WRONG_SQL
};


struct RegexPatterns{
public:
    std::regex ABE_ENC_PATTERN;
    std::regex ABE_ENC_SQL_PATTERN;
    std::regex ABE_DEC_PATTERN;
    std::regex ABE_DEC_SQL_PATTERN;

    std::unordered_map<CommandType, std::regex> mp;

    RegexPatterns(){
        const std::string ABE_ANY_R = ".*?";
        const std::string ABE_COMMA_R = "\\s*,\\s*";
        const std::string ABE_SUFIX_R = "\\s*\\)";

        const std::string ABE_ENC_PREFIX_R = "abe_enc\\(\\s*";
        const std::string ABE_ENC_DATA_R = "['\"`]((?:\\\\\"|\\\\\\(|\\\\\\)|[^\"\\(\\)])+)['\"`]"; // 真实正则：((?:\\"|\\\(|\\\)|[^\"\(\)])+)
        const std::string ABE_ENC_POLICY_R = "['\"`]((?:\\\\\"|\\\\\\(|\\\\\\)|[^\"\\(\\)])+)['\"`]";
        const std::string ABE_ENC_REGEX = ABE_ENC_PREFIX_R + ABE_ENC_DATA_R
                                            + ABE_COMMA_R + ABE_ENC_POLICY_R + ABE_SUFIX_R;     //加密函数正则
        const std::string ABE_ENC_SQL_REGEX =  ABE_ANY_R + ABE_ENC_REGEX + ABE_ANY_R;  

        const std::string ABE_DEC_PREFIX_R = "abe_dec\\(\\s*";
        const std::string ABE_DEC_FIELD_R = "[`]*(\\w+)[`]*";
        const std::string ABE_DEC_REGEX = ABE_DEC_PREFIX_R + ABE_DEC_FIELD_R + ABE_SUFIX_R;      //解密函数正则
        const std::string ABE_DEC_SQL_REGEX = ABE_ANY_R + ABE_DEC_REGEX + ABE_ANY_R;

        const std::string COM_SELECT_SQL_REGEX = "\\s*select.*";
        const std::string COM_INSERT_SQL_REGEX = "\\s*insert.*";
        const std::string COM_SHOW_SQL_REGEX = "\\s*show.*";
        const std::string COM_SELECT_CURRENT_USER_SQL_REGEX = "\\s*select\\s+current_user().*";
        const std::string GET_ABE_KEY_REGEX = "\\s*show\\s+current_abe_key;\\s*";

        ABE_ENC_PATTERN = std::regex(ABE_ENC_REGEX, std::regex::icase);
        ABE_ENC_SQL_PATTERN = std::regex(ABE_ENC_SQL_REGEX, std::regex::icase);
        ABE_DEC_PATTERN = std::regex(ABE_DEC_REGEX, std::regex::icase);
        ABE_DEC_SQL_PATTERN = std::regex(ABE_DEC_SQL_REGEX, std::regex::icase);

        mp[COM_SELECT] = std::regex(COM_SELECT_SQL_REGEX, std::regex::icase);
        mp[COM_INSERT] = std::regex(COM_INSERT_SQL_REGEX, std::regex::icase);
        mp[COM_SHOW] = std::regex(COM_SHOW_SQL_REGEX, std::regex::icase);
        mp[COM_SELECT_CURRENT_USER] = std::regex(COM_SELECT_CURRENT_USER_SQL_REGEX, std::regex::icase);
        mp[COM_GET_ABE_KEY] = std::regex(GET_ABE_KEY_REGEX, std::regex::icase);
    }
};
static RegexPatterns PATTERNS_ALL;

//一个改写点，包括abe策略（用户输入）、明文data、密文enc_data
struct enc_field{
    std::string policy; 
    std::string data;
    std::string enc_data;
};

//解密改写点
struct dec_field{
    std::string field_name;  //要解密的field_name
    int field_num;   //要解密的field位置，如select a,b,abe_dec()的abe_dec位置为2（从0开始）
};


class rewrite_plan{
public:
    /*
    * input: 用户输入的原始sql语句
    * real_sql: 重写完成后真正要执行的sql语句
    */
    rewrite_plan(std::string input) : raw_sql(input), is_enc(false), is_dec(false) {}

    bool parse_and_rewrite();

    bool need_print() const{   return (com_type == COM_SELECT || com_type == COM_SHOW);}
    bool need_enc() const {    return is_enc;   }
    bool need_dec() const {    return is_dec;   }

    void set_crypto(struct abe_crypto &c){
        crypto = &c;
    }

    void set_crypto(struct abe_crypto *c){
        crypto = c;
    }

    //需要解密的列名
    std::vector<std::string> get_field_name_list() const;

    struct abe_crypto * crypto; //abe算法

    /*
    * 查询，包括select/show，需要输出查询结果
    */
    CommandType com_type;

    //只考虑owner,encrypted_key,sig_db,sig_db_type,sig_kms,sig_kms_type
    static constexpr int TABLE_ABE_UER_KEY_FIELD_NUM = 6;
    enum abe_user_key_field {F_OWNER_NUM = 0,F_KEY_NUM = 1,F_SIG_DB_NUM = 2, F_SIG_DB_TYPE_NUM = 3,
                            F_SIG_KMS_NUM = 4, F_SIG_KMS_TYPE_NUM = 5};
    std::string raw_sql; //用户输入sql
    std::string real_sql;

private:
    bool is_enc;    //true:加密时，一般为插入 
    bool is_dec;    //true,解密一般为查询

    std::vector<struct enc_field> enc_plan;  //改写点列表

    //解密需要：
    std::vector<struct dec_field> dec_plan;


    bool insert_handler(std::string &real_sql, const std::string &raw_sql);
    bool select_handler(std::string &real_sql, const std::string &raw_sql);
    

};

}//namespace mysqlx::abe
}//namespace mysqlx
#endif