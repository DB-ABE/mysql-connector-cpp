#include "mysqlx/abe/rewrite.h"
#include <regex>
#include <iostream>
#include <string>
#include <algorithm>
using std::string;


/*因sql-parser库对mysql语句支持很不友好，且当前并未找到实用的sql解析库
*（最好是能解析mysql语句，然后可以反序列化，即解析后修改相关项，恢复成sql语句）
* 暂使用正则表达式实现abe_enc/abe_dec的匹配和重写
* 文本内容理论要求：不能为空
*　policy理论要求：\w(字母，数字，下划线)，| 属性分隔符，空白字符如空格等，等号，小数点，百分号
* 加密函数格式：abe_enc(<data>,<policy>)
* 解密函数格式：abe_dec(<field name>)
*/

CommandType simple_parse(const string sql){
    std::smatch result;
    for(auto it: PATTERNS_ALL.mp){
        if(std::regex_match(sql, result, it.second)){
            return it.first;
        }
    }
    return COM_OTHER;
}


bool rewrite_plan::insert_handler(string &real_sql, const string &raw_sql){
    std::regex pattern = PATTERNS_ALL.ABE_ENC_SQL_PATTERN;
    std::regex pattern_enc = PATTERNS_ALL.ABE_ENC_PATTERN;
    string new_sql = raw_sql;
    std::smatch result;
    while (std::regex_match(new_sql, result, pattern, std::regex_constants::format_first_only)){
        is_enc = true;//需要加密
        //abe_enc只有两个参数，data和policy
        struct enc_field temp;
        temp.data = result[1];
        temp.policy = result[2];

        string cipher;
        crypto->encrypt(temp.data, temp.policy, cipher);
        
        temp.enc_data = "'" + cipher + "'";
        
        new_sql = std::regex_replace(new_sql, pattern_enc, temp.enc_data, std::regex_constants::format_first_only);
        enc_plan.push_back(temp);
        // std::cout << "new_sql: " << new_sql << std::endl;
    }

    real_sql = new_sql;
    return true;
}

bool rewrite_plan::select_handler(string &real_sql, const string &raw_sql){
    std::regex pattern = PATTERNS_ALL.ABE_DEC_SQL_PATTERN;
    std::regex pattern_dec = PATTERNS_ALL.ABE_DEC_PATTERN;
    std::smatch result;
    string new_sql = raw_sql;
    while (std::regex_match(new_sql, result, pattern, std::regex_constants::format_first_only)){
        is_dec = true;//需要解密

        //abe_dec只有一个参数，field_name
        struct dec_field temp;
        temp.field_name = result[1];
        new_sql = std::regex_replace(new_sql, pattern_dec, temp.field_name, std::regex_constants::format_first_only);
        dec_plan.push_back(temp);
        // std::cout << "new_sql: " << new_sql << std::endl;
    }
    real_sql = new_sql;
    return true;
}

bool rewrite_plan::parse_and_rewrite(){
    
    std::string sql = raw_sql;
    //只有show/select命令需要打印查询结果，其他的不需要
    com_type = simple_parse(sql);
    
    switch (com_type)
    {
        case COM_SELECT:{
            // std::cout << "select statement" << std::endl;
            
            select_handler(real_sql, raw_sql);
            // std::cout << "after replace: " << real_sql << std::endl;
            break;
        }
        case COM_INSERT:{
            // std::cout << "insert statement" << std::endl;
            insert_handler(real_sql, raw_sql);
            // std::cout << "after replace: " << real_sql << std::endl;
            break;
        }
        case COM_GET_ABE_KEY:{
            real_sql = "select owner,encrypted_key,sig_db,sig_db_type,sig_kms,sig_kms_type from mysql.abe_user_key";
            real_sql += " where owner = '" + crypto->user.user_id + "';";
            break;
        }
        case COM_SHOW:
        case COM_SELECT_CURRENT_USER:
        case COM_OTHER:{
            real_sql = sql;
            break;
        }
        default:
            break;
    }
    return true;
}

std::vector<string> rewrite_plan::field_name_list() const {
    std::vector<string> list;
    for(auto item : dec_plan){
        list.push_back(item.field_name);
    }
    return list;
}