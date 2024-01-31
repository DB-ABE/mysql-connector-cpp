# MySQL Connector/C++

## ABE支持

### 使用

要使用ABE功能，需引用abe_extern.h头文件。

开放接口和使用方法可参考如下示例：

```cpp
#include <iostream>
#include <vector>
#include<mysqlx/xdevapi.h>
#include<mysqlx/xapi.h>
#include<mysqlx/abe_extern.h>
using namespace mysqlx;
using std::cout;
using std::endl;
using std::vector;

//数据库连接
Session get_connect(){
    //注意 mysqlcppconn8 默认使用的端口：33060，若连接3306端口会提示错误
    //使用用户名：testabe
    //用户 root 的密码是：123456
    //主机：172.17.0.9
    //端口：33060
    //数据库：company
    cout << "start connecting...\n";

    SessionSettings option("172.17.0.9", 33060, "testabe", "123456");
    Session sess(option); 
    
    cout <<"Done!" <<endl;
    cout <<"Session accepted, creating collection..." <<endl;

    sess.sql("use company").execute();  //使用数据库 webserver
    return sess;
}

//正常用法
void normal_example(Session &sess){
    cout << "normal query begin:" << endl;
    RowResult rs = sess.sql("select * from note").execute();
    for (auto it = rs.begin();it != rs.end();++it){
        cout << (*it).get(0).get<int>() <<" ";
        cout << (*it).get(1).get<string>(); //这个string是mysqlx的string，继承自std::u16string
        cout << endl;
    }
    cout << "normal query end." << endl;
}
void abe_example1(Session &sess) {
    /*
    *   1. 初始化abe环境
    *       - 利用abe_parameters设置abe所需的参数
    *       - 传入Session，创建abe_env对象
    *       - 传入abe_parameters参数，初始化abe_env对象。 这一过程
    *         将会导入abe模块所需的abe密钥、RSA密钥（db/kms公钥，用户私钥）
    *         等信息。之后，将会执行预查询，包括获取用户名称、属性列表，如果
    *         之前没有导入abe用户密钥，还会通过预查询获取用户密钥，该密钥将
    *         经过验签、解密后存储到指定位置
    *       
    */
    abe_parameters params;
    params.abe_key_path = "/root/connector_demo/data/abe/abe_key";
    params.abe_pp_path = "/root/connector_demo/data/abe/abe_pp";
    params.db_cert_path = "/root/connector_demo/data/certs/dbcert.pem";
    params.kms_cert_path = "/root/connector_demo/data/certs/kmscert.pem";
    params.rsa_sk_path = "/root/connector_demo/data/prikey/testabe@%.pem";

    abe_env env(sess);
    env.init(params);

    cout << "abe query begin:" << endl;
    /*
    *   2. 执行abe查询，
    *       - 查询执行的格式为：env.sql("sql query statement").execute();
    *         其中env.sql函数将会返回一个abe_query类型的对象，该对象存储了sql语句
    *         改写相关信息，改写和执行发生在abe_query类的execute方法。
    *       - 加密sql示例：
    *           insert into share2 values (2, abe_enc("hello,hello","attr1 and attr2"));
    *         其中，abe_enc为加密“函数”，第一个参数为原始明文，第二个参数为用户设置的abe访问策略
    *       - 解密sql示例：
    *           select id,title,abe_dec(data) from share;、
    *         其中abe_dec为解密“函数”，参数为要解密的列名
    *       - 恢复明文
    *           查询得到的为密文，使用recover方法恢复明文，需要注意所有abe相关实现都是基于std::string
    *           所以在获取密文时需要使用get<std::string>()
    */
    abe_query query = env.sql("select id,title,abe_dec(data) from share;");
    RowResult rs2 = query.execute();
    // cout << "real_sql = " << query.real_sql << endl;
    for (auto it = rs2.begin();it != rs2.end();++it){
        cout << (*it).get(0).get<int>() << "\t";
        cout << (*it).get(1).get<mysqlx::abi2::r0::string>() << "\t";
        auto ustr = (*it).get(2).get<std::string>();
        try{
            cout << env.recover(ustr);
        }catch(const Error &e){
            cout << "can't decrypt";
        }
        cout << endl;
    }
    cout << "abe query end." << endl;
 
}
int main()
{
    try{
        Session sess = get_connect();
        normal_example(sess);
        abe_example1(sess);
    
    } catch (const Error& e) {
        cout << e.what() <<endl;
    }
    return 0;
}
```

### 编译

本部分基于8.0.27分支开发，编译安装方式和8.0.27一致。

ABE相关头文件位于include/mysqlx目录下，相关cpp文件位于devapi目录下。

暂时使用的ABE加密库为openabe，需在文件devapi/abe/CMakeLists.txt中指定openabe等依赖的搜索路径。


## Documentation

* [MySQL](http://www.mysql.com/)
* [Connector/C++ API Reference](https://dev.mysql.com/doc/dev/connector-cpp/8.0/)

## Questions/Bug Reports

* [Discussion Forum](https://forums.mysql.com/list.php?167)
* [Slack](https://mysqlcommunity.slack.com)
* [Bugs](https://bugs.mysql.com)

