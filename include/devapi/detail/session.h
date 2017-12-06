/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * The MySQL Connector/C++ is licensed under the terms of the GPLv2
 * <http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>, like most
 * MySQL Connectors. There are special exceptions to the terms and
 * conditions of the GPLv2 as it is applied to this software, see the
 * FLOSS License Exception
 * <http://www.mysql.com/about/legal/licensing/foss-exception.html>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef MYSQLX_DETAIL_SESSION_H
#define MYSQLX_DETAIL_SESSION_H

#include "../common.h"


namespace mysqlx {

class Session;
class Schema;
class Table;
class Collection;

namespace common {
  class Session_impl;
}

namespace internal {

class Schema_detail;
using Session_impl = common::Session_impl;
using Shared_session_impl = std::shared_ptr<common::Session_impl>;

/*
  Base class for database objects. Can't be used alone.
*/

class PUBLIC_API Db_obj_base
{
protected:

  DLL_WARNINGS_PUSH
  Shared_session_impl m_sess;
  string m_name;
  DLL_WARNINGS_POP

  Db_obj_base(const Shared_session_impl& sess, const string& name)
    : m_sess(sess), m_name(name)
  {}
};


class PUBLIC_API Collection_detail
  : public Db_obj_base
{
protected:

  Collection_detail(const Shared_session_impl &sess, const string &name)
    : Db_obj_base(sess, name)
  {}

  virtual Schema_detail& get_schema() = 0;

  Result add_or_replace_one(const string &id, Value&&, bool);
};


// ---------------------------------------------------------------------------

/*
  Base class for classes to be used by common::List_source<> which get item
  from query results.

  It assumes that the first column in the results contains string
  data. An instance of this class iterates over the string data in the
  result until all rows are consumed.

  Derived class must send the query to the server and set m_res member to point
  at the result of this query.
*/

struct PUBLIC_API Query_src
{
  using Value = string;
  using Res_impl = common::Result_impl<string>;

  DLL_WARNINGS_PUSH
  std::unique_ptr<Res_impl> m_res;
  DLL_WARNINGS_POP

  const common::Row_data *m_row = nullptr;

public:

  virtual void  iterator_start()
  {
    assert(m_res);
  }

  bool   iterator_next();
  string iterator_get();
};


// ---------------------------------------------------------------------------


class PUBLIC_API Schema_detail
  : public Db_obj_base
{
protected:

  enum Obj_type { COLLECTION, TABLE };

  /*
    Sources for lists of schema objects and their names.

    When constructing a source, a SQL style patter on object names is
    given as ctor parameter -- only object matching the pattern are listed.
    Name_src accepts a parameter which tells whether names of tables or
    collections should be listed.
  */

  struct PUBLIC_API Name_src
    : public Query_src
  {
    const Schema &m_schema;
    Name_src(const Schema&, Obj_type, const string &pattern);
  };

  struct PUBLIC_API Collection_src
    : Name_src
  {
    using Value = Collection;

    Collection_src(const Schema &sch, const string &pattern)
      : Name_src(sch, COLLECTION, pattern)
    {}

    using Name_src::iterator_start;
    using Name_src::iterator_next;
    Collection iterator_get();
  };

  struct PUBLIC_API Table_src
    : Name_src
  {
    using Value = Table;

    Table_src(const Schema &sch, const string &pattern)
      : Name_src(sch, TABLE, pattern)
    {}

    using Name_src::iterator_start;
    using Name_src::iterator_next;
    Table iterator_get();
  };

  Schema_detail(const Shared_session_impl &sess, const string &name)
    : Db_obj_base(sess, name)
  {}

public:

  using CollectionList = List_initializer<List_source<Collection_src>>;
  using TableList      = List_initializer<List_source<Table_src>>;
  using StringList     = List_initializer<List_source<Name_src>>;

  void  create_collection(const string &name, bool reuse);
  void  drop_collection(const string &name);

  friend Collection_detail;

  struct Access;
  friend Access;
};


/*
  Class representing an SQL statement that can be executed on the server.
*/

struct SQL_statement;

using SQL_statement_cmd = Executable<SqlResult, SQL_statement>;

struct SQL_statement
  : public Bind_placeholders< SQL_statement_cmd >
{
  SQL_statement(Session *sess, const string &query)
  {
    assert(sess);
    try {
      reset(internal::Crud_factory::mk_sql(*sess, query));
    }
    CATCH_AND_WRAP
  }

  SQL_statement(SQL_statement_cmd &other)
  {
    SQL_statement_cmd::operator=(other);
  }

  SQL_statement(SQL_statement_cmd &&other)
  {
    SQL_statement_cmd::operator=(std::move(other));
  }
};


struct PUBLIC_API Session_detail
{
  // Disable copy semantics for session class.

  Session_detail(const Session_detail&) = delete;
  Session_detail& operator=(const Session_detail&) = delete;

  /*
    Sources for lists of schemata and schema names. Only schemata matching
    the given SQL-style pattern are listed.
  */

  struct PUBLIC_API Name_src
    : public Query_src
  {
    const Session &m_sess;
    Name_src(const Session&, const string &pattern);
  };

  struct PUBLIC_API Schema_src
    : Name_src
  {
    using Value = Schema;

    Schema_src(Session &sess, const string &pattern)
      : Name_src(sess, pattern)
    {}

    Schema_src(Session &sess)
      : Schema_src(sess, L"%")
    {}

    using Name_src::iterator_start;
    using Name_src::iterator_next;
    Schema iterator_get();
  };

public:

  using SchemaList = List_initializer<List_source<Schema_src>>;

protected:

  struct INTERNAL Impl;

  /*
    Note: Session implementation is shared with result objects because it
    must exists as long as result implementation exists. This means that
    even when session object is deleted, its implementation can still hang
    around.
  */

  DLL_WARNINGS_PUSH
  Shared_session_impl  m_impl = NULL;
  Session_detail *m_parent_session = NULL;
  std::set<Session_detail*>  m_child_sessions;
  DLL_WARNINGS_POP

  Session_detail(common::Settings_impl&);

  virtual ~Session_detail()
  {
    try {
      if (m_impl)
        close();
    }
    catch (...) {}
  }

  void create_schema(const string &name, bool reuse);
  void drop_schema(const string &name);
  const std::wstring& get_default_schema_name();

  void start_transaction();
  void commit();
  void rollback();


  common::Session_impl& get_impl()
  {
    if (!m_impl)
      THROW("Invalid session");
    return *m_impl;
  }

  INTERNAL cdk::Session& get_cdk_session();

  void close();

  /*
    TODO: Do we still need these?
  */

  void add_child(Session_detail *child)
  {
    assert(child);
    child->m_parent_session = this;
    m_child_sessions.insert(child);
  }

  void remove_child(Session_detail *child)
  {
    m_child_sessions.erase(child);
  }

  /*
    This notification is sent from parent session when it is closed.
  */
  void parent_close_notify()
  {
    if (m_parent_session)
      m_impl = NULL;
  }

  /*
    Do necessary cleanups before sending new command to the server.
  */
  void prepare_for_cmd();

public:

  /// @cond IGNORED
  friend Result_detail::Impl;
  friend internal::Crud_factory;
  /// @endcond
};

}  // internal namespace
}  // mysqlx namespace

#endif
