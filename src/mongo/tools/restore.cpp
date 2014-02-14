// @file restore.cpp

/**
*    Copyright (C) 2008 10gen Inc.
*    Copyright (C) 2013 Tokutek Inc.
*
*    This program is free software: you can redistribute it and/or  modify
*    it under the terms of the GNU Affero General Public License, version 3,
*    as published by the Free Software Foundation.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU Affero General Public License for more details.
*
*    You should have received a copy of the GNU Affero General Public License
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "pch.h"

#include <boost/filesystem/convenience.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/program_options.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/lexical_cast.hpp>
#include <fcntl.h>
#include <fstream>
#include <set>

#include "mongo/bson/util/bson_extract.h"
#include "mongo/client/auth_helpers.h"
#include "mongo/client/dbclientcursor.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/auth/authorization_manager_global.h"
#include "mongo/db/auth/authz_manager_external_state_d.h"
#include "mongo/db/auth/user_name.h"
#include "mongo/db/auth/role_name.h"
#include "mongo/db/json.h"
#include "mongo/db/namespace_string.h"
#include "mongo/tools/mongorestore_options.h"
#include "mongo/tools/tool.h"
#include "mongo/util/stringutils.h"
#include "mongo/db/json.h"
#include "mongo/client/dbclientcursor.h"
#include "mongo/client/remote_loader.h"

using namespace mongo;

namespace po = boost::program_options;

class Restore : public BSONTool {
public:

    bool _drop;
    bool _restoreOptions;
    bool _restoreIndexes;
    int _w;
    bool _doBulkLoad;
    string _curns;
    string _curdb;
    string _curcoll;
    set<UserName> _users; // Holds users that are already in the cluster when restoring with --drop
    set<RoleName> _roles; // Holds roles that are already in the cluster when restoring with --drop
    scoped_ptr<Matcher> _opmatcher; // For oplog replay
    scoped_ptr<OpTime> _oplogLimitTS; // for oplog replay (limit)
    int _oplogEntrySkips; // oplog entries skipped
    int _oplogEntryApplies; // oplog entries applied
    int _serverAuthzVersion; // authSchemaVersion of the cluster being restored into.
    int _dumpFileAuthzVersion; // version extracted from admin.system.version file in dump.
    bool _serverAuthzVersionDocExists; // Whether the remote cluster has an admin.system.version doc
    Restore() : BSONTool() { }

    virtual void printHelp(ostream& out) {
        printMongoRestoreHelp(&out);
    }

    void storeRemoteAuthzVersion() {
        Status status = auth::getRemoteStoredAuthorizationVersion(&conn(),
                                                                  &_serverAuthzVersion);
        uassertStatusOK(status);
        uassert(17370,
                mongoutils::str::stream() << "Restoring users and roles is only supported for "
                        "clusters with auth schema versions " <<
                        AuthorizationManager::schemaVersion24 << " or " <<
                        AuthorizationManager::schemaVersion26Final << ", found: " <<
                        _serverAuthzVersion,
                _serverAuthzVersion == AuthorizationManager::schemaVersion24 ||
                _serverAuthzVersion == AuthorizationManager::schemaVersion26Final);

        _serverAuthzVersionDocExists = !conn().findOne(
                AuthorizationManager::versionCollectionNamespace,
                AuthorizationManager::versionDocumentQuery).isEmpty();
    }

    virtual int doRun() {

        // Give restore the mongod implementation of AuthorizationManager so that it can run
        // the _mergeAuthzCollections command directly against the data files
        clearGlobalAuthorizationManager();
        setGlobalAuthorizationManager(new AuthorizationManager(
                new AuthzManagerExternalStateMongod()));

        boost::filesystem::path root = mongoRestoreGlobalParams.restoreDirectory;

        // check if we're actually talking to a machine that can write
        if (!isMaster()) {
            return -1;
        }

        if (isMongos() && _db == "" && exists(root / "config")) {
            log() << "Cannot do a full restore on a sharded system" << endl;
            return -1;
        }

        if (mongoRestoreGlobalParams.restoreUsersAndRoles) {
            storeRemoteAuthzVersion(); // populate _serverAuthzVersion

            if (_serverAuthzVersion == AuthorizationManager::schemaVersion26Final) {
                uassert(17408,
                        mongoutils::str::stream() << mongoRestoreGlobalParams.tempUsersColl <<
                                " collection already exists, but is needed to restore user data.  "
                                "Drop this collection or specify a different collection (via "
                                "--tempUsersColl) to use to temporarily hold user data during the "
                                "restore process",
                        !conn().exists(mongoRestoreGlobalParams.tempUsersColl));
                uassert(17407,
                        mongoutils::str::stream() << mongoRestoreGlobalParams.tempRolesColl <<
                                " collection already exists, but is needed to restore role data.  "
                                "Drop this collection or specify a different collection (via "
                                "--tempRolesColl) to use to temporarily hold role data during the "
                                "restore process",
                        !conn().exists(mongoRestoreGlobalParams.tempRolesColl));
            }

            if (toolGlobalParams.db.empty() && toolGlobalParams.coll.empty() &&
                    exists(root / "admin" / "system.version.bson")) {
                // Will populate _dumpFileAuthzVersion
                processFileAndMetadata(root / "admin" / "system.version.bson",
                                       "admin.system.version");
                uassert(17371,
                        mongoutils::str::stream() << "Server's authorization data schema version "
                                "does not match that of the data in the dump file.  Server's schema"
                                " version: " << _serverAuthzVersion << ", schema version in dump: "
                                << _dumpFileAuthzVersion,
                        _serverAuthzVersion == _dumpFileAuthzVersion);
            } else if (!toolGlobalParams.db.empty()) {
                // DB-specific restore
                if (exists(root / "$admin.system.users.bson")) {
                    uassert(17372,
                            mongoutils::str::stream() << "$admin.system.users.bson file found, "
                                    "which implies that the dump was taken from a system with "
                                    "schema version " << AuthorizationManager::schemaVersion26Final
                                    << " users, but server has authorization schema version "
                                    << _serverAuthzVersion,
                            _serverAuthzVersion == AuthorizationManager::schemaVersion26Final);
                    toolInfoLog() << "Restoring users for the " << toolGlobalParams.db <<
                            " database to admin.system.users" << endl;
                    processFileAndMetadata(root / "$admin.system.users.bson", "admin.system.users");
                }
                if (exists(root / "$admin.system.roles.bson")) {
                    uassert(17373,
                            mongoutils::str::stream() << "$admin.system.roles.bson file found, "
                                    "which implies that the dump was taken from a system with  "
                                    "schema version " << AuthorizationManager::schemaVersion26Final
                                    << " authorization data, but server has authorization schema "
                                    "version " << _serverAuthzVersion,
                            _serverAuthzVersion == AuthorizationManager::schemaVersion26Final);
                    toolInfoLog() << "Restoring roles for the " << toolGlobalParams.db <<
                            " database to admin.system.roles" << endl;
                    processFileAndMetadata(root / "$admin.system.roles.bson", "admin.system.roles");
                }
            }
        }
        if (hasParam( "noLoader" )) {
            _doBulkLoad = false;
        }
        if (hasParam( "keepIndexVersion" )) {
            log() << "warning: --keepIndexVersion is deprecated in TokuMX" << endl;
        }
        if (hasParam( "oplogReplay" )) {
            log() << "warning: --oplogReplay is deprecated in TokuMX" << endl;
        }
        if (hasParam( "oplogLimit" )) {
            log() << "warning: --oplogLimit is deprecated in TokuMX" << endl;
        }

        /* If _db is not "" then the user specified a db name to restore as.
         *
         * In that case we better be given either a root directory that
         * contains only .bson files or a single .bson file  (a db).
         *
         * In the case where a collection name is specified we better be
         * given either a root directory that contains only a single
         * .bson file, or a single .bson file itself (a collection).
         */
        drillDown(root, _db != "", _coll != "", true);
        string err = conn().getLastError(_db == "" ? "admin" : _db);
        if (!err.empty()) {
            error() << err;
        }

        return EXIT_CLEAN;
    }

    void drillDown( boost::filesystem::path root, bool use_db, bool use_coll, bool top_level=false ) {
        LOG(2) << "drillDown: " << root.string() << endl;

        // skip hidden files and directories
        if (root.leaf().string()[0] == '.' && root.leaf().string() != ".")
            return;

        if ( is_directory( root ) ) {
            boost::filesystem::directory_iterator end;
            boost::filesystem::directory_iterator i(root);
            while ( i != end ) {
                boost::filesystem::path p = *i;
                i++;

                if (use_db) {
                    if (boost::filesystem::is_directory(p)) {
                        error() << "ERROR: root directory must be a dump of a single database" << endl;
                        error() << "       when specifying a db name with --db" << endl;
                        printHelp(cout);
                        return;
                    }
                }

                if (use_coll) {
                    if (boost::filesystem::is_directory(p) || i != end) {
                        error() << "ERROR: root directory must be a dump of a single collection" << endl;
                        error() << "       when specifying a collection name with --collection" << endl;
                        printHelp(cout);
                        return;
                    }
                }

                // don't insert oplog
                if (top_level && !use_db && p.leaf() == "oplog.bson")
                    continue;

                // Only restore indexes from a corresponding .metadata.json file.
                if ( p.leaf() != "system.indexes.bson" ) {
                    drillDown(p, use_db, use_coll);
                }
            }

            return;
        }

        if ( endsWith( root.string().c_str() , ".metadata.json" ) ) {
            // Metadata files are handled when the corresponding .bson file is handled
            return;
        }

        if ( ! ( endsWith( root.string().c_str() , ".bson" ) ||
                 endsWith( root.string().c_str() , ".bin" ) ) ) {
            error() << "don't know what to do with file [" << root.string() << "]" << endl;
            return;
        }

        log() << root.string() << endl;

        if ( root.leaf() == "system.profile.bson" ) {
            log() << "\t skipping" << endl;
            return;
        }

        string ns;
        if (use_db) {
            ns += _db;
        }
        else {
            ns = root.parent_path().filename().string();
            if (ns.empty())
                ns = "test";
        }

        verify( ns.size() );

        string oldCollName = root.leaf().string(); // Name of the collection that was dumped from
        oldCollName = oldCollName.substr( 0 , oldCollName.find_last_of( "." ) );
        if (use_coll) {
            ns += "." + _coll;
        }
        else {
            ns += "." + oldCollName;
        }

        log() << "\tgoing into namespace [" << ns << "]" << endl;

        if ( root.leaf() == "system.profile.bson" ) {
            toolInfoLog() << "\t skipping system.profile.bson" << std::endl;
            return;
        }

        processFileAndMetadata(root, ns);
    }

    /**
     * 1) Drop collection if --drop was specified.  For system.users or system.roles collections,
     * however, you don't want to remove all the users/roles up front as some of them may be needed
     * by the restore.  Instead, keep a set of all the users/roles originally in the server, then
     * after restoring the users/roles from the dump, remove any users roles that were present in
     * the system originally but aren't in the dump.
     *
     * 2) Parse metadata file (if present) and if the collection doesn't exist (or was just dropped
     * b/c we're using --drop), create the collection with the options from the metadata file
     *
     * 3) Restore the data from the dump file for this collection
     *
     * 4) If the user asked to drop this collection, then at this point the _users and _roles sets
     * will contain users and roles that were in the collection but not in the dump we are
     * restoring. Iterate these sets and delete any users and roles that are there.
     *
     * 5) Restore indexes based on index definitions from the metadata file.
     */
    void processFileAndMetadata(const boost::filesystem::path& root, const std::string& ns) {

        _curns = ns;
        _curdb = nsToDatabase(_curns);
        _curcoll = nsToCollectionSubstring(_curns).toString();

        toolInfoLog() << "\tgoing into namespace [" << _curns << "]" << std::endl;

        // 1) Drop collection if needed.  Save user and role data if this is a system.users or
        // system.roles collection
        if (mongoRestoreGlobalParams.drop) {
            if (_curcoll == "system.users") {
                if (_serverAuthzVersion == AuthorizationManager::schemaVersion24 ||
                            _curdb != "admin") {
                    // Restoring 2.4-style user docs so can't use the _mergeAuthzCollections command
                    // Create map of the users currently in the DB so the ones that don't show up in
                    // the dump file can be removed later.
                    BSONObj fields = BSON("user" << 1 << "userSource" << 1);
                    scoped_ptr<DBClientCursor> cursor(conn().query(_curns, Query(), 0, 0, &fields));
                    while (cursor->more()) {
                        BSONObj user = cursor->next();
                        string userDB;
                        uassertStatusOK(bsonExtractStringFieldWithDefault(user,
                                                                          "userSource",
                                                                          _curdb,
                                                                          &userDB));
                        _users.insert(UserName(user["user"].String(), userDB));
                    }
                }
            }
            else if (!startsWith(_curcoll, "system.")) { // Can't drop system collections
                toolInfoLog() << "\t dropping" << std::endl;
                conn().dropCollection( ns );
            }
        } else {
            // If drop is not used, warn if the collection exists.
            scoped_ptr<DBClientCursor> cursor(conn().query(_curdb + ".system.namespaces",
                                                           Query(BSON("name" << ns))));
            if (cursor->more()) {
                // collection already exists show warning
                toolError() << "Restoring to " << ns << " without dropping. Restored data "
                        << "will be inserted without raising errors; check your server log"
                        << std::endl;
            }
        }

        BSONObj metadataObject;
        if (_restoreOptions || _restoreIndexes) {
            boost::filesystem::path metadataFile = (root.branch_path() / (oldCollName + ".metadata.json"));
            if (!boost::filesystem::exists(metadataFile.string())) {
                // This is fine because dumps from before 2.1 won't have a metadata file, just print a warning.
                // System collections shouldn't have metadata so don't warn if that file is missing.
                if (!startsWith(metadataFile.leaf().string(), "system.")) {
                    log() << metadataFile.string() << " not found. Skipping." << endl;
                }
            } else {
                metadataObject = parseMetadataFile(metadataFile.string());
            }
        }

        _curns = ns.c_str();
        NamespaceString nss(_curns);
        _curdb = nss.db;
        _curcoll = nss.coll;

        // 3) Actually restore the BSONObjs inside the dump file
        processFile( root );

        // 4) If running with --drop, remove any users/roles that were in the system at the
        // beginning of the restore but weren't found in the dump file
        if (_curcoll == "system.users") {
            if ((_serverAuthzVersion == AuthorizationManager::schemaVersion24 ||
                    _curdb != "admin")) {
                // Restoring 2.4 style user docs so don't use the _mergeAuthzCollections command
                if (mongoRestoreGlobalParams.drop) {
                    // Delete any users that used to exist but weren't in the dump file
                    for (set<UserName>::iterator it = _users.begin(); it != _users.end(); ++it) {
                        const UserName& name = *it;
                        BSONObjBuilder queryBuilder;
                        queryBuilder << "user" << name.getUser();
                        if (name.getDB() == _curdb) {
                            // userSource field won't be present for v1 users docs in the same db as
                            // the user is defined on.
                            queryBuilder << "userSource" << BSONNULL;
                        } else {
                            queryBuilder << "userSource" << name.getDB();
                        }
                        conn().remove(_curns, Query(queryBuilder.done()));
                    }
                    _users.clear();
                }
            } else {
                // Use _mergeAuthzCollections command to move into admin.system.users the user
                // docs that were restored into the temp user collection
                BSONObj res;
                conn().runCommand("admin",
                                  BSON("_mergeAuthzCollections" << 1 <<
                                       "tempUsersCollection" <<
                                               mongoRestoreGlobalParams.tempUsersColl <<
                                       "drop" << mongoRestoreGlobalParams.drop <<
                                       "writeConcern" << BSON("w" << mongoRestoreGlobalParams.w)),
                                  res);
                uassert(17412,
                        mongoutils::str::stream() << "Cannot restore users because the "
                                "_mergeAuthzCollections command failed: " << res.toString(),
                        res["ok"].trueValue());

                conn().dropCollection(mongoRestoreGlobalParams.tempUsersColl);
            }
        }
        if (_curns == "admin.system.roles") {
            // Use _mergeAuthzCollections command to move into admin.system.roles the role
            // docs that were restored into the temp roles collection
            BSONObj res;
            conn().runCommand("admin",
                              BSON("_mergeAuthzCollections" << 1 <<
                                   "tempRolesCollection" <<
                                           mongoRestoreGlobalParams.tempRolesColl <<
                                   "drop" << mongoRestoreGlobalParams.drop <<
                                   "writeConcern" << BSON("w" << mongoRestoreGlobalParams.w)),
                              res);
            uassert(17413,
                    mongoutils::str::stream() << "Cannot restore roles because the "
                            "_mergeAuthzCollections command failed: " << res.toString(),
                    res["ok"].trueValue());

            conn().dropCollection(mongoRestoreGlobalParams.tempRolesColl);
        }

        if (_drop && root.leaf() == "system.users.bson") {
            // Delete any users that used to exist but weren't in the dump file
            for (set<string>::iterator it = _users.begin(); it != _users.end(); ++it) {
                BSONObj userMatch = BSON("user" << *it);
                conn().remove(ns, Query(userMatch));
            }
            _users.clear();
        }
    }

    virtual void gotObject( const BSONObj& obj ) {
        StringData collstr = nsToCollectionSubstring(_curns);
        massert( 16910, "Shouldn't be inserting into system.indexes directly",
                        collstr != "system.indexes" );
        if (_drop && collstr == "system.users" && _users.count(obj["user"].String())) {
            // Since system collections can't be dropped, we have to manually
            // replace the contents of the system.users collection
            BSONObj userMatch = BSON("user" << obj["user"].String());
            conn().update(_curns, Query(userMatch), obj);
            _users.erase(obj["user"].String());
        } else {
            conn().insert( _curns , obj );

            // wait for insert to propagate to "w" nodes (doesn't warn if w used without replset)
            if ( _w > 0 ) {
                string err = conn().getLastError(_curdb, false, false, _w);
                if (!err.empty()) {
                    error() << err << endl;
                }
            }
        }
    }

        if (nsToCollectionSubstring(_curns) == "system.indexes") {
            createIndex(obj, true);
        }
        else if (_curns == "admin.system.roles") {
            // To prevent modifying roles when other role modifications may be going on, restore
            // the roles to a temporary collection and merge them into admin.system.roles later
            // using the _mergeAuthzCollections command.
            conn().insert(mongoRestoreGlobalParams.tempRolesColl, obj);
        }
        else if (_curcoll == "system.users") {
            if (obj.hasField("credentials")) {
                if (_serverAuthzVersion == AuthorizationManager::schemaVersion24) {
                    // v3 user, v1 system
                    uasserted(17407,
                              mongoutils::str::stream()
                                      << "Server has authorization schema version "
                                      << AuthorizationManager::schemaVersion24
                                      << ", but found a schema version "
                                      << AuthorizationManager::schemaVersion26Final << " user: "
                                      << obj.toString());
                } else {
                    // v3 user, v3 system
                    uassert(17414,
                            mongoutils::str::stream() << "Found a schema version " <<
                                    AuthorizationManager::schemaVersion26Final <<
                                    " user when restoring to a non-admin db system.users "
                                    "collection: " << obj.toString(),
                            _curdb == "admin");
                    // To prevent modifying users when other user modifications may be going on,
                    // restore the users to a temporary collection and merge them into
                    // admin.system.users later using the _mergeAuthzCollections command.
                    conn().insert(mongoRestoreGlobalParams.tempUsersColl, obj);
                }
            } else {
                if (_serverAuthzVersion == AuthorizationManager::schemaVersion26Final &&
                        !_serverAuthzVersionDocExists) {
                    // This is a clean 2.6 system without any users, so it is okay to restore
                    // 2.4-schema users into it.  This will make the system a 2.4 schema version
                    // system.
                    _serverAuthzVersion = AuthorizationManager::schemaVersion24;
                }

                if (_serverAuthzVersion == AuthorizationManager::schemaVersion24 ||
                        _curdb != "admin") { // Restoring 2.4 schema users to non-admin dbs is OK)
                    // v1 user, v1 system
                    string userDB;
                    uassertStatusOK(bsonExtractStringFieldWithDefault(obj,
                                                                      "userSource",
                                                                      _curdb,
                                                                      &userDB));

                    if (mongoRestoreGlobalParams.drop && _users.count(UserName(obj["user"].String(),
                                                                               userDB))) {
                        // Since system collections can't be dropped, we have to manually
                        // replace the contents of the system.users collection
                        BSONObj userMatch = BSON("user" << obj["user"].String() <<
                                                 "userSource" << userDB);
                        conn().update(_curns, Query(userMatch), obj);
                        _users.erase(UserName(obj["user"].String(), userDB));
                    } else {
                        conn().insert(_curns, obj);
                    }
                } else {
                    // v1 user, v3 system
                    // TODO(spencer): SERVER-12491 Rather than failing here, we should convert the
                    // v1 user to an equivalent v3 schema user
                    uasserted(17408,
                              mongoutils::str::stream()
                                      << "Server has authorization schema version "
                                      << AuthorizationManager::schemaVersion26Final
                                      << ", but found a schema version "
                                      << AuthorizationManager::schemaVersion24 << " user: "
                                      << obj.toString());
                }
            }
            newOptsBuilder.append(opt);
        }
        if (!compressionSpecified && !_defaultCompression.empty()) {
            newOptsBuilder.append("compression", _defaultCompression);
        }
        if (!pageSizeSpecified && ((int) _defaultPageSize) != 0) {
            newOptsBuilder.append("pageSize", (int) _defaultPageSize);
        }
        if (!readPageSizeSpecified && ((int) _defaultReadPageSize) != 0) {
            newOptsBuilder.append("readPageSize", (int) _defaultReadPageSize);
        }
        return newOptsBuilder.obj();
    }

    BSONObj parseMetadataFile(string filePath) {
        long long fileSize = boost::filesystem::file_size(filePath);
        ifstream file(filePath.c_str(), ios_base::in);

        scoped_ptr<char> buf(new char[fileSize]);
        file.read(buf.get(), fileSize);
        int objSize;
        BSONObj obj;
        obj = fromjson (buf.get(), &objSize);
        return obj;
    }

    // Compares 2 BSONObj representing collection options. Returns true if the objects
    // represent different options. Ignores the "create" field.
    bool optionsSame(BSONObj obj1, BSONObj obj2) {
        int nfields = 0;
        BSONObjIterator i(obj1);
        while ( i.more() ) {
            BSONElement e = i.next();
            if (!obj2.hasField(e.fieldName())) {
                if (strcmp(e.fieldName(), "create") == 0) {
                    continue;
                } else {
                    return false;
                }
            }
            nfields++;
            if (e != obj2[e.fieldName()]) {
                return false;
            }
        }
        return nfields == obj2.nFields();
    }

    void createCollectionWithOptions(BSONObj obj) {
        BSONObjIterator i(obj);

        // Rebuild obj as a command object for the "create" command.
        // - {create: <name>} comes first, where <name> is the new name for the collection
        // - elements with type Undefined get skipped over
        BSONObjBuilder bo;
        bo.append("create", _curcoll);
        while (i.more()) {
            BSONElement e = i.next();

            if (strcmp(e.fieldName(), "create") == 0) {
                continue;
            }

            if (e.type() == Undefined) {
                log() << _curns << ": skipping undefined field: " << e.fieldName() << endl;
                continue;
            }

            bo.append(e);
        }
        obj = bo.obj();

        BSONObj fields = BSON("options" << 1);
        scoped_ptr<DBClientCursor> cursor(conn().query(_curdb + ".system.namespaces", Query(BSON("name" << _curns)), 0, 0, &fields));

        bool createColl = true;
        if (cursor->more()) {
            createColl = false;
            BSONObj nsObj = cursor->next();
            if (!nsObj.hasField("options") || !optionsSame(obj, nsObj["options"].Obj())) {
                    log() << "WARNING: collection " << _curns << " exists with different options than are in the metadata.json file and not using --drop. Options in the metadata file will be ignored." << endl;
            }
        }

        if (!createColl) {
            return;
        }

        BSONObj info;
        if (!conn().runCommand(_curdb, obj, info)) {
            uasserted(15936, "Creating collection " + _curns + " failed. Errmsg: " + info["errmsg"].String());
        } else {
            log() << "\tCreated collection " << _curns << " with options: " << obj.jsonString() << endl;
        }
    }

    BSONObj renameIndexNs(const BSONObj &orig) {
        BSONObjBuilder bo;
        BSONObjIterator i(orig);
        while ( i.more() ) {
            BSONElement e = i.next();
            if (strcmp(e.fieldName(), "ns") == 0) {
                string s = _curdb + "." + _curcoll;
                bo.append("ns", s);
            }
            else if (strcmp(e.fieldName(), "v") != 0) { // Remove index version number
                bo.append(e);
            }
        }
        return bo.obj();
    }

    /* We must handle if the dbname or collection name is different at restore time than what was dumped.
     */
    void createIndex(BSONObj indexObj) {
        LOG(0) << "\tCreating index: " << indexObj << endl;
        conn().insert( _curdb + ".system.indexes" ,  indexObj );

        // We're stricter about errors for indexes than for regular data
        BSONObj err = conn().getLastErrorDetailed(_curdb, false, false, _w);

        if (err.hasField("err") && !err["err"].isNull()) {
            if (err["err"].str() == "norepl" && _w > 1) {
                error() << "Cannot specify write concern for non-replicas" << endl;
            }
            else {
                string errCode;

                if (err.hasField("code")) {
                    errCode = str::stream() << err["code"].numberInt();
                }

                error() << "Error creating index " << indexObj["ns"].String() << ": "
                        << errCode << " " << err["err"] << endl;
            }

            ::abort();
        }

        massert(16441, str::stream() << "Error calling getLastError: " << err["errmsg"],
                err["ok"].trueValue());
    }
};

int main( int argc , char ** argv, char ** envp ) {
    mongo::runGlobalInitializersOrDie(argc, argv, envp);
    Restore restore;
    return restore.main( argc , argv );
}
