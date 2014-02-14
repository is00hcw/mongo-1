/*
*    Copyright (C) 2012 10gen Inc.
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

#pragma once

#include <string>

#include "mongo/base/disallow_copying.h"
#include "mongo/base/status.h"
#include "mongo/db/auth/user_name.h"
#include "mongo/db/jsobj.h"

namespace mongo {

    /**
     * Public interface for a class that encapsulates all the information related to system
     * state not stored in AuthorizationManager.  This is primarily to make AuthorizationManager
     * easier to test as well as to allow different implementations for mongos and mongod.
     */
    class AuthzManagerExternalState {
        MONGO_DISALLOW_COPYING(AuthzManagerExternalState);

    public:

        virtual ~AuthzManagerExternalState();

        /**
         * Initializes the external state object.  Must be called after construction and before
         * calling other methods.  Object may not be used after this method returns something other
         * than Status::OK().
         */
        virtual Status initialize() = 0;

        /**
         * Retrieves the schema version of the persistent data describing users and roles.
         * Will leave *outVersion unmodified on non-OK status return values.
         */
        virtual Status getStoredAuthorizationVersion(int* outVersion) = 0;

        /**
         * Writes into "result" a document describing the named user and returns Status::OK().  The
         * description includes the user credentials, if present, the user's role membership and
         * delegation information, a full list of the user's privileges, and a full list of the
         * user's roles, including those roles held implicitly through other roles (indirect roles).
         * In the event that some of this information is inconsistent, the document will contain a
         * "warnings" array, with string messages describing inconsistencies.
         *
         * If the user does not exist, returns ErrorCodes::UserNotFound.
         */
        virtual Status getUserDescription(const UserName& userName, BSONObj* result) = 0;

        /**
         * Writes into "result" a document describing the named role and returns Status::OK().  The
         * description includes the roles in which the named role has membership and a full list of
         * the roles of which the named role is a member, including those roles memberships held
         * implicitly through other roles (indirect roles). If "showPrivileges" is true, then the
         * description documents will also include a full list of the role's privileges.
         * In the event that some of this information is inconsistent, the document will contain a
         * "warnings" array, with string messages describing inconsistencies.
         *
         * If the role does not exist, returns ErrorCodes::RoleNotFound.
         */
        virtual Status getRoleDescription(const RoleName& roleName,
                                          bool showPrivileges,
                                          BSONObj* result) = 0;

        /**
         * Writes into "result" documents describing the roles that are defined on the given
         * database. Each role description document includes the other roles in which the role has
         * membership and a full list of the roles of which the named role is a member,
         * including those roles memberships held implicitly through other roles (indirect roles).
         * If showPrivileges is true, then the description documents will also include a full list
         * of the role's privileges.  If showBuiltinRoles is true, then the result array will
         * contain description documents for all the builtin roles for the given database, if it
         * is false the result will just include user defined roles.
         * In the event that some of the information in a given role description is inconsistent,
         * the document will contain a "warnings" array, with string messages describing
         * inconsistencies.
         */
        virtual Status getRoleDescriptionsForDB(const std::string dbname,
                                                bool showPrivileges,
                                                bool showBuiltinRoles,
                                                vector<BSONObj>* result) = 0;

        /**
         * Gets the privilege document for "userName" stored in the system.users collection of
         * database "dbname".  Useful only for schemaVersion24 user documents.  For newer schema
         * versions, use getUserDescription().
         *
         * On success, returns Status::OK() and stores a shared-ownership copy of the document into
         * "result".
         */
        Status getPrivilegeDocumentV1(
                const StringData& dbname, const UserName& userName, BSONObj* result);

        /**
         * Returns true if there exists at least one privilege document in the system.
         */
        bool hasAnyPrivilegeDocuments();

        /**
         * Creates the given user object in the given database.
         *
         * TODO(spencer): remove dbname argument once users are only written into the admin db
         */
        Status insertPrivilegeDocument(const std::string& dbname,
                                       const BSONObj& userObj,
                                       const BSONObj& writeConcern);

        /**
         * Updates the given user object with the given update modifier.
         */
        Status updatePrivilegeDocument(const UserName& user,
                                       const BSONObj& updateObj,
                                       const BSONObj& writeConcern);

        /**
         * Removes users for the given database matching the given query.
         * Writes into *numRemoved the number of user documents that were modified.
         */
        Status removePrivilegeDocuments(const BSONObj& query,
                                        const BSONObj& writeConcern,
                                        int* numRemoved);

        /**
         * Puts into the *dbnames vector the name of every database in the cluster.
         * May take a global lock, so should only be called during startup.
         */
        virtual Status getAllDatabaseNames(std::vector<std::string>* dbnames) = 0;


        // Returns true if there exists at least one privilege document in the given database.
        bool hasPrivilegeDocument(const std::string& dbname) const;

        // Creates the given user object in the given database.
        virtual Status insertPrivilegeDocument(const std::string& dbname,
                                               const BSONObj& userObj) const = 0;

        // Updates the given user object with the given update modifier.
        virtual Status updatePrivilegeDocument(const UserName& user,
                                               const BSONObj& updateObj) const = 0;

    protected:
        AuthzManagerExternalState(); // This class should never be instantiated directly.

        // Queries the userNamespace with the given query and returns the privilegeDocument found
        // in *result.  Returns true if it finds a document matching the query, or false if not.
        virtual bool _findUser(const std::string& usersNamespace,
                               const BSONObj& query,
                               BSONObj* result) const = 0;

    };

} // namespace mongo
