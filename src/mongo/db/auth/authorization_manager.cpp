/**
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

#include "mongo/platform/basic.h"

#include "mongo/db/auth/authorization_manager.h"

#include <boost/thread/mutex.hpp>
#include <memory>
#include <string>
#include <vector>

#include "mongo/base/init.h"
#include "mongo/base/status.h"
#include "mongo/db/auth/action_set.h"
#include "mongo/db/auth/privilege.h"
#include "mongo/db/auth/privilege_set.h"
#include "mongo/db/auth/user.h"
#include "mongo/db/auth/user_name.h"
#include "mongo/db/auth/user_name_hash.h"
#include "mongo/db/jsobj.h"
#include "mongo/platform/unordered_map.h"
#include "mongo/util/mongoutils/str.h"

namespace mongo {

    AuthInfo::AuthInfo() {
        user = "__system";
    }
    AuthInfo internalSecurity;

    const std::string AuthorizationManager::SERVER_RESOURCE_NAME = "$SERVER";
    const std::string AuthorizationManager::CLUSTER_RESOURCE_NAME = "$CLUSTER";
    const std::string AuthorizationManager::USER_NAME_FIELD_NAME = "user";
    const std::string AuthorizationManager::USER_SOURCE_FIELD_NAME = "userSource";
    const std::string AuthorizationManager::PASSWORD_FIELD_NAME = "pwd";

    const NamespaceString AuthorizationManager::adminCommandNamespace("admin.$cmd");
    const NamespaceString AuthorizationManager::rolesCollectionNamespace("admin.system.roles");
    const NamespaceString AuthorizationManager::usersAltCollectionNamespace(
            "admin.system.new_users");
    const NamespaceString AuthorizationManager::usersBackupCollectionNamespace(
            "admin.system.backup_users");
    const NamespaceString AuthorizationManager::usersCollectionNamespace("admin.system.users");
    const NamespaceString AuthorizationManager::versionCollectionNamespace("admin.system.version");
    const NamespaceString AuthorizationManager::defaultTempUsersCollectionNamespace(
            "admin.tempusers");
    const NamespaceString AuthorizationManager::defaultTempRolesCollectionNamespace(
            "admin.temproles");

namespace {
    const std::string ADMIN_DBNAME = "admin";
    const std::string LOCAL_DBNAME = "local";

    const std::string ROLES_FIELD_NAME = "roles";
    const std::string OTHER_DB_ROLES_FIELD_NAME = "otherDBRoles";
    const std::string READONLY_FIELD_NAME = "readOnly";

    const std::string SYSTEM_ROLE_READ = "read";
    const std::string SYSTEM_ROLE_READ_WRITE = "readWrite";
    const std::string SYSTEM_ROLE_USER_ADMIN = "userAdmin";
    const std::string SYSTEM_ROLE_DB_ADMIN = "dbAdmin";
    const std::string SYSTEM_ROLE_CLUSTER_ADMIN = "clusterAdmin";
    const std::string SYSTEM_ROLE_READ_ANY_DB = "readAnyDatabase";
    const std::string SYSTEM_ROLE_READ_WRITE_ANY_DB = "readWriteAnyDatabase";
    const std::string SYSTEM_ROLE_USER_ADMIN_ANY_DB = "userAdminAnyDatabase";
    const std::string SYSTEM_ROLE_DB_ADMIN_ANY_DB = "dbAdminAnyDatabase";

    // System roles for backwards compatibility with 2.2 and prior
    const std::string SYSTEM_ROLE_V0_READ = "oldRead";
    const std::string SYSTEM_ROLE_V0_READ_WRITE= "oldReadWrite";
    const std::string SYSTEM_ROLE_V0_ADMIN_READ = "oldAdminRead";
    const std::string SYSTEM_ROLE_V0_ADMIN_READ_WRITE= "oldAdminReadWrite";

    // ActionSets for the various system roles.  These ActionSets contain all the actions that
    // a user of each system role is granted.
    ActionSet readRoleActions;
    ActionSet readWriteRoleActions;
    ActionSet userAdminRoleActions;
    ActionSet dbAdminRoleActions;
    ActionSet clusterAdminRoleActions;
    // Can only be performed by internal connections.  Nothing ever explicitly grants these actions,
    // but they're included when calling addAllActions on an ActionSet, which is how internal
    // connections are granted their privileges.
    ActionSet internalActions;
    // Old-style user roles
    ActionSet compatibilityReadOnlyActions;
    ActionSet compatibilityReadWriteActions;
    ActionSet compatibilityReadOnlyAdminActions;
    ActionSet compatibilityReadWriteAdminActions;

}  // namespace


    // This sets up the system role ActionSets.  This is what determines what actions each role
    // is authorized to perform
    MONGO_INITIALIZER(AuthorizationSystemRoles)(InitializerContext* context) {
        // Read role
        readRoleActions.addAction(ActionType::cloneCollectionLocalSource);
        readRoleActions.addAction(ActionType::collStats);
        readRoleActions.addAction(ActionType::dbHash);
        readRoleActions.addAction(ActionType::dbStats);
        readRoleActions.addAction(ActionType::find);
        readRoleActions.addAction(ActionType::indexRead);
        readRoleActions.addAction(ActionType::killCursors);

        // Read-write role
        readWriteRoleActions.addAllActionsFromSet(readRoleActions);
        readWriteRoleActions.addAction(ActionType::cloneCollectionTarget);
        readWriteRoleActions.addAction(ActionType::convertToCapped);
        readWriteRoleActions.addAction(ActionType::createCollection); // db admin gets this also
        readWriteRoleActions.addAction(ActionType::dropCollection);
        readWriteRoleActions.addAction(ActionType::dropIndexes);
        readWriteRoleActions.addAction(ActionType::emptycapped);
        readWriteRoleActions.addAction(ActionType::ensureIndex);
        readWriteRoleActions.addAction(ActionType::insert);
        readWriteRoleActions.addAction(ActionType::remove);
        readWriteRoleActions.addAction(ActionType::renameCollectionSameDB); // db admin gets this also
        readWriteRoleActions.addAction(ActionType::update);

        // User admin role
        userAdminRoleActions.addAction(ActionType::userAdmin);

        // DB admin role
        dbAdminRoleActions.addAction(ActionType::clean);
        dbAdminRoleActions.addAction(ActionType::cloneCollectionLocalSource);
        dbAdminRoleActions.addAction(ActionType::collMod);
        dbAdminRoleActions.addAction(ActionType::collStats);
        dbAdminRoleActions.addAction(ActionType::compact);
        dbAdminRoleActions.addAction(ActionType::convertToCapped);
        dbAdminRoleActions.addAction(ActionType::createCollection); // read_write gets this also
        dbAdminRoleActions.addAction(ActionType::dbStats);
        dbAdminRoleActions.addAction(ActionType::dropCollection);
        dbAdminRoleActions.addAction(ActionType::dropIndexes);
        dbAdminRoleActions.addAction(ActionType::ensureIndex);
        dbAdminRoleActions.addAction(ActionType::indexRead);
        dbAdminRoleActions.addAction(ActionType::indexStats);
        dbAdminRoleActions.addAction(ActionType::profileEnable);
        dbAdminRoleActions.addAction(ActionType::profileRead);
        dbAdminRoleActions.addAction(ActionType::reIndex);
        dbAdminRoleActions.addAction(ActionType::renameCollectionSameDB); // read_write gets this also
        dbAdminRoleActions.addAction(ActionType::storageDetails);
        dbAdminRoleActions.addAction(ActionType::validate);

        // We separate clusterAdmin read-only and read-write actions for backwards
        // compatibility with old-style read-only admin users.  This separation is not exposed to
        // the user, and could go away once we stop supporting old-style privilege documents.
        ActionSet clusterAdminRoleReadActions;
        ActionSet clusterAdminRoleWriteActions;

        // Cluster admin role
        clusterAdminRoleReadActions.addAction(ActionType::connPoolStats);
        clusterAdminRoleReadActions.addAction(ActionType::connPoolSync);
        clusterAdminRoleReadActions.addAction(ActionType::getCmdLineOpts);
        clusterAdminRoleReadActions.addAction(ActionType::getLog);
        clusterAdminRoleReadActions.addAction(ActionType::getParameter);
        clusterAdminRoleReadActions.addAction(ActionType::getShardMap);
        clusterAdminRoleReadActions.addAction(ActionType::getShardVersion);
        clusterAdminRoleReadActions.addAction(ActionType::hostInfo);
        clusterAdminRoleReadActions.addAction(ActionType::listDatabases);
        clusterAdminRoleReadActions.addAction(ActionType::listShards);
        clusterAdminRoleReadActions.addAction(ActionType::logRotate);
        clusterAdminRoleReadActions.addAction(ActionType::netstat);
        clusterAdminRoleReadActions.addAction(ActionType::replSetFreeze);
        clusterAdminRoleReadActions.addAction(ActionType::replSetGetStatus);
        clusterAdminRoleReadActions.addAction(ActionType::replSetMaintenance);
        clusterAdminRoleReadActions.addAction(ActionType::replSetStepDown);
        clusterAdminRoleReadActions.addAction(ActionType::replSetSyncFrom);
        clusterAdminRoleReadActions.addAction(ActionType::setParameter);
        clusterAdminRoleReadActions.addAction(ActionType::setShardVersion); // TODO: should this be internal?
        clusterAdminRoleReadActions.addAction(ActionType::serverStatus);
        clusterAdminRoleReadActions.addAction(ActionType::splitVector);
        // Shutdown is in read actions b/c that's how it was in 2.2
        clusterAdminRoleReadActions.addAction(ActionType::shutdown);
        clusterAdminRoleReadActions.addAction(ActionType::top);
        clusterAdminRoleReadActions.addAction(ActionType::touch);
        clusterAdminRoleReadActions.addAction(ActionType::unlock);
        clusterAdminRoleReadActions.addAction(ActionType::unsetSharding);
        clusterAdminRoleReadActions.addAction(ActionType::writeBacksQueued);

        clusterAdminRoleWriteActions.addAction(ActionType::addShard);
        clusterAdminRoleWriteActions.addAction(ActionType::closeAllDatabases);
        clusterAdminRoleWriteActions.addAction(ActionType::cpuProfiler);
        clusterAdminRoleWriteActions.addAction(ActionType::cursorInfo);
        clusterAdminRoleWriteActions.addAction(ActionType::diagLogging);
        clusterAdminRoleWriteActions.addAction(ActionType::dropDatabase); // TODO: Should there be a CREATE_DATABASE also?
        clusterAdminRoleWriteActions.addAction(ActionType::enableSharding);
        clusterAdminRoleWriteActions.addAction(ActionType::flushRouterConfig);
        clusterAdminRoleWriteActions.addAction(ActionType::fsync);
        clusterAdminRoleWriteActions.addAction(ActionType::inprog);
        clusterAdminRoleWriteActions.addAction(ActionType::killop);
        clusterAdminRoleWriteActions.addAction(ActionType::moveChunk);
        clusterAdminRoleWriteActions.addAction(ActionType::movePrimary);
        clusterAdminRoleWriteActions.addAction(ActionType::removeShard);
        clusterAdminRoleWriteActions.addAction(ActionType::repairDatabase);
        clusterAdminRoleWriteActions.addAction(ActionType::replSetInitiate);
        clusterAdminRoleWriteActions.addAction(ActionType::replSetReconfig);
        clusterAdminRoleWriteActions.addAction(ActionType::resync);
        clusterAdminRoleWriteActions.addAction(ActionType::shardCollection);
        clusterAdminRoleWriteActions.addAction(ActionType::shardingState);
        clusterAdminRoleWriteActions.addAction(ActionType::split);
        clusterAdminRoleWriteActions.addAction(ActionType::splitChunk);

        clusterAdminRoleActions.addAllActionsFromSet(clusterAdminRoleReadActions);
        clusterAdminRoleActions.addAllActionsFromSet(clusterAdminRoleWriteActions);
        clusterAdminRoleActions.addAction(ActionType::killCursors);

        // Old-style user actions, for backwards compatibility
        compatibilityReadOnlyActions.addAllActionsFromSet(readRoleActions);

        compatibilityReadWriteActions.addAllActionsFromSet(readWriteRoleActions);
        compatibilityReadWriteActions.addAllActionsFromSet(dbAdminRoleActions);
        compatibilityReadWriteActions.addAllActionsFromSet(userAdminRoleActions);
        compatibilityReadWriteActions.addAction(ActionType::clone);
        compatibilityReadWriteActions.addAction(ActionType::copyDBTarget);
        compatibilityReadWriteActions.addAction(ActionType::dropDatabase);
        compatibilityReadWriteActions.addAction(ActionType::repairDatabase);

        compatibilityReadOnlyAdminActions.addAllActionsFromSet(compatibilityReadOnlyActions);
        compatibilityReadOnlyAdminActions.addAllActionsFromSet(clusterAdminRoleReadActions);

        compatibilityReadWriteAdminActions.addAllActionsFromSet(compatibilityReadWriteActions);
        compatibilityReadWriteAdminActions.addAllActionsFromSet(compatibilityReadOnlyAdminActions);
        compatibilityReadWriteAdminActions.addAllActionsFromSet(clusterAdminRoleWriteActions);

        // Internal commands
        internalActions.addAction(ActionType::clone);
        internalActions.addAction(ActionType::handshake);
        internalActions.addAction(ActionType::mapReduceShardedFinish);
        internalActions.addAction(ActionType::replSetElect);
        internalActions.addAction(ActionType::replSetFresh);
        internalActions.addAction(ActionType::replSetGetRBID);
        internalActions.addAction(ActionType::replSetHeartbeat);
        internalActions.addAction(ActionType::writebacklisten);
        internalActions.addAction(ActionType::_migrateClone);
        internalActions.addAction(ActionType::_recvChunkAbort);
        internalActions.addAction(ActionType::_recvChunkCommit);
        internalActions.addAction(ActionType::_recvChunkStart);
        internalActions.addAction(ActionType::_recvChunkStatus);
        internalActions.addAction(ActionType::_transferMods);

        return Status::OK();
    }

    bool AuthorizationManager::_doesSupportOldStylePrivileges = true;

    /**
     * Guard object for synchronizing accesses to data cached in AuthorizationManager instances.
     * This guard allows one thread to access the cache at a time, and provides an exception-safe
     * mechanism for a thread to release the cache mutex while performing network or disk operations
     * while allowing other readers to proceed.
     *
     * There are two ways to use this guard.  One may simply instantiate the guard like a
     * std::lock_guard, and perform reads or writes of the cache.
     *
     * Alternatively, one may instantiate the guard, examine the cache, and then enter into an
     * update mode by first wait()ing until otherUpdateInFetchPhase() is false, and then
     * calling beginFetchPhase().  At this point, other threads may acquire the guard in the simple
     * manner and do reads, but other threads may not enter into a fetch phase.  During the fetch
     * phase, the thread should perform required network or disk activity to determine what update
     * it will make to the cache.  Then, it should call endFetchPhase(), to reacquire the user cache
     * mutex.  At that point, the thread can make its modifications to the cache and let the guard
     * go out of scope.
     *
     * All updates by guards using a fetch-phase are totally ordered with respect to one another,
     * and all guards using no fetch phase are totally ordered with respect to one another, but
     * there is not a total ordering among all guard objects.
     *
     * The cached data has an associated counter, called the cache generation.  If the cache
     * generation changes while a guard is in fetch phase, the fetched data should not be stored
     * into the cache, because some invalidation event occurred during the fetch phase.
     *
     * NOTE: It is not safe to enter fetch phase while holding a database lock.  Fetch phase
     * operations are allowed to acquire database locks themselves, so entering fetch while holding
     * a database lock may lead to deadlock.
     */
    class AuthorizationManager::CacheGuard {
        MONGO_DISALLOW_COPYING(CacheGuard);
    public:
        enum FetchSynchronization {
            fetchSynchronizationAutomatic,
            fetchSynchronizationManual
        };

        /**
         * Constructs a cache guard, locking the mutex that synchronizes user cache accesses.
         */
        CacheGuard(AuthorizationManager* authzManager,
                   const FetchSynchronization sync = fetchSynchronizationAutomatic) :
            _isThisGuardInFetchPhase(false),
            _authzManager(authzManager),
            _lock(authzManager->_cacheMutex) {

            if (fetchSynchronizationAutomatic == sync) {
                synchronizeWithFetchPhase();
            }
        }

        /**
         * Releases the mutex that synchronizes user cache access, if held, and notifies
         * any threads waiting for their own opportunity to update the user cache.
         */
        ~CacheGuard() {
            if (!_lock.owns_lock()) {
                _lock.lock();
            }
            if (_isThisGuardInFetchPhase) {
                fassert(17190, _authzManager->_isFetchPhaseBusy);
                _authzManager->_isFetchPhaseBusy = false;
                _authzManager->_fetchPhaseIsReady.notify_all();
            }
        }

        /**
         * Returns true of the authzManager reports that it is in fetch phase.
         */
        bool otherUpdateInFetchPhase() { return _authzManager->_isFetchPhaseBusy; }

        /**
         * Waits on the _authzManager->_fetchPhaseIsReady condition.
         */
        void wait() {
            fassert(0, !_isThisGuardInFetchPhase);
            _authzManager->_fetchPhaseIsReady.wait(_lock);
        }

        /**
         * Enters fetch phase, releasing the _authzManager->_cacheMutex after recording the current
         * cache generation.
         */
        void beginFetchPhase() {
            fassert(17191, !_authzManager->_isFetchPhaseBusy);
            _isThisGuardInFetchPhase = true;
            _authzManager->_isFetchPhaseBusy = true;
            _startGeneration = _authzManager->_cacheGeneration;
            _lock.unlock();
        }

        /**
         * Exits the fetch phase, reacquiring the _authzManager->_cacheMutex.
         */
        void endFetchPhase() {
            _lock.lock();
            _isThisGuardInFetchPhase = false;
            _authzManager->_isFetchPhaseBusy = false;
        }

        /**
         * Returns true if _authzManager->_cacheGeneration remained the same while this guard was
         * in fetch phase.  Behavior is undefined if this guard never entered fetch phase.
         *
         * If this returns true, do not update the cached data with this
         */
        bool isSameCacheGeneration() const {
            fassert(0, !_isThisGuardInFetchPhase);
            return _startGeneration == _authzManager->_cacheGeneration;
        }

    static inline StringData makeStringDataFromBSONElement(const BSONElement& element) {
        return StringData(element.valuestr(), element.valuestrsize() - 1);
    }

        uint64_t _startGeneration;
        bool _isThisGuardInFetchPhase;
        AuthorizationManager* _authzManager;
        boost::unique_lock<boost::mutex> _lock;
    };

    AuthorizationManager::AuthorizationManager(AuthzManagerExternalState* externalState) :
        _authEnabled(false),
        _externalState(externalState),
        _version(2),
        _cacheGeneration(0),
        _isFetchPhaseBusy(false) {
    }

    AuthorizationManager::~AuthorizationManager() {
        for (unordered_map<UserName, User*>::iterator it = _userCache.begin();
                it != _userCache.end(); ++it) {
            delete it->second ;
        }
    }

    int AuthorizationManager::getAuthorizationVersion() {
        CacheGuard guard(this, CacheGuard::fetchSynchronizationManual);
        int newVersion = _version;
        if (0 == newVersion) {
            guard.beginFetchPhase();
            Status status = _externalState->getStoredAuthorizationVersion(&newVersion);
            guard.endFetchPhase();
            if (status.isOK()) {
                if (guard.isSameCacheGeneration()) {
                    _version = newVersion;
                }
            }
            else {
                warning() << "Could not determine schema version of authorization data. " << status;
            }
        }
        return newVersion;
    }

    void AuthorizationManager::setSupportOldStylePrivilegeDocuments(bool enabled) {
        _doesSupportOldStylePrivileges = enabled;
    }

    bool AuthorizationManager::getSupportOldStylePrivilegeDocuments() {
        return _doesSupportOldStylePrivileges;
    }

    void AuthorizationManager::setAuthEnabled(bool enabled) {
        _authEnabled = enabled;
    }

    bool AuthorizationManager::isAuthEnabled() {
        return _authEnabled;
    }

    Status AuthorizationManager::getPrivilegeDocument(const std::string& dbname,
                                                      const UserName& userName,
                                                      BSONObj* result) const {
        return _externalState->getPrivilegeDocument(dbname, userName, result);
    }

    bool AuthorizationManager::hasPrivilegeDocument(const std::string& dbname) const {
        return _externalState->hasPrivilegeDocument(dbname);
    }

    Status AuthorizationManager::insertPrivilegeDocument(const std::string& dbname,
                                                         const BSONObj& userObj) const {
        return _externalState->insertPrivilegeDocument(dbname, userObj);
    }

    Status AuthorizationManager::updatePrivilegeDocument(const UserName& user,
                                                         const BSONObj& updateObj) const {
        return _externalState->updatePrivilegeDocument(user, updateObj);
    }

    ActionSet AuthorizationManager::getAllUserActions() const {
        ActionSet allActions;
        allActions.addAllActionsFromSet(readRoleActions);
        allActions.addAllActionsFromSet(readWriteRoleActions);
        allActions.addAllActionsFromSet(userAdminRoleActions);
        allActions.addAllActionsFromSet(dbAdminRoleActions);
        allActions.addAllActionsFromSet(clusterAdminRoleActions);
        return allActions;
    }

    ActionSet AuthorizationManager::getActionsForOldStyleUser(const std::string& dbname,
                                                              bool readOnly) const {
        if (dbname == ADMIN_DBNAME || dbname == LOCAL_DBNAME) {
            if (readOnly) {
                return compatibilityReadOnlyAdminActions;
            } else {
                return compatibilityReadWriteAdminActions;
            }
        } else {
            if (readOnly) {
                return compatibilityReadOnlyActions;
            } else {
                return compatibilityReadWriteActions;
            }
        }
    }


    Status _checkRolesArray(const BSONElement& rolesElement) {
        if (rolesElement.type() != Array) {
            return _badValue("Role fields must be an array when present in system.users entries",
                             0);
        }
        for (BSONObjIterator iter(rolesElement.embeddedObject()); iter.more(); iter.next()) {
            BSONElement element = *iter;
            if (element.type() != String || makeStringDataFromBSONElement(element).empty()) {
                return _badValue("Roles must be non-empty strings.", 0);
            }
        }
        return Status::OK();
    }

    Status AuthorizationManager::checkValidPrivilegeDocument(const StringData& dbname,
                                                             const BSONObj& doc) {
        BSONElement userElement = doc[AuthorizationManager::USER_NAME_FIELD_NAME];
        BSONElement userSourceElement = doc[AuthorizationManager::USER_SOURCE_FIELD_NAME];
        BSONElement passwordElement = doc[AuthorizationManager::PASSWORD_FIELD_NAME];
        BSONElement rolesElement = doc[ROLES_FIELD_NAME];
        BSONElement otherDBRolesElement = doc[OTHER_DB_ROLES_FIELD_NAME];
        BSONElement readOnlyElement = doc[READONLY_FIELD_NAME];

        // Validate the "user" element.
        if (userElement.type() != String)
            return _badValue("system.users entry needs 'user' field to be a string", 14051);
        if (makeStringDataFromBSONElement(userElement).empty())
            return _badValue("system.users entry needs 'user' field to be non-empty", 14053);

        // Must set exactly one of "userSource" and "pwd" fields.
        if (userSourceElement.eoo() == passwordElement.eoo()) {
            return _badValue("system.users entry must have either a 'pwd' field or a 'userSource' "
                             "field, but not both", 0);
        }

        if (!AuthorizationManager::getSupportOldStylePrivilegeDocuments() && rolesElement.eoo()) {
            return _oldPrivilegeFormatNotSupported();
        }

        // Cannot have both "roles" and "readOnly" elements.
        if (!rolesElement.eoo() && !readOnlyElement.eoo()) {
            return _badValue("system.users entry must not have both 'roles' and 'readOnly' fields",
                             0);
        }

        // Validate the "pwd" element, if present.
        if (!passwordElement.eoo()) {
            if (passwordElement.type() != String)
                return _badValue("system.users entry needs 'pwd' field to be a string", 14052);
            if (makeStringDataFromBSONElement(passwordElement).empty())
                return _badValue("system.users entry needs 'pwd' field to be non-empty", 14054);
        }

        // Validate the "userSource" element, if present.
        if (!userSourceElement.eoo()) {
            if (userSourceElement.type() != String ||
                makeStringDataFromBSONElement(userSourceElement).empty()) {

                return _badValue("system.users entry needs 'userSource' field to be a non-empty "
                                 "string, if present", 0);
            }
            if (userSourceElement.str() == dbname) {
                return _badValue(mongoutils::str::stream() << "'" << dbname <<
                                 "' is not a valid value for the userSource field in " <<
                                 dbname << ".system.users entries",
                                 0);
            }
            if (rolesElement.eoo()) {
                return _badValue("system.users entry needs 'roles' field if 'userSource' field "
                                 "is present.", 0);
            }
        }

        // Validate the "roles" element.
        if (!rolesElement.eoo()) {
            Status status = _checkRolesArray(rolesElement);
            if (!status.isOK())
                return status;
        }

        if (!otherDBRolesElement.eoo()) {
            if (dbname != ADMIN_DBNAME) {
                return _badValue("Only admin.system.users entries may contain 'otherDBRoles' "
                                 "fields", 0);
            }
            if (rolesElement.eoo()) {
                return _badValue("system.users entries with 'otherDBRoles' fields must contain "
                                 "'roles' fields", 0);
            }
            if (otherDBRolesElement.type() != Object) {
                return _badValue("'otherDBRoles' field must be an object when present in "
                                 "system.users entries", 0);
            }
            for (BSONObjIterator iter(otherDBRolesElement.embeddedObject());
                 iter.more(); iter.next()) {

                Status status = _checkRolesArray(*iter);
                if (!status.isOK())
                    return status;
            }
        }

        return Status::OK();
    }

    Status AuthorizationManager::buildPrivilegeSet(const std::string& dbname,
                                                   const UserName& user,
                                                   const BSONObj& privilegeDocument,
                                                   PrivilegeSet* result) const {
        if (!privilegeDocument.hasField(ROLES_FIELD_NAME)) {
            // Old-style (v2.2 and prior) privilege document
            if (AuthorizationManager::getSupportOldStylePrivilegeDocuments()) {
                return _buildPrivilegeSetFromOldStylePrivilegeDocument(dbname,
                                                                       user,
                                                                       privilegeDocument,
                                                                       result);
            }
            else {
                return _oldPrivilegeFormatNotSupported();
            }
        }
        else {
            return _buildPrivilegeSetFromExtendedPrivilegeDocument(
                    dbname, user, privilegeDocument, result);
        }
    }

    Status AuthorizationManager::_buildPrivilegeSetFromOldStylePrivilegeDocument(
            const std::string& dbname,
            const UserName& user,
            const BSONObj& privilegeDocument,
            PrivilegeSet* result) const {
        if (!(privilegeDocument.hasField(AuthorizationManager::USER_NAME_FIELD_NAME) &&
              privilegeDocument.hasField(AuthorizationManager::PASSWORD_FIELD_NAME))) {

            return Status(ErrorCodes::UnsupportedFormat,
                          mongoutils::str::stream() << "Invalid old-style privilege document "
                                  "received when trying to extract privileges: "
                                   << privilegeDocument,
                          0);
        }
        std::string userName = privilegeDocument[AuthorizationManager::USER_NAME_FIELD_NAME].str();
        if (userName != user.getUser()) {
            return Status(ErrorCodes::BadValue,
                          mongoutils::str::stream() << "Principal name from privilege document \""
                                  << userName
                                  << "\" doesn't match name of provided Principal \""
                                  << user.getUser()
                                  << "\"",
                          0);
        }

        bool readOnly = privilegeDocument[READONLY_FIELD_NAME].trueValue();
        ActionSet actions = getActionsForOldStyleUser(dbname, readOnly);
        std::string resourceName = (dbname == ADMIN_DBNAME || dbname == LOCAL_DBNAME) ?
            PrivilegeSet::WILDCARD_RESOURCE : dbname;
        result->grantPrivilege(Privilege(resourceName, actions), user);

        return Status::OK();
    }


    /**
     * Adds to "outPrivileges" the privileges associated with having the named "role" on "dbname".
     *
     * Returns non-OK status if "role" is not a defined role in "dbname".
     */
    void _addPrivilegesForSystemRole(const std::string& dbname,
                                     const std::string& role,
                                     std::vector<Privilege>* outPrivileges) {
        const bool isAdminDB = (dbname == ADMIN_DBNAME);

        if (role == SYSTEM_ROLE_READ) {
            outPrivileges->push_back(Privilege(dbname, readRoleActions));
        }
        else if (role == SYSTEM_ROLE_READ_WRITE) {
            outPrivileges->push_back(Privilege(dbname, readWriteRoleActions));
        }
        else if (role == SYSTEM_ROLE_USER_ADMIN) {
            outPrivileges->push_back(Privilege(dbname, userAdminRoleActions));
        }
        else if (role == SYSTEM_ROLE_DB_ADMIN) {
            outPrivileges->push_back(Privilege(dbname, dbAdminRoleActions));
        }
        else if (role == SYSTEM_ROLE_V0_READ) {
            outPrivileges->push_back(Privilege(dbname, compatibilityReadOnlyActions));
        }
        else if (role == SYSTEM_ROLE_V0_READ_WRITE) {
            outPrivileges->push_back(Privilege(dbname, compatibilityReadWriteActions));
        }
        else if (isAdminDB && role == SYSTEM_ROLE_READ_ANY_DB) {
            outPrivileges->push_back(Privilege(PrivilegeSet::WILDCARD_RESOURCE, readRoleActions));
        }
        else if (isAdminDB && role == SYSTEM_ROLE_READ_WRITE_ANY_DB) {
            outPrivileges->push_back(
                    Privilege(PrivilegeSet::WILDCARD_RESOURCE, readWriteRoleActions));
        }
        else if (isAdminDB && role == SYSTEM_ROLE_USER_ADMIN_ANY_DB) {
            outPrivileges->push_back(
                    Privilege(PrivilegeSet::WILDCARD_RESOURCE, userAdminRoleActions));
        }
        else if (isAdminDB && role == SYSTEM_ROLE_DB_ADMIN_ANY_DB) {
            outPrivileges->push_back(
                    Privilege(PrivilegeSet::WILDCARD_RESOURCE, dbAdminRoleActions));
        }
        else if (isAdminDB && role == SYSTEM_ROLE_CLUSTER_ADMIN) {
            outPrivileges->push_back(
                    Privilege(PrivilegeSet::WILDCARD_RESOURCE, clusterAdminRoleActions));
        }
        else if (isAdminDB && role == SYSTEM_ROLE_V0_ADMIN_READ) {
            outPrivileges->push_back(
                    Privilege(PrivilegeSet::WILDCARD_RESOURCE, compatibilityReadOnlyAdminActions));
        }
        else if (isAdminDB && role == SYSTEM_ROLE_V0_ADMIN_READ_WRITE) {
            outPrivileges->push_back(
                    Privilege(PrivilegeSet::WILDCARD_RESOURCE, compatibilityReadWriteAdminActions));
        }
        else {
            warning() << "No such role, \"" << role << "\", in database " << dbname <<
                    ". No privileges will be acquired from this role" << endl;
        }
    }

    /**
     * Given a database name and a BSONElement representing an array of roles, populates
     * "outPrivileges" with the privileges associated with the given roles on the named database.
     *
     * Returns Status::OK() on success.
     */
    Status _getPrivilegesFromRoles(const std::string& dbname,
                                   const BSONElement& rolesElement,
                                   std::vector<Privilege>* outPrivileges) {

        static const char privilegesTypeMismatchMessage[] =
            "Roles must be enumerated in an array of strings.";

        if (dbname == PrivilegeSet::WILDCARD_RESOURCE) {
            return Status(ErrorCodes::BadValue,
                          PrivilegeSet::WILDCARD_RESOURCE + " is an invalid database name.");
        }

        if (rolesElement.type() != Array)
            return Status(ErrorCodes::TypeMismatch, privilegesTypeMismatchMessage);

        for (BSONObjIterator iter(rolesElement.embeddedObject()); iter.more(); iter.next()) {
            BSONElement roleElement = *iter;
            if (roleElement.type() != String)
                return Status(ErrorCodes::TypeMismatch, privilegesTypeMismatchMessage);
            _addPrivilegesForSystemRole(dbname, roleElement.str(), outPrivileges);
        }
        return Status::OK();
    }

    Status AuthorizationManager::_buildPrivilegeSetFromExtendedPrivilegeDocument(
            const std::string& dbname,
            const UserName& user,
            const BSONObj& privilegeDocument,
            PrivilegeSet* result) const {

        if (!privilegeDocument[READONLY_FIELD_NAME].eoo()) {
            return Status(ErrorCodes::UnsupportedFormat,
                          "Privilege documents may not contain both \"readonly\" and "
                          "\"roles\" fields");
        }

        std::vector<Privilege> acquiredPrivileges;

        // Acquire privileges on "dbname".
        Status status = _getPrivilegesFromRoles(
                dbname, privilegeDocument[ROLES_FIELD_NAME], &acquiredPrivileges);
        if (!status.isOK())
            return status;

        // If "dbname" is the admin database, handle the otherDBPrivileges field, which
        // grants privileges on databases other than "dbname".
        BSONElement otherDbPrivileges = privilegeDocument[OTHER_DB_ROLES_FIELD_NAME];
        if (dbname == ADMIN_DBNAME) {
            switch (otherDbPrivileges.type()) {
            case EOO:
                break;
            case Object: {
                for (BSONObjIterator iter(otherDbPrivileges.embeddedObject());
                     iter.more(); iter.next()) {

                    BSONElement rolesElement = *iter;
                    status = _getPrivilegesFromRoles(
                            rolesElement.fieldName(), rolesElement, &acquiredPrivileges);
                    if (!status.isOK())
                        return status;
                }
                break;
            }
            default:
                return Status(ErrorCodes::TypeMismatch,
                              "Field \"otherDBRoles\" must be an object, if present.");
            }
        }
        else if (!otherDbPrivileges.eoo()) {
            return Status(ErrorCodes::BadValue, "Only the admin database may contain a field "
                          "called \"otherDBRoles\"");
        }

        result->grantPrivileges(acquiredPrivileges, user);
        return Status::OK();
    }

    Status AuthorizationManager::acquireUser(const UserName& userName, User** acquiredUser) {
        boost::lock_guard<boost::mutex> lk(_lock);
        unordered_map<UserName, User*>::iterator it = _userCache.find(userName);
        if (it != _userCache.end()) {
            fassert(16914, it->second);
            it->second->incrementRefCount();
            *acquiredUser = it->second;
            return Status::OK();
        }

        std::auto_ptr<User> user;

        int authzVersion = _version;
        guard.beginFetchPhase();
        if (authzVersion == 0) {
            Status status = _externalState->getStoredAuthorizationVersion(&authzVersion);
            if (!status.isOK())
                return status;
        }

        switch (authzVersion) {
        default:
            return Status(ErrorCodes::BadValue, mongoutils::str::stream() <<
                          "Illegal value for authorization data schema version, " << authzVersion);
        case 2: {
            Status status = _fetchUserV2(userName, &user);
            if (!status.isOK())
                return status;
            break;
        }
        case 1: {
            Status status = _fetchUserV1(userName, &user);
            if (!status.isOK())
                return status;
            break;
        }
        }
        guard.endFetchPhase();

        user->incrementRefCount();

        // NOTE: It is not safe to throw an exception from here to the end of the method.
        if (guard.isSameCacheGeneration()) {
            _userCache.insert(make_pair(userName, user.get()));
            if (_version == 0)
                _version = authzVersion;
        }
        else {
            // If the cache generation changed while this thread was in fetch mode, the data
            // associated with the user may now be invalid, so we must mark it as such.  The caller
            // may still opt to use the information for a short while, but not indefinitely.
            user->invalidate();
        }
        *acquiredUser = user.release();

        return Status::OK();
    }

    Status AuthorizationManager::_fetchUserV2(const UserName& userName,
                                              std::auto_ptr<User>* acquiredUser) {
        BSONObj userObj;
        Status status = getUserDescription(userName, &userObj);
        if (!status.isOK()) {
            return status;
        }

        // Put the new user into an auto_ptr temporarily in case there's an error while
        // initializing the user.
        std::auto_ptr<User> user(new User(userName));

        status = _initializeUserFromPrivilegeDocument(user.get(), userObj);
        if (!status.isOK()) {
            return status;
        }
        acquiredUser->reset(user.release());
        return Status::OK();
    }

    Status AuthorizationManager::_fetchUserV1(const UserName& userName,
                                              std::auto_ptr<User>* acquiredUser) {

        BSONObj privDoc;
        V1UserDocumentParser parser;
        const bool isExternalUser = (userName.getDB() == "$external");
        const bool isAdminUser = (userName.getDB() == "admin");

        std::auto_ptr<User> user(new User(userName));
        user->setSchemaVersion1();
        user->markProbedV1("$external");
        if (isExternalUser) {
            User::CredentialData creds;
            creds.isExternal = true;
            user->setCredentials(creds);
        }
        else {
            // Users from databases other than "$external" must have an associated privilege
            // document in their database.
            Status status = _externalState->getPrivilegeDocumentV1(
                    userName.getDB(), userName, &privDoc);
            if (!status.isOK())
                return status;

            status = parser.initializeUserRolesFromUserDocument(
                    user.get(), privDoc, userName.getDB());
            if (!status.isOK())
                return status;

            status = parser.initializeUserCredentialsFromUserDocument(user.get(), privDoc);
            if (!status.isOK())
                return status;
            user->markProbedV1(userName.getDB());
        }
        if (!isAdminUser) {
            // Users from databases other than "admin" probe the "admin" database at login, to
            // ensure that the acquire any privileges derived from "otherDBRoles" fields in
            // admin.system.users.
            Status status = _externalState->getPrivilegeDocumentV1("admin", userName, &privDoc);
            if (status.isOK()) {
                status = parser.initializeUserRolesFromUserDocument(user.get(), privDoc, "admin");
                if (!status.isOK())
                    return status;
            }
            user->markProbedV1("admin");
        }

        _initializeUserPrivilegesFromRolesV1(user.get());
        acquiredUser->reset(user.release());
        return Status::OK();
    }

    Status AuthorizationManager::acquireV1UserProbedForDb(
            const UserName& userName, const StringData& dbname, User** acquiredUser) {

        CacheGuard guard(this, CacheGuard::fetchSynchronizationManual);
        unordered_map<UserName, User*>::iterator it;
        while ((_userCache.end() == (it = _userCache.find(userName))) &&
               guard.otherUpdateInFetchPhase()) {

            guard.wait();
        }

        User* user = NULL;
        if (_userCache.end() != it) {
            user = it->second;
            fassert(0, user->getSchemaVersion() == 1);
            fassert(0, user->isValid());
            if (user->hasProbedV1(dbname)) {
                user->incrementRefCount();
                *acquiredUser = user;
                return Status::OK();
            }
        }

        while (guard.otherUpdateInFetchPhase())
            guard.wait();

        guard.beginFetchPhase();

        std::auto_ptr<User> auser;
        if (!user) {
            Status status = _fetchUserV1(userName, &auser);
            if (!status.isOK())
                return status;
            user = auser.get();
        }

        BSONObj privDoc;
        Status status = _externalState->getPrivilegeDocumentV1(dbname, userName, &privDoc);
        if (status.isOK()) {
            V1UserDocumentParser parser;
            status = parser.initializeUserRolesFromUserDocument(user, privDoc, dbname);
            if (!status.isOK())
                return status;
            _initializeUserPrivilegesFromRolesV1(user);
            user->markProbedV1(dbname);
        }
        else if (status != ErrorCodes::UserNotFound) {
            return status;
        }

        user->incrementRefCount();
        // NOTE: It is not safe to throw an exception from here to the end of the method.
        *acquiredUser = user;
        auser.release();
        if (guard.isSameCacheGeneration()) {
            _userCache.insert(make_pair(userName, user));
        }
        else {
            // If the cache generation changed while this thread was in fetch mode, the data
            // associated with the user may now be invalid, so we must mark it as such.  The caller
            // may still opt to use the information for a short while, but not indefinitely.
            user->invalidate();
        }
        return Status::OK();
    }

    void AuthorizationManager::releaseUser(User* user) {
        boost::lock_guard<boost::mutex> lk(_lock);
        user->decrementRefCount();
        if (user->getRefCount() == 0) {
            _userCache.erase(user->getName());
            delete user;
        }
    }

    void AuthorizationManager::invalidateUserByName(const UserName& userName) {
        CacheGuard guard(this, CacheGuard::fetchSynchronizationManual);
        ++_cacheGeneration;
        unordered_map<UserName, User*>::iterator it = _userCache.find(userName);
        if (it == _userCache.end()) {
            return;
        }

        user->setCredentials(credentials);
        return Status::OK();
    }

    void AuthorizationManager::invalidateUsersFromDB(const std::string& dbname) {
        CacheGuard guard(this, CacheGuard::fetchSynchronizationManual);
        ++_cacheGeneration;
        unordered_map<UserName, User*>::iterator it = _userCache.begin();
        while (it != _userCache.end()) {
            User* user = it->second;
            if (user->getName().getDB() == dbname) {
                _userCache.erase(it++);
                user->invalidate();
            } else {
                user->addRole(RoleName(SYSTEM_ROLE_V0_READ_WRITE, dbname));
            }
        }
    }

    Status _initializeUserRolesFromV1PrivilegeDocument(
                User* user, const BSONObj& privDoc, const StringData& dbname) {
        static const char privilegesTypeMismatchMessage[] =
            "Roles in V1 user documents must be enumerated in an array of strings.";

        for (BSONObjIterator iter(privDoc["roles"].embeddedObject()); iter.more(); iter.next()) {
            BSONElement roleElement = *iter;
            if (roleElement.type() != String)
                return Status(ErrorCodes::TypeMismatch, privilegesTypeMismatchMessage);

            user->addRole(RoleName(roleElement.String(), dbname));
        }
        return Status::OK();
    }

    /**
     * Logs that the auth schema upgrade failed because of "status" and returns "status".
     */
    Status logUpgradeFailed(const Status& status) {
        log() << "Auth schema upgrade failed with " << status;
        return status;
    }

    void AuthorizationManager::_invalidateUserCache_inlock() {
        ++_cacheGeneration;
        for (unordered_map<UserName, User*>::iterator it = _userCache.begin();
                it != _userCache.end(); ++it) {
            if (it->second->getName() == internalSecurity.user->getName()) {
                // Don't invalidate the internal user
                continue;
            }
            it->second->invalidate();
        }
        _userCache.clear();
        // Make sure the internal user stays in the cache.
        _userCache.insert(make_pair(internalSecurity.user->getName(), internalSecurity.user));

        // If the authorization manager was running with version-1 schema data, check to
        // see if the version has updated next time we go to add data to the cache.
        if (1 == _version)
            _version = 0;
    }

    Status AuthorizationManager::initialize() {
        invalidateUserCache();
        Status status = _externalState->initialize();
        if (!status.isOK())
            return status;

        return Status::OK();
    }

    /**
     * Inserts "document" into "collection", throwing a DBException on failure.
     */
    void uassertInsertIntoCollection(
            AuthzManagerExternalState* externalState,
            const NamespaceString& collection,
            const BSONObj& document,
            const BSONObj& writeConcern) {
        uassertStatusOK(externalState->insert(collection, document, writeConcern));
    }

    /**
     * Copies the contents of "sourceCollection" into "targetCollection", which must be a distinct
     * collection.
     */
    Status copyCollectionContents(
            AuthzManagerExternalState* externalState,
            const NamespaceString& targetCollection,
            const NamespaceString& sourceCollection,
            const BSONObj& writeConcern) {
        return externalState->query(
                sourceCollection,
                BSONObj(),
                BSONObj(),
                boost::bind(uassertInsertIntoCollection,
                            externalState,
                            targetCollection,
                            _1,
                            writeConcern));
    }

    /**
     * Upgrades auth schema from schemaVersion24 to schemaVersion26Upgrade.
     *
     * Assumes that the current version is schemaVersion24.
     *
     * - Backs up usersCollectionNamespace into usersBackupCollectionNamespace.
     * - Empties usersAltCollectionNamespace.
     * - Builds usersAltCollectionNamespace from the contents of every database's system.users
     *   collection.
     * - Manipulates the schema version document appropriately.
     *
     * Upon successful completion, system is in schemaVersion26Upgrade.  On failure,
     * system is in schemaVersion24 or schemaVersion26Upgrade, but it is safe to re-run this
     * method.
     */
    Status buildNewUsersCollection(
            AuthzManagerExternalState* externalState,
            const BSONObj& writeConcern) {

        // Write an explicit schemaVersion24 into the schema version document, to facilitate
        // recovery.
        Status status = externalState->updateOne(
                AuthorizationManager::versionCollectionNamespace,
                AuthorizationManager::versionDocumentQuery,
                BSON("$set" << BSON(AuthorizationManager::schemaVersionFieldName <<
                                    AuthorizationManager::schemaVersion24)),
                true,
                writeConcern);
        if (!status.isOK())
            return logUpgradeFailed(status);

        log() << "Auth schema upgrade erasing contents of " <<
            AuthorizationManager::usersBackupCollectionNamespace;
        int numRemoved;
        status = externalState->remove(
                AuthorizationManager::usersBackupCollectionNamespace,
                BSONObj(),
                writeConcern,
                &numRemoved);
        if (!status.isOK())
            return logUpgradeFailed(status);

        log() << "Auth schema upgrade backing up " <<
            AuthorizationManager::usersCollectionNamespace << " into " <<
            AuthorizationManager::usersBackupCollectionNamespace;
        status = copyCollectionContents(
                externalState,
                AuthorizationManager::usersBackupCollectionNamespace,
                AuthorizationManager::usersCollectionNamespace,
                writeConcern);
        if (!status.isOK())
            return logUpgradeFailed(status);

        log() << "Auth schema upgrade dropping indexes from " <<
            AuthorizationManager::usersAltCollectionNamespace;
        status = externalState->dropIndexes(AuthorizationManager::usersAltCollectionNamespace,
                                            writeConcern);
        if (!status.isOK()) {
            warning() << "Auth schema upgrade failed to drop indexes on " <<
                AuthorizationManager::usersAltCollectionNamespace << " (" << status << ")";
        }

        log() << "Auth schema upgrade erasing contents of " <<
            AuthorizationManager::usersAltCollectionNamespace;
        status = externalState->remove(
                AuthorizationManager::usersAltCollectionNamespace,
                BSONObj(),
                writeConcern,
                &numRemoved);
        if (!status.isOK())
            return logUpgradeFailed(status);

        log() << "Auth schema upgrade creating needed indexes of " <<
            AuthorizationManager::usersAltCollectionNamespace;
        status = externalState->createIndex(
                AuthorizationManager::usersAltCollectionNamespace,
                BSON("user" << 1 << "db" << 1),
                true,
                writeConcern);
        if (!status.isOK())
            return logUpgradeFailed(status);

        // Update usersAltCollectionNamespace from the contents of each database's system.users
        // collection.
        std::vector<std::string> dbNames;
        status = externalState->getAllDatabaseNames(&dbNames);
        if (!status.isOK())
            return logUpgradeFailed(status);
        for (size_t i = 0; i < dbNames.size(); ++i) {
            const std::string& db = dbNames[i];
            status = upgradeUsersFromDB(externalState, db, writeConcern);
            if (!status.isOK())
                return logUpgradeFailed(status);
        }

        // Switch to schemaVersion26Upgrade.  Starting after this point, user information will be
        // read from usersAltCollectionNamespace.
        status = externalState->updateOne(
                AuthorizationManager::versionCollectionNamespace,
                AuthorizationManager::versionDocumentQuery,
                BSON("$set" << BSON(AuthorizationManager::schemaVersionFieldName <<
                                    AuthorizationManager::schemaVersion26Upgrade)),
                true,
                writeConcern);
        if (!status.isOK())
            return logUpgradeFailed(status);
        return Status::OK();
    }

    /**
     * Modifies the given User object by inspecting its roles and giving it the relevant
     * privileges from those roles.
     */
    void _initializeUserPrivilegesFromRoles(User* user) {
        std::vector<Privilege> privileges;

        RoleNameIterator it = user->getRoles();
        while (it.more()) {
            const RoleName& roleName = it.next();
            _addPrivilegesForSystemRole(roleName.getDB().toString(),
                                        roleName.getRole().toString(),
                                        &privileges);
        }
        user->addPrivileges(privileges);
    }

    Status AuthorizationManager::upgradeSchemaStep(const BSONObj& writeConcern, bool* isDone) {
        int authzVersion;
        Status status = getAuthorizationVersion(&authzVersion);
        if (!status.isOK()) {
            return status;
        }

        switch (authzVersion) {
        case schemaVersion24:
            *isDone = false;
            return buildNewUsersCollection(_externalState.get(), writeConcern);
        case schemaVersion26Upgrade: {
            Status status = overwriteSystemUsersCollection(_externalState.get(), writeConcern);
            if (status.isOK())
                *isDone = true;
            return status;
        }
        status = _initializeUserRolesFromPrivilegeDocument(user, privDoc, user->getName().getDB());
        if (!status.isOK()) {
            return status;
        }
        _initializeUserPrivilegesFromRoles(user);
        return Status::OK();
    }

    namespace {
        class AuthzUpgradeLockGuard {
            MONGO_DISALLOW_COPYING(AuthzUpgradeLockGuard);
        public:
            explicit AuthzUpgradeLockGuard(AuthzManagerExternalState* externalState)
                : _externalState(externalState), _locked(false) {
            }

            ~AuthzUpgradeLockGuard() {
                if (_locked)
                    unlock();
            }

            bool tryLock() {
                fassert(17111, !_locked);
                _locked = _externalState->tryLockUpgradeProcess();
                return _locked;
            }

            void unlock() {
                fassert(17112, _locked);
                _externalState->unlockUpgradeProcess();
                _locked = false;
            }
        private:
            AuthzManagerExternalState* _externalState;
            bool _locked;
        };

        BSONObj userAsV2PrivilegeDocument(const User& user) {
            BSONObjBuilder builder;

            const UserName& name = user.getName();
            builder.append(AuthorizationManager::USER_NAME_FIELD_NAME, name.getUser());
            builder.append(AuthorizationManager::USER_SOURCE_FIELD_NAME, name.getDB());

            const User::CredentialData& credentials = user.getCredentials();
            if (!credentials.isExternal) {
                BSONObjBuilder credentialsBuilder(builder.subobjStart("credentials"));
                credentialsBuilder.append("MONGODB-CR", credentials.password);
                credentialsBuilder.doneFast();
            }

            BSONArrayBuilder rolesArray(builder.subarrayStart("roles"));
            for (RoleNameIterator roles = user.getRoles(); roles.more(); roles.next()) {
                const RoleName& roleName = roles.get();
                BSONObjBuilder roleBuilder(rolesArray.subobjStart());
                roleBuilder.append("name", roleName.getRole());
                roleBuilder.append("source", roleName.getDB());
                roleBuilder.appendBool("canDelegate", false);
                roleBuilder.appendBool("hasRole", true);
                roleBuilder.doneFast();
            }
            rolesArray.doneFast();
            return builder.obj();
        }

        const NamespaceString newusersCollectionName("admin._newusers");
        const NamespaceString usersCollectionName("admin.system.users");
        const NamespaceString backupUsersCollectionName("admin.backup.users");
        const NamespaceString versionCollectionName("admin.system.version");
        const BSONObj versionDocumentQuery = BSON("_id" << 1);

        /**
         * Fetches the admin.system.version document and extracts the currentVersion field's
         * value, supposing it is an integer, and writes it to outVersion.
         */
        Status readAuthzVersion(AuthzManagerExternalState* externalState, int* outVersion) {
            BSONObj versionDoc;
            Status status = externalState->findOne(
                    versionCollectionName, versionDocumentQuery, &versionDoc);
            if (!status.isOK() && ErrorCodes::NoMatchingDocument != status) {
                return status;
            }
            BSONElement currentVersionElement = versionDoc["currentVersion"];
            if (!versionDoc.isEmpty() && !currentVersionElement.isNumber()) {
                return Status(ErrorCodes::TypeMismatch,
                              "Field 'currentVersion' in admin.system.version must be a number.");
            }
            *outVersion = currentVersionElement.numberInt();
            return Status::OK();
        }
    }  // namespace

    Status AuthorizationManager::upgradeAuthCollections() {
        boost::lock_guard<boost::mutex> lkLocal(_lock);
        AuthzUpgradeLockGuard lkUpgrade(_externalState.get());
        if (!lkUpgrade.tryLock()) {
            return Status(ErrorCodes::LockBusy, "Could not lock auth data upgrade process lock.");
        }
        int durableVersion;
        Status status = readAuthzVersion(_externalState.get(), &durableVersion);
        if (!status.isOK())
            return status;

        if (_version == 2) {
            switch (durableVersion) {
            case 0:
            case 1: {
                const char msg[] = "User data format version in memory and on disk inconsistent; "
                    "please restart this node.";
                error() << msg;
                return Status(ErrorCodes::UserDataInconsistent, msg);
            }
            case 2:
                return Status::OK();
            default:
                return Status(ErrorCodes::BadValue,
                              mongoutils::str::stream() <<
                              "Cannot upgrade admin.system.version to 2 from " <<
                              durableVersion);
            }
        }
        fassert(17113, _version == 1);
        switch (durableVersion) {
        case 0:
        case 1:
            break;
        case 2: {
            const char msg[] = "User data format version in memory and on disk inconsistent; "
                "please restart this node.";
            error() << msg;
            return Status(ErrorCodes::UserDataInconsistent, msg);
        }
        default:
                return Status(ErrorCodes::BadValue,
                              mongoutils::str::stream() <<
                              "Cannot upgrade admin.system.version from 2 to " <<
                              durableVersion);
        }

        // Upgrade from v1 to v2.
        status = _externalState->copyCollection(usersCollectionName, backupUsersCollectionName);
        if (!status.isOK())
            return status;
        status = _externalState->dropCollection(newusersCollectionName);
        if (!status.isOK())
            return status;
        status = _externalState->createIndex(
                newusersCollectionName,
                BSON(USER_NAME_FIELD_NAME << 1 << USER_SOURCE_FIELD_NAME << 1),
                true // unique
                );
        if (!status.isOK())
            return status;
        for (unordered_map<UserName, User*>::const_iterator iter = _userCache.begin();
             iter != _userCache.end(); ++iter) {

            // Do not create a user document for the internal user.
            if (iter->second == internalSecurity.user)
                continue;

            status = _externalState->insert(
                    newusersCollectionName, userAsV2PrivilegeDocument(*iter->second));
            if (!status.isOK())
                return status;
        }
        status = _externalState->renameCollection(newusersCollectionName, usersCollectionName);
        if (!status.isOK())
            return status;
        status = _externalState->updateOne(
                versionCollectionName,
                versionDocumentQuery,
                BSON("$set" << BSON("currentVersion" << 2)),
                true);
        if (!status.isOK())
            return status;
        _version = 2;
        return status;
    }

    static bool isAuthzNamespace(const StringData& ns) {
        return (ns == AuthorizationManager::rolesCollectionNamespace.ns() ||
                ns == AuthorizationManager::usersCollectionNamespace.ns() ||
                ns == AuthorizationManager::versionCollectionNamespace.ns());
    }

    static bool isAuthzCollection(const StringData& coll) {
        return (coll == AuthorizationManager::rolesCollectionNamespace.coll() ||
                coll == AuthorizationManager::usersCollectionNamespace.coll() ||
                coll == AuthorizationManager::versionCollectionNamespace.coll());
    }

    static bool loggedCommandOperatesOnAuthzData(const char* ns, const BSONObj& cmdObj) {
        if (ns != AuthorizationManager::adminCommandNamespace.ns())
            return false;
        const StringData cmdName(cmdObj.firstElement().fieldNameStringData());
        if (cmdName == "drop") {
            return isAuthzCollection(StringData(cmdObj.firstElement().valuestr(),
                                                cmdObj.firstElement().valuestrsize() - 1));
        }
        else if (cmdName == "dropDatabase") {
            return true;
        }
        else if (cmdName == "renameCollection") {
            return isAuthzCollection(cmdObj.firstElement().str()) ||
                isAuthzCollection(cmdObj["to"].str());
        }
        else if (cmdName == "dropIndexes") {
            return false;
        }
        else {
            return true;
        }
    }

    static bool appliesToAuthzData(
            const char* op,
            const char* ns,
            const BSONObj& o) {

        switch (*op) {
        case 'i':
        case 'u':
        case 'd':
            return isAuthzNamespace(ns);
        case 'c':
            return loggedCommandOperatesOnAuthzData(ns, o);
            break;
        case 'n':
            return false;
        default:
            return true;
        }
    }

    void AuthorizationManager::logOp(
            const char* op,
            const char* ns,
            const BSONObj& o,
            BSONObj* o2,
            bool* b) {

        _externalState->logOp(op, ns, o, o2, b);
        if (appliesToAuthzData(op, ns, o)) {
            CacheGuard guard(this, CacheGuard::fetchSynchronizationManual);
            _invalidateUserCache_inlock();
        }
    }

} // namespace mongo
