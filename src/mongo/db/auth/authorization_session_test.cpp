/*    Copyright 2012 10gen Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 * Unit tests of the AuthorizationSession type.
 */

#include "mongo/base/status.h"
#include "mongo/db/auth/authz_session_external_state_mock.h"
#include "mongo/db/auth/authz_manager_external_state_mock.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/auth/authorization_session.h"
#include "mongo/db/jsobj.h"
#include "mongo/db/namespacestring.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/map_util.h"

#define ASSERT_NULL(EXPR) ASSERT_FALSE(EXPR)
#define ASSERT_NON_NULL(EXPR) ASSERT_TRUE(EXPR)

namespace mongo {
namespace {

    TEST(AuthorizationSessionTest, AcquirePrivilegeAndCheckAuthorization) {
        Principal* principal = new Principal(UserName("Spencer", "test"));
        ActionSet actions;
        actions.addAction(ActionType::insert);
        Privilege writePrivilege("test", actions);
        Privilege allDBsWritePrivilege("*", actions);
        AuthzManagerExternalStateMock* managerExternalState = new AuthzManagerExternalStateMock();
        AuthorizationManager authManager(managerExternalState);
        AuthzSessionExternalStateMock* sessionExternalState = new AuthzSessionExternalStateMock(
                &authManager);
        AuthorizationSession authzSession(sessionExternalState);

        ASSERT_FALSE(authzSession.checkAuthorization("test", ActionType::insert));
        sessionExternalState->setReturnValueForShouldIgnoreAuthChecks(true);
        ASSERT_TRUE(authzSession.checkAuthorization("test", ActionType::insert));
        sessionExternalState->setReturnValueForShouldIgnoreAuthChecks(false);
        ASSERT_FALSE(authzSession.checkAuthorization("test", ActionType::insert));

        ASSERT_EQUALS(ErrorCodes::UserNotFound,
                      authzSession.acquirePrivilege(writePrivilege, principal->getName()));
        authzSession.addAuthorizedPrincipal(principal);
        ASSERT_OK(authzSession.acquirePrivilege(writePrivilege, principal->getName()));
        ASSERT_TRUE(authzSession.checkAuthorization("test", ActionType::insert));

        ASSERT_FALSE(authzSession.checkAuthorization("otherDb", ActionType::insert));
        ASSERT_OK(authzSession.acquirePrivilege(allDBsWritePrivilege, principal->getName()));
        ASSERT_TRUE(authzSession.checkAuthorization("otherDb", ActionType::insert));
        // Auth checks on a collection should be applied to the database name.
        ASSERT_TRUE(authzSession.checkAuthorization("otherDb.collectionName", ActionType::insert));

        authzSession.logoutDatabase("test");
        ASSERT_FALSE(authzSession.checkAuthorization("test", ActionType::insert));
    }

    class AuthManagerExternalStateImplictPriv : public AuthzManagerExternalStateMock {
    public:
        AuthManagerExternalStateImplictPriv() : AuthzManagerExternalStateMock() {}

        virtual bool _findUser(const string& usersNamespace,
                               const BSONObj& query,
                               BSONObj* result) const {

        virtual Status _findUser(const std::string& usersNamespace,
                                 const BSONObj& query,
                                 BSONObj* result) {
            if (_findsShouldFail) {
                return Status(ErrorCodes::UnknownError, "_findUser set to fail in mock.");
            }
            else {
                userSource = query[AuthorizationManager::USER_SOURCE_FIELD_NAME].String();
            }
            *result = mapFindWithDefault(_privilegeDocs,
                                         std::make_pair(dbstr,
                                                        UserName(user, userSource)),
                                                        BSON("invalid" << 1));
            return  !(*result)["invalid"].trueValue();
        }

        void addPrivilegeDocument(const string& dbname,
                                  const UserName& user,
                                  const BSONObj& doc) {

            ASSERT(_privilegeDocs.insert(std::make_pair(std::make_pair(dbname, user),
                                                        doc.getOwned())).second);
        }

    private:
        std::map<std::pair<std::string, UserName>, BSONObj > _privilegeDocs;
    };

    class AuthSessionExternalStateImplictPriv : public AuthzSessionExternalStateMock {
    public:
        AuthSessionExternalStateImplictPriv(AuthorizationManager* authzManager,
                                            AuthManagerExternalStateImplictPriv* managerExternal) :
            AuthzSessionExternalStateMock(authzManager),
            _authManagerExternalState(managerExternal) {}

        void addPrivilegeDocument(const string& dbname,
                                  const UserName& user,
                                  const BSONObj& doc) {
            _authManagerExternalState->addPrivilegeDocument(dbname, user, doc);
        }

    private:
        AuthManagerExternalStateImplictPriv* _authManagerExternalState;
    };

    class ImplicitPriviligesTest : public ::mongo::unittest::Test {
    public:
        AuthManagerExternalStateImplictPriv* managerState;
        AuthSessionExternalStateImplictPriv* sessionState;
        scoped_ptr<AuthorizationSession> authzSession;
        scoped_ptr<AuthorizationManager> authzManager;

        void setUp() {
            managerState = new FailureCapableAuthzManagerExternalStateMock();
            managerState->setAuthzVersion(2);
            authzManager.reset(new AuthorizationManager(managerState));
            sessionState = new AuthSessionExternalStateImplictPriv(authzManager.get(),
                                                                   managerState);
            authzSession.reset(new AuthorizationSession(sessionState));
        }
    };

    const ResourcePattern testDBResource(ResourcePattern::forDatabaseName("test"));
    const ResourcePattern otherDBResource(ResourcePattern::forDatabaseName("other"));
    const ResourcePattern adminDBResource(ResourcePattern::forDatabaseName("admin"));
    const ResourcePattern testFooCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("test.foo")));
    const ResourcePattern otherFooCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("other.foo")));
    const ResourcePattern thirdFooCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("third.foo")));
    const ResourcePattern adminFooCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("admin.foo")));
    const ResourcePattern testUsersCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("test.system.users")));
    const ResourcePattern otherUsersCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("other.system.users")));
    const ResourcePattern thirdUsersCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("third.system.users")));
    const ResourcePattern testIndexesCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("test.system.indexes")));
    const ResourcePattern otherIndexesCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("other.system.indexes")));
    const ResourcePattern thirdIndexesCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("third.system.indexes")));
    const ResourcePattern testProfileCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("test.system.profile")));
    const ResourcePattern otherProfileCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("other.system.profile")));
    const ResourcePattern thirdProfileCollResource(
            ResourcePattern::forExactNamespace(NamespaceString("third.system.profile")));

    TEST_F(AuthorizationSessionTest, AddUserAndCheckAuthorization) {
        // Check that disabling auth checks works
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testFooCollResource, ActionType::insert));
        sessionState->setReturnValueForShouldIgnoreAuthChecks(true);
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                             testFooCollResource, ActionType::insert));
        sessionState->setReturnValueForShouldIgnoreAuthChecks(false);
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testFooCollResource, ActionType::insert));

        // Check that you can't authorize a user that doesn't exist.
        ASSERT_EQUALS(ErrorCodes::UserNotFound,
                      authzSession->addAndAuthorizeUser(UserName("spencer", "test")));

        // Add a user with readWrite and dbAdmin on the test DB
        ASSERT_OK(managerState->insertPrivilegeDocument("admin",
                BSON("user" << "spencer" <<
                     "db" << "test" <<
                     "credentials" << BSON("MONGODB-CR" << "a") <<
                     "roles" << BSON_ARRAY(BSON("role" << "readWrite" <<
                                                "db" << "test" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false) <<
                                           BSON("role" << "dbAdmin" <<
                                                "db" << "test" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false))),
                BSONObj()));
        ASSERT_OK(authzSession->addAndAuthorizeUser(UserName("spencer", "test")));

        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::insert));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testDBResource, ActionType::dbStats));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherFooCollResource, ActionType::insert));

        // Add an admin user with readWriteAnyDatabase
        ASSERT_OK(managerState->insertPrivilegeDocument("admin",
                BSON("user" << "admin" <<
                     "db" << "admin" <<
                     "credentials" << BSON("MONGODB-CR" << "a") <<
                     "roles" << BSON_ARRAY(BSON("role" << "readWriteAnyDatabase" <<
                                                "db" << "admin" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false))),
                BSONObj()));
        ASSERT_OK(authzSession->addAndAuthorizeUser(UserName("admin", "admin")));

        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            ResourcePattern::forExactNamespace(
                                    NamespaceString("anydb.somecollection")),
                            ActionType::insert));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            otherDBResource, ActionType::insert));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            otherFooCollResource, ActionType::insert));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherFooCollResource, ActionType::collMod));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::insert));

        authzSession->logoutDatabase("test");
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            otherFooCollResource, ActionType::insert));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::insert));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testFooCollResource, ActionType::collMod));

        authzSession->logoutDatabase("admin");
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherFooCollResource, ActionType::insert));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testFooCollResource, ActionType::insert));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testFooCollResource, ActionType::collMod));
    }

    TEST_F(AuthorizationSessionTest, SystemCollectionsAccessControl) {
        ASSERT_OK(managerState->insertPrivilegeDocument("admin",
                BSON("user" << "rw" <<
                     "db" << "test" <<
                     "credentials" << BSON("MONGODB-CR" << "a") <<
                     "roles" << BSON_ARRAY(BSON("role" << "readWrite" <<
                                                "db" << "test" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false) <<
                                           BSON("role" << "dbAdmin" <<
                                                "db" << "test" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false))),
                BSONObj()));
        ASSERT_OK(managerState->insertPrivilegeDocument("admin",
                BSON("user" << "useradmin" <<
                     "db" << "test" <<
                     "credentials" << BSON("MONGODB-CR" << "a") <<
                     "roles" << BSON_ARRAY(BSON("role" << "userAdmin" <<
                                                "db" << "test" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false))),
                BSONObj()));
        ASSERT_OK(managerState->insertPrivilegeDocument("admin",
                BSON("user" << "rwany" <<
                     "db" << "test" <<
                     "credentials" << BSON("MONGODB-CR" << "a") <<
                     "roles" << BSON_ARRAY(BSON("role" << "readWriteAnyDatabase" <<
                                                "db" << "admin" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false) <<
                                           BSON("role" << "dbAdminAnyDatabase" <<
                                                "db" << "admin" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false))),
                BSONObj()));
        ASSERT_OK(managerState->insertPrivilegeDocument("admin",
                BSON("user" << "useradminany" <<
                     "db" << "test" <<
                     "credentials" << BSON("MONGODB-CR" << "a") <<
                     "roles" << BSON_ARRAY(BSON("role" << "userAdminAnyDatabase" <<
                                                "db" << "admin" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false))),
                BSONObj()));

        ASSERT_OK(authzSession->addAndAuthorizeUser(UserName("rwany", "test")));

        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testUsersCollResource, ActionType::insert));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testUsersCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherUsersCollResource, ActionType::insert));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherUsersCollResource, ActionType::find));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                             testIndexesCollResource, ActionType::find));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                             testProfileCollResource, ActionType::find));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                             otherIndexesCollResource, ActionType::find));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                             otherProfileCollResource, ActionType::find));

        // Logging in as useradminany@test implicitly logs out rwany@test.
        ASSERT_OK(authzSession->addAndAuthorizeUser(UserName("useradminany", "test")));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testUsersCollResource, ActionType::insert));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                             testUsersCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherUsersCollResource, ActionType::insert));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                             otherUsersCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testIndexesCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testProfileCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherIndexesCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherProfileCollResource, ActionType::find));

        // Logging in as rw@test implicitly logs out useradminany@test.
        ASSERT_OK(authzSession->addAndAuthorizeUser(UserName("rw", "test")));

        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testUsersCollResource, ActionType::insert));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testUsersCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherUsersCollResource, ActionType::insert));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherUsersCollResource, ActionType::find));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                             testIndexesCollResource, ActionType::find));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                             testProfileCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherIndexesCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherProfileCollResource, ActionType::find));


        // Logging in as useradmin@test implicitly logs out rw@test.
        ASSERT_OK(authzSession->addAndAuthorizeUser(UserName("useradmin", "test")));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testUsersCollResource, ActionType::insert));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testUsersCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherUsersCollResource, ActionType::insert));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherUsersCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testIndexesCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             testProfileCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherIndexesCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                             otherProfileCollResource, ActionType::find));
    }

    TEST_F(AuthorizationSessionTest, InvalidateUser) {
        // Add a readWrite user
        ASSERT_OK(managerState->insertPrivilegeDocument("admin",
                BSON("user" << "spencer" <<
                     "db" << "test" <<
                     "credentials" << BSON("MONGODB-CR" << "a") <<
                     "roles" << BSON_ARRAY(BSON("role" << "readWrite" <<
                                                "db" << "test" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false))),
                BSONObj()));
        ASSERT_OK(authzSession->addAndAuthorizeUser(UserName("spencer", "test")));

        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::find));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::insert));

        User* user = authzSession->lookupUser(UserName("spencer", "test"));
        ASSERT(user->isValid());

        // Change the user to be read-only
        managerState->clearPrivilegeDocuments();
        ASSERT_OK(managerState->insertPrivilegeDocument("admin",
                BSON("user" << "spencer" <<
                     "db" << "test" <<
                     "credentials" << BSON("MONGODB-CR" << "a") <<
                     "roles" << BSON_ARRAY(BSON("role" << "read" <<
                                                "db" << "test" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false))),
                BSONObj()));

        // Make sure that invalidating the user causes the session to reload its privileges.
        authzManager->invalidateUserByName(user->getName());
        authzSession->startRequest(); // Refreshes cached data for invalid users
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::insert));

        user = authzSession->lookupUser(UserName("spencer", "test"));
        ASSERT(user->isValid());

        // Delete the user.
        managerState->clearPrivilegeDocuments();
        // Make sure that invalidating the user causes the session to reload its privileges.
        authzManager->invalidateUserByName(user->getName());
        authzSession->startRequest(); // Refreshes cached data for invalid users
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::insert));
        ASSERT_FALSE(authzSession->lookupUser(UserName("spencer", "test")));
    }

    TEST_F(AuthorizationSessionTest, UseOldUserInfoInFaceOfConnectivityProblems) {
        // Add a readWrite user
        ASSERT_OK(managerState->insertPrivilegeDocument("admin",
                BSON("user" << "spencer" <<
                     "db" << "test" <<
                     "credentials" << BSON("MONGODB-CR" << "a") <<
                     "roles" << BSON_ARRAY(BSON("role" << "readWrite" <<
                                                "db" << "test" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false))),
                BSONObj()));
        ASSERT_OK(authzSession->addAndAuthorizeUser(UserName("spencer", "test")));

        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::find));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::insert));

        User* user = authzSession->lookupUser(UserName("spencer", "test"));
        ASSERT(user->isValid());

        // Change the user to be read-only
        managerState->setFindsShouldFail(true);
        managerState->clearPrivilegeDocuments();
        ASSERT_OK(managerState->insertPrivilegeDocument("admin",
                BSON("user" << "spencer" <<
                     "db" << "test" <<
                     "credentials" << BSON("MONGODB-CR" << "a") <<
                     "roles" << BSON_ARRAY(BSON("role" << "read" <<
                                                "db" << "test" <<
                                                "hasRole" << true <<
                                                "canDelegate" << false))),
                BSONObj()));

        // Even though the user's privileges have been reduced, since we've configured user
        // document lookup to fail, the authz session should continue to use its known out-of-date
        // privilege data.
        authzManager->invalidateUserByName(user->getName());
        authzSession->startRequest(); // Refreshes cached data for invalid users
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::find));
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::insert));

        // Once we configure document lookup to succeed again, authorization checks should
        // observe the new values.
        managerState->setFindsShouldFail(false);
        authzSession->startRequest(); // Refreshes cached data for invalid users
        ASSERT_TRUE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::find));
        ASSERT_FALSE(authzSession->isAuthorizedForActionsOnResource(
                            testFooCollResource, ActionType::insert));
    }


    TEST_F(AuthorizationSessionTest, ImplicitAcquireFromSomeDatabasesWithV1Users) {
        return;
        managerState->setAuthzVersion(1);

        managerState->insert(NamespaceString("test.system.users"),
                                    BSON("user" << "andy" <<
                                         "pwd" << "a" <<
                                         "roles" << BSON_ARRAY("readWrite")));
        sessionState->addPrivilegeDocument("test2", UserName("andy", "test"),
                                    BSON("user" << "andy" <<
                                         "userSource" << "test" <<
                                         "roles" <<  BSON_ARRAY("read")));
        sessionState->addPrivilegeDocument("admin", UserName("andy", "test"),
                                    BSON("user" << "andy" <<
                                         "userSource" << "test" <<
                                         "roles" << BSON_ARRAY("clusterAdmin") <<
                                         "otherDBRoles" << BSON("third" << BSON_ARRAY("dbAdmin"))),
                                    BSONObj());
        ASSERT_OK(authzManager->initialize());

        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       testFooCollResource, ActionType::find));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       testFooCollResource, ActionType::insert));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       testFooCollResource, ActionType::collMod));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       otherFooCollResource, ActionType::find));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       otherFooCollResource, ActionType::insert));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       otherFooCollResource, ActionType::collMod));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       thirdFooCollResource, ActionType::find));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       thirdFooCollResource, ActionType::insert));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       thirdFooCollResource, ActionType::collMod));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       adminFooCollResource, ActionType::find));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       adminFooCollResource, ActionType::insert));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       adminFooCollResource, ActionType::collMod));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       ResourcePattern::forClusterResource(), ActionType::shutdown));

        ASSERT_OK(authzSession->addAndAuthorizeUser(UserName("andy", "test")));

        User* user = authzSession->lookupUser(UserName("andy", "test"));
        ASSERT(UserName("andy", "test") == user->getName());

        ASSERT(authzSession->isAuthorizedForActionsOnResource(
                       testFooCollResource, ActionType::find));
        ASSERT(authzSession->isAuthorizedForActionsOnResource(
                       testFooCollResource, ActionType::insert));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       testFooCollResource, ActionType::collMod));
        ASSERT(authzSession->isAuthorizedForActionsOnResource(
                       otherFooCollResource, ActionType::find));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       otherFooCollResource, ActionType::insert));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       otherFooCollResource, ActionType::collMod));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       thirdFooCollResource, ActionType::find));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       thirdFooCollResource, ActionType::insert));
        ASSERT(authzSession->isAuthorizedForActionsOnResource(
                       thirdFooCollResource, ActionType::collMod));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       adminFooCollResource, ActionType::find));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       adminFooCollResource, ActionType::insert));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       adminFooCollResource, ActionType::collMod));
        ASSERT(authzSession->isAuthorizedForActionsOnResource(
                       ResourcePattern::forClusterResource(), ActionType::shutdown));

        authzSession->logoutDatabase("test");

        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       testFooCollResource, ActionType::find));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       testFooCollResource, ActionType::insert));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       testFooCollResource, ActionType::collMod));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       otherFooCollResource, ActionType::find));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       otherFooCollResource, ActionType::insert));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       otherFooCollResource, ActionType::collMod));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       thirdFooCollResource, ActionType::find));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       thirdFooCollResource, ActionType::insert));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       thirdFooCollResource, ActionType::collMod));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       adminFooCollResource, ActionType::find));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       adminFooCollResource, ActionType::insert));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       adminFooCollResource, ActionType::collMod));
        ASSERT(!authzSession->isAuthorizedForActionsOnResource(
                       ResourcePattern::forClusterResource(), ActionType::shutdown));
    }

}  // namespace
}  // namespace mongo
