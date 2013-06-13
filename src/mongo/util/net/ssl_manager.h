 /*
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


#ifdef MONGO_SSL

#pragma once

#include <string>
#include "mongo/base/disallow_copying.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

namespace mongo {
    class SSLManagerInterface {
    public:
        explicit SSLManager(const SSLParams& params);

        /**
         * Initiates a TLS connection.
         * Throws SocketException on failure.
         * @return a pointer to an SSL context; caller must SSL_free it.
         */
        SSL* connect(int fd);

        /**
         * Waits for the other side to initiate a TLS connection.
         * Throws SocketException on failure.
         * @return a pointer to an SSL context; caller must SSL_free it.
         */
        SSL* accept(int fd);

        /**
         * Fetches a peer certificate and validates it if it exists
         * Throws SocketException on failure
         * @return a std::string containing the certificate's subject name.
         */
        virtual std::string validatePeerCertificate(const SSL* ssl) = 0;

        /**
         * Cleans up SSL thread local memory; use at thread exit
         * to avoid memory leaks
         */
        static void cleanupThreadLocals();

        /**
         * Get the subject name of our own server certificate
         * @return the subject name.
         */
        virtual std::string getSubjectName() = 0;

        /**
         * ssl.h shims
         */
        SSL* _secure(int fd);

        /**
         * Fetches the error text for an error code, in a thread-safe manner.
         */
        std::string _getSSLErrorMessage(int code);

        /**
         * Given an error code from an SSL-type IO function, logs an 
         * appropriate message and throws a SocketException
         */
        void _handleSSLError(int code);

        /** @return true if was successful, otherwise false */
        bool _setupPEM( const std::string& keyFile , const std::string& password );

        /*
         * Set up SSL for certificate validation by loading a CA
         */
        bool _setupCA(const std::string& caFile);

        /*
         * Import a certificate revocation list into our SSL context
         * for use with validating certificates
         */
        bool _setupCRL(const std::string& crlFile);

        /*
         * Activate FIPS 140-2 mode, if the server started with a command line
         * parameter.
         */
        void _setupFIPS();

        /*
         * Wrapper for SSL_Connect() that handles SSL_ERROR_WANT_READ,
         * see SERVER-7940
         */
        int _ssl_connect(SSL* ssl);

        /*
         * Initialize the SSL Library.
         * This function can be called multiple times; it ensures it only
         * does the SSL initialization once per process.
         */
        void _initializeSSL(const SSLParams& params);
    };
}
#endif
