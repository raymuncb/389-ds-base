/** BEGIN COPYRIGHT BLOCK
 *  * Copyright (C) 2016 Red Hat, Inc.
 *   * All rights reserved.
 *    *
 *     * License: GPL (version 3 or any later version).
 *      * See LICENSE for details.
 *       * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/*
 *  * slapd hashed password routines
 *   *
 *    */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "crypt_blowfish.h"

#include "pwdstorage.h"

#include <pk11pub.h>

/* Need this for htonl and ntohl */
#include <arpa/inet.h>

/* Always generate 'b' type hashes for new passwords to match
 * OpenBSD 5.5+ behaviour.
 * See first http://www.openwall.com/lists/announce/2011/07/17/1 and then
 * http://www.openwall.com/lists/announce/2014/08/31/1
 */
#define BCRYPT_DEFAULT_PREFIX		"$2b"

/* Default work factor as currently used by the OpenBSD project for normal
 * accounts. Only used when no work factor is supplied in the slapd.conf
 * when loading the module. See README for more information.
 */
#define BCRYPT_DEFAULT_WORKFACTOR        8
#define BCRYPT_MIN_WORKFACTOR            4
#define BCRYPT_MAX_WORKFACTOR           32

#define BCRYPT_SALT_SIZE                16
#define BCRYPT_OUTPUT_SIZE              61

static const char *schemeName = BCRYPT_SCHEME_NAME;


int bcrypt_pw_cmp(const char *userpwd, const char *dbpwd){
    slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName,"Entering chk_bcrypt\n");
    char computedhash[BCRYPT_OUTPUT_SIZE];
    int rc;

    if (userpwd == NULL) {
        slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName,"Error: Stored hash is NULL\n");
        return -1;
    }

    slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName,"Supplied hash: \"%s\"\n", (char *)dbpwd);

    /*if (passwd > BCRYPT_OUTPUT_SIZE) {
        _DEBUG("Error: Stored hash is too large. Size = %d\n",
               (int) passwd->bv_len);
        return -1;
    }*/

    slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName,"Hashing provided credentials: \"%s\"\n", (char *) userpwd);
    /* No need to base64 decode, as crypt_blowfish already does that */
    if (_crypt_blowfish_rn( (char *) userpwd,
                            (char *) dbpwd,
                            computedhash,
                            BCRYPT_OUTPUT_SIZE) == NULL) {
        slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName,"Error: _crypt_blowfish_rn returned NULL\n");
        return -1;
    }
    slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName,"Resulting hash: \"%s\"\n", computedhash);

    slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName,"Comparing newly created hash with supplied hash: ");
    rc = strcmp(computedhash,dbpwd);
    slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName,"strcmp result: %i",rc);
    if(rc == 0)
        slapi_log_error(SLAPI_LOG_PLUGIN, (char *) schemeName, "passwords match");
    else
        slapi_log_error(SLAPI_LOG_PLUGIN, (char *) schemeName, "passwords doesn't match");
    return rc;
}

char *bcrypt_pw_enc(const char *pwd){
    char bcrypthash[BCRYPT_OUTPUT_SIZE];
    char saltinput[BCRYPT_SALT_SIZE];
    char settingstring[sizeof(BCRYPT_DEFAULT_PREFIX) + 1 + BCRYPT_SALT_SIZE + 1];
    char * enc;

    struct berval salt;
    struct berval digest;
    static int bcrypt_workfactor = 10;

    salt.bv_val = saltinput;
    salt.bv_len = sizeof(saltinput);

    if (_crypt_gensalt_blowfish_rn(BCRYPT_DEFAULT_PREFIX,
                                   bcrypt_workfactor,
                                   saltinput,
                                   BCRYPT_SALT_SIZE,
                                   settingstring,
                                   BCRYPT_OUTPUT_SIZE) == NULL) {
        slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName,"Error: _crypt_gensalt_blowfish_rn returned NULL\n");
    }

    slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName, "Hashing password \"%s\" with settingstring \"%s\"\n",
           pwd, settingstring);
    if (_crypt_blowfish_rn( pwd,
                            settingstring,
                            bcrypthash,
                            BCRYPT_OUTPUT_SIZE) == NULL)
       slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName,"ERROR: BCRYPT failed");

    slapi_log_error(SLAPI_LOG_PLUGIN,(char*) schemeName,"bcrypt hash created: \"%s\"\n", bcrypthash);

    enc = slapi_ch_smprintf("%c%s%c%s", PWD_HASH_PREFIX_START, (char *)schemeName,
                            PWD_HASH_PREFIX_END, bcrypthash );
    if (!pwd)
        return NULL;
    slapi_log_error(SLAPI_LOG_PLUGIN, (char *)schemeName, "In bcrypt_pw_enc final hash %s \n", enc);
    //enc = slapi_ch_strdup( pwd );
    return enc;
}
