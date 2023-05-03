/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.xwiki.ldapuserimport;

import java.util.List;

import org.xwiki.component.annotation.Role;
import org.xwiki.stability.Unstable;

/**
 * Configuration for the LDAP User Import application.
 *
 * @version $Id$
 * @since 1.4
 */
@Role
@Unstable
public interface LDAPUserImportConfiguration
{
    /**
     * Define who is allowed to import LDAP users in the wiki.
     */
    enum UserImportPolicy
    {
        /**
         * Only allow global administrators.
         */
        GLOBAL_ADMINS,

        /**
         * Allow both global and local wiki administrators to import users.
         */
        GLOBAL_AND_LOCAL_ADMINS,

        /**
         * Allow anyone able to edit a group to import users.
         */
        GROUP_EDITORS
    }

    /**
     * @return the list of LDAP user attributes
     */
    List<String> getLDAPUserAttributes();

    /**
     * @return {@code true} if the user search should be performed on a single LDAP field in the UI
     */
    boolean getEnableSingleFieldSearch();

    /**
     * @return true if a OIDC Object should be added to new user profiles upon import
     * @see #getOIDCIssuer()
     */
    boolean getAddOIDCObject();

    /**
     * @return the OIDC issuer to be provided when an OIDC Object should be added to new user profiles upon import
     * @see #getAddOIDCObject()
     */
    String getOIDCIssuer();

    /**
     * @return the user import policy
     */
    UserImportPolicy getUserImportPolicy();

    /**
     * @return the format to be used for new user page names
     */
    String getUserPageNameFormatter();

    /**
     * @return the maximum number of users to be displayed in the import wizard
     */
    int getMaxUserImportWizardResults();

    /**
     * @return true if groups should be updated on synchronization
     */
    boolean getTriggerGroupUpdate();

    /**
     * @return true if user group membership should be updated upon synchronization
     */
    boolean getForceUserGroupMembershipUpdate();

    /**
     * @return the base DN under which LDAP groups to be imported should be searched
     */
    String getLDAPGroupImportSearchDN();

    /**
     * @return the filter to be used when searching for groups to import
     */
    String getLDAPGroupImportSearchFilter();

    /**
     * @return the page name that should be used for LDAP groups
     */
    String getGroupPageName();

    /**
     * @return true if LDAP groups should be automatically imported in XWiki
     */
    boolean getTriggerGroupImport();
}
