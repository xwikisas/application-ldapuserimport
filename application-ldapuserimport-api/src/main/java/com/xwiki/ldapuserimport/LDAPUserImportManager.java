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
import java.util.Map;

import org.xwiki.component.annotation.Role;

/**
 * @version $Id$
 * @since 1.0
 */
@Role
public interface LDAPUserImportManager
{
    /**
     * Get all the users that have the searched value contained in any of the provided fields value.
     *
     * @param singleField the field to only filter when the single field search is enabled
     * @param allFields the list of all configured fields
     * @param searchInput the value to search for
     * @param isFullSearch allowing to choose if the search is a "contains" search or a "begin with" search
     * @return a map containing all the matching users with information from all fields
     * @throws Exception in case of exceptions
     */
    Map<String, Map<String, String>> getUsers(String singleField, String allFields,
        String searchInput, boolean isFullSearch)
        throws Exception;

    /**
     * Import the selected users.
     *
     * @param usersList the list of users to be imported
     * @param groupName the group to add users in
     * @return a map of imported user profiles and URLs
     * @throws Exception in case of exceptions
     */
    Map<String, Map<String, String>> importUsers(String[] usersList, String groupName) throws Exception;

    /**
     * Check if the current user is allowed to import users.
     *
     * @return true if has import right, false otherwise
     * @throws Exception in case of exceptions
     */
    boolean hasImport() throws Exception;

    /**
     * Check if the list of displayed users reached the top limit represented by the resultsNumber in the configuration.
     * Compare the size of displayed list with the top limit.
     *
     * @param displayedUsersNb the number of users displayed in the import wizard
     * @return true if the list of displayed users reached the top limit, false otherwise
     * @throws Exception in case of exceptions
     */
    boolean displayedMax(int displayedUsersNb) throws Exception;

    /**
     * Get a list of all the XWiki groups that are included in the LDAP groups mapping.
     *
     * @return a list of XWiki groups
     * @throws Exception in case of exceptions
     */
    List<String> getXWikiMappedGroups() throws Exception;

    /**
     * Get the number of LDAP users that will be created or updated in the current XWiki group.
     *
     * @param xWikiGroupName the group name
     * @return the number of users to be synchronized from a group
     * @throws Exception in case of exceptions
     */
    int getGroupMemberSize(String xWikiGroupName) throws Exception;

    /**
     * Create or update users from LDAP in the current XWiki group.
     *
     * @param xWikiGroupName the group name
     * @return true if the update was successful, false otherwise
     * @throws Exception in case of exceptions
     */
    boolean updateGroup(String xWikiGroupName) throws Exception;

    /**
     * Create or update users from LDAP in all the XWiki groups that are included in the groups mapping.
     *
     * @throws Exception in case of exceptions
     */
    void updateGroups() throws Exception;

    /**
     * Get all the LDAP groups from a domain. Each group contains information about the relation with the current XWiki
     * group (associated or not).
     *
     * @param searchInput the value to search for
     * @param xWikiGroupName the group name
     * @return the list of groups
     * @param isFullSearch allowing to choose if the search is a "contains" search or a "begin with" search
     * @throws Exception in case of exceptions
     */
    Map<String, Map<String, String>> getLDAPGroups(String searchInput, String xWikiGroupName,
        boolean isFullSearch) throws Exception;

    /**
     * Get all the LDAP Organizational Units from a domain. Each group contains information about the relation with the
     * current XWiki  group (associated or not).
     *
     * @param searchInput the value to search for
     * @param xWikiGroupName the group name
     * @param isFullSearch allowing to choose if the search is a "contains" search or a "begin with" search
     * @param isOUSearch denotes whether the search is done over LDAP groups or organizational units
     * @return the list of organizational units
     * @throws Exception in case of exceptions
     */
    Map<String, Map<String, String>> getLDAPGroups(String searchInput, String xWikiGroupName,
        boolean isFullSearch, boolean isOUSearch) throws Exception;

    /**
     * Associate a list of LDAP groups to an XWiki group.
     *
     * @param ldapGroupsList the list of LDAP Groups to be assigned
     * @param xWikiGroupName the group name
     * @return true if the groups association succeeded, false otherwise
     * @throws Exception in case of exceptions
     */
    boolean associateGroups(String[] ldapGroupsList, String xWikiGroupName) throws Exception;
}
