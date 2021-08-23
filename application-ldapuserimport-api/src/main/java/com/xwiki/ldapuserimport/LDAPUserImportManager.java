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
     * @return a map containing all the matching users with information from all fields
     */

    Map<String, Map<String, String>> getUsers(String singleField, String allFields, String searchInput);

    /**
     * Import the selected users.
     * 
     * @param usersList the list of users to be imported
     * @param groupName the group to add users in
     * @return a map of imported user profiles and URLs
     */
    Map<String, Map<String, String>> importUsers(String[] usersList, String groupName);

    /**
     * Check if the current user is allowed to import users.
     * 
     * @return true if has import right, false otherwise
     */
    boolean hasImport();

    /**
     * Check if the list of displayed users reached the top limit represented by the resultsNumber in the configuration.
     * Compare the size of displayed list with the top limit.
     *
     * @param displayedUsersNb the number of users displayed in the import wizard
     * @return true if the list of displayed users reached the top limit, false otherwise
     */
    boolean displayedMax(int displayedUsersNb);

    /**
     * Get a list of all the XWiki groups that are included in the groups mapping.
     *
     * @return a list of XWiki groups
     */
    List<String> getXWikiMappedGroups();

    /**
     * @param xWikiGroupName the group name
     * @return the number of users to be synchronized from a group
     */
    int getGroupMemberSize(String xWikiGroupName);

    /**
     * @param xWikiGroupName the group name
     * @return true if the update was successful, false otherwise
     */
    boolean updateGroup(String xWikiGroupName);
}
