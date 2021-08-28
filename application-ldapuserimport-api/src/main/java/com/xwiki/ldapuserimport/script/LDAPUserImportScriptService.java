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
package com.xwiki.ldapuserimport.script;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.script.service.ScriptService;
import com.xwiki.ldapuserimport.LDAPUserImportManager;

/**
 * @version $Id$
 * @since 1.0
 */
@Component
@Named("ldapuserimport")
@Singleton
public class LDAPUserImportScriptService implements ScriptService
{
    @Inject
    private LDAPUserImportManager manager;

    /**
     * Get all the users that have the searched value contained in any of the provided fields value.
     *
     * @param singleField the field to only filter when the single field search is enabled
     * @param allFields the list of all configured fields
     * @param searchInput the value to search for
     * @return a map containing all the matching users with information from all fields
     */
    public Map<String, Map<String, String>> getUsers(String singleField, String allFields, String searchInput)
    {
        if (hasImport()) {
            return manager.getUsers(singleField, allFields, searchInput);
        }
        return Collections.emptyMap();
    }

    /**
     * Import the selected users.
     *
     * @param usersList the list of users to be imported
     * @param groupName the group to add users in
     * @return a map of imported user profiles and URLs
     */
    public Map<String, Map<String, String>> importUsers(String[] usersList, String groupName)
    {
        if (hasImport()) {
            return manager.importUsers(usersList, groupName);
        }
        return Collections.emptyMap();
    }

    /**
     * Check if the current user is allowed to import users.
     *
     * @return true if has import right, false otherwise
     */
    public boolean hasImport()
    {
        return manager.hasImport();
    }

    /**
     * Check if the list of displayed users reached the top limit represented by the resultsNumber in the configuration.
     * Compare the size of displayed list with the top limit.
     *
     * @param displayedUsersNb the number of users displayed in the import wizard
     * @return true if the list of displayed users reached the top limit, false otherwise
     */
    public boolean displayedMax(int displayedUsersNb)
    {
        return manager.displayedMax(displayedUsersNb);
    }

    /**
     * Get a list of all the XWiki groups that are included in the LDAP groups mapping.
     *
     * @return a list of XWiki groups
     */
    public List<String> getXWikiMappedGroups()
    {
        return manager.getXWikiMappedGroups();
    }

    /**
     * Get the number of LDAP users that will be created or updated in the current XWiki group.
     *
     * @param xWikiGroupName the group name
     * @return the number of users to be synchronized from a group
     */
    public int getGroupMemberSize(String xWikiGroupName)
    {
        return manager.getGroupMemberSize(xWikiGroupName);
    }

    /**
     * Create or update users from LDAP in the current XWiki group.
     *
     * @param xWikiGroupName the group name
     * @return true if the update was successful, false otherwise
     */
    public boolean updateGroup(String xWikiGroupName)
    {
        if (hasImport()) {
            return manager.updateGroup(xWikiGroupName);
        }
        return false;
    }

    /**
     * Create or update users from LDAP in all the XWiki groups that are included in the groups mapping.
     */
    public void updateGroups()
    {
        manager.updateGroups();
    }

    /**
     * Get all the LDAP groups from a domain. Each group contains information about the relation with the current XWiki
     * group (associated or not).
     *
     * @param searchInput the value to search for
     * @param xWikiGroupName the group name
     * @return the list of groups
     */
    public Map<String, Map<String, String>> getLDAPGroups(String searchInput, String xWikiGroupName)
    {
        return manager.getLDAPGroups(searchInput, xWikiGroupName);
    }

    /**
     * Associate a list of LDAP groups to an XWiki group.
     *
     * @param ldapGroupsList the list of LDAP Groups to be assigned
     * @param xWikiGroupName the group name
     * @return true if the groups association succeeded, false otherwise
     */
    public boolean associateGroups(String[] ldapGroupsList, String xWikiGroupName)
    {
        if (hasImport()) {
            return manager.associateGroups(ldapGroupsList, xWikiGroupName);
        }
        return false;
    }
}
