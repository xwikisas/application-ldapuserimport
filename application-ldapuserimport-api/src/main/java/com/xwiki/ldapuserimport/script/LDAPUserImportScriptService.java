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
        return null;
    }

    /**
     * Import the selected users.
     * 
     * @param usersList the list of users to be imported
     * @param groupName the group to add users in
     * @param addOIDCObj whether to add or not the OIDC object in user profile
     * @return a map of imported user profiles and URLs
     */
    public Map<String, String> importUsers(String[] usersList, String groupName, boolean addOIDCObj)
    {
        if (hasImport()) {
            return manager.importUsers(usersList, groupName, addOIDCObj);
        }
        return null;
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
}
