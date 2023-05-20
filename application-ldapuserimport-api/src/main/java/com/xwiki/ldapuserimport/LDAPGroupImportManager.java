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
import org.xwiki.job.JobException;
import org.xwiki.stability.Unstable;

import com.xwiki.ldapuserimport.job.AbstractLDAPGroupImportJob;

/**
 * Manager for importing LDAP groups.
 *
 * @version $Id$
 * @since 1.4
 */
@Role
@Unstable
public interface LDAPGroupImportManager
{
    /**
     * Get a list of every LDAP group from the configured LDAP server that qualify for import.
     *
     * @param groupSearchDN the base DN under which groups should be searched
     * @param groupSearchFilter the filter to use when searching groups
     * @return every LDAP group that exist in the configured LDAP directory.
     */
    List<String> getImportableGroups(String groupSearchDN, String groupSearchFilter);

    /**
     * Start a job to import the LDAP groups.
     *
     * @param groupSearchDN the base search DN
     * @param groupPageName the format of group pages
     * @param groupSearchFilter the filter to search groups
     * @return the LDAP group import job
     * @throws JobException if an error occurs starting the import job
     */
    AbstractLDAPGroupImportJob importLDAPGroups(String groupPageName, String groupSearchDN, String groupSearchFilter)
        throws JobException;

    /**
     * Start a job to import the LDAP groups, using the group search DN, group search filter and group page name
     * defined in the application configuration.
     *
     * @return the LDAP group import job
     * @throws JobException if an error occurs starting the import job
     */
    AbstractLDAPGroupImportJob importLDAPGroups() throws JobException;
}