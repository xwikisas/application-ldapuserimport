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
package com.xwiki.ldapuserimport.job;

import java.util.List;

import org.xwiki.job.AbstractRequest;
import org.xwiki.stability.Unstable;

/**
 * Request for the LDAP Group Import Job.
 *
 * @version $Id$
 * @since 1.4
 */
@Unstable
public class LDAPGroupImportRequest extends AbstractRequest
{
    private static final String PROP_LDAP_GROUP_SEARCH_DN = "ldapGroupSearchDN";

    private static final String PROP_LDAP_GROUP_SEARCH_FILTER = "ldapGroupSearchFilter";

    private static final String PROP_LDAP_GROUP_SEARCH_ATTRIBUTES = "ldapGroupSearchAttributes";

    private static final String PROP_GROUP_PAGE_NAME_FORMAT = "groupPageNameFormat";

    /**
     * @return the DN under which LDAP groups should be searched
     */
    public String getLDAPGroupSearchDN()
    {
        return getProperty(PROP_LDAP_GROUP_SEARCH_DN);
    }

    /**
     * @param ldapGroupSearchDN the DN under which LDAP groups should be searched
     */
    public void setLDAPGroupSearchDN(String ldapGroupSearchDN)
    {
        setProperty(PROP_LDAP_GROUP_SEARCH_DN, ldapGroupSearchDN);
    }

    /**
     * @return the search filter to be used when importing LDAP groups
     */
    public String getLDAPGroupSearchFilter()
    {
        return getProperty(PROP_LDAP_GROUP_SEARCH_FILTER);
    }

    /**
     * @param ldapGroupSearchFilter the search filter to be used when importing LDAP groups
     */
    public void setLDAPGroupSearchFilter(String ldapGroupSearchFilter)
    {
        setProperty(PROP_LDAP_GROUP_SEARCH_FILTER, ldapGroupSearchFilter);
    }

    /**
     * @return the attributes to be used when importing LDAP groups
     */
    public List<String> getLDAPGroupSearchAttributes()
    {
        return getProperty(PROP_LDAP_GROUP_SEARCH_ATTRIBUTES);
    }

    /**
     * @param ldapGroupSearchAttributes the attributes to be fetched when searching groups
     */
    public void setLDAPGroupSearchAttributes(List<String> ldapGroupSearchAttributes)
    {
        setProperty(PROP_LDAP_GROUP_SEARCH_ATTRIBUTES, ldapGroupSearchAttributes);
    }

    /**
     * @return the page name for imported groups
     */
    public String getGroupPageName()
    {
        return getProperty(PROP_GROUP_PAGE_NAME_FORMAT);
    }

    /**
     * @param groupPageName the page name for imported groups
     */
    public void setGroupPageNameFormat(String groupPageName)
    {
        setProperty(PROP_GROUP_PAGE_NAME_FORMAT, groupPageName);
    }
}
