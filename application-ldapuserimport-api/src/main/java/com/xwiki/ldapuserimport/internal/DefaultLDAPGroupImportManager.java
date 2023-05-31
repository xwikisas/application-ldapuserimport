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
package com.xwiki.ldapuserimport.internal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.contrib.ldap.XWikiLDAPConnection;
import org.xwiki.contrib.ldap.XWikiLDAPException;
import org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute;
import org.xwiki.job.JobException;
import org.xwiki.job.JobExecutor;

import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;
import com.xpn.xwiki.XWikiContext;
import com.xwiki.ldapuserimport.LDAPGroupImportManager;
import com.xwiki.ldapuserimport.LDAPUserImportConfiguration;
import com.xwiki.ldapuserimport.job.AbstractLDAPGroupImportJob;
import com.xwiki.ldapuserimport.job.LDAPGroupImportRequest;

import static com.novell.ldap.LDAPConnection.SCOPE_SUB;
import static com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper.getGroupsFilter;

/**
 * Default implementation of {@link LDAPGroupImportManager}.
 *
 * @version $Id$
 * @since 1.4
 */
@Component
@Singleton
public class DefaultLDAPGroupImportManager implements LDAPGroupImportManager
{
    @Inject
    private LDAPUserImportConfiguration ldapUserImportConfiguration;

    @Inject
    private JobExecutor jobExecutor;

    @Inject
    private Logger logger;

    @Inject
    private Provider<XWikiLDAPConfig> xWikiLDAPConfigProvider;

    @Inject
    private Provider<XWikiContext> xWikiContextProvider;

    @Override
    public Map<String, List<XWikiLDAPSearchAttribute>> getImportableGroups(String groupSearchDN,
        String groupSearchFilter, List<String> groupSearchAttributes)
    {
        XWikiContext context = xWikiContextProvider.get();
        XWikiLDAPConfig configuration = xWikiLDAPConfigProvider.get();
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
        Map<String, List<XWikiLDAPSearchAttribute>> results = new HashMap<>();

        try {
            connection.open(configuration.getLDAPBindDN(), configuration.getLDAPBindPassword(), context);

            String[] attributes = groupSearchAttributes.toArray(new String[0]);
            LDAPSearchResults ldapSearchResults = connection.search(groupSearchDN, groupSearchFilter, attributes,
                SCOPE_SUB);
            while (ldapSearchResults.hasMore()) {
                LDAPEntry entry = ldapSearchResults.next();

                List<XWikiLDAPSearchAttribute> attributeList = new ArrayList<>();
                connection.ldapToXWikiAttribute(attributeList, entry.getAttributeSet());
                results.put(entry.getDN(), attributeList);
            }
        } catch (XWikiLDAPException | LDAPException e) {
            logger.warn("Failed to get a list of importable LDAP groups using base DN [{}] and filter [{}]."
                    + "Root cause is: [{}].", groupSearchDN, groupSearchFilter, ExceptionUtils.getRootCauseMessage(e));
        } finally {
            connection.close();
        }

        return results;
    }

    @Override
    public AbstractLDAPGroupImportJob importLDAPGroups(String groupPageNameFormat, String groupSearchDN,
        String groupSearchFilter, List<String> groupSearchAttributes) throws JobException
    {
        LDAPGroupImportRequest request = new LDAPGroupImportRequest();
        request.setLDAPGroupSearchDN(groupSearchDN);
        request.setLDAPGroupSearchFilter(groupSearchFilter);
        request.setLDAPGroupSearchAttributes(groupSearchAttributes);
        request.setGroupPageNameFormat(groupPageNameFormat);

        return (AbstractLDAPGroupImportJob) jobExecutor.execute(AbstractLDAPGroupImportJob.JOB_TYPE, request);
    }

    @Override
    public AbstractLDAPGroupImportJob importLDAPGroups() throws JobException
    {
        String groupSearchFilter = StringUtils.isBlank(ldapUserImportConfiguration.getLDAPGroupImportSearchFilter())
            ? getGroupsFilter(StringUtils.EMPTY, xWikiLDAPConfigProvider.get())
            : ldapUserImportConfiguration.getLDAPGroupImportSearchFilter();
        return importLDAPGroups(ldapUserImportConfiguration.getGroupPageNameFormat(),
            ldapUserImportConfiguration.getLDAPGroupImportSearchDN(), groupSearchFilter,
            ldapUserImportConfiguration.getLDAPGroupImportSearchAttributes());
    }
}
