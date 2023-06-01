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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xwiki.ldapuserimport.LDAPUserImportConfiguration;

/**
 * Default implementation of the {@link LDAPUserImportConfiguration}.
 *
 * @version $Id$
 * @since 1.4
 */
@Component
@Singleton
public class DefaultLDAPUserImportConfiguration implements LDAPUserImportConfiguration, Initializable
{
    private static final String LDAP_USER_IMPORT = "LDAPUserImport";

    private static final LocalDocumentReference CONFIGURATION_CLASS_REFERENCE =
        new LocalDocumentReference(LDAP_USER_IMPORT, "LDAPUserImportConfigClass");

    private static final int DEFAULT_MAX_USER_IMPORT_WIZARD_RESULTS = 20;

    private static final List<String> DEFAULT_LDAP_GROUP_SEARCH_ATTRIBUTES =
        Collections.singletonList(XWikiLDAPUtilsHelper.CN);

    private static final String DEFAULT_GROUP_PAGE_NAME = "${uid}Group";

    private DocumentReference configurationReference;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private Logger logger;

    @Inject
    private WikiDescriptorManager wikiDescriptorManager;

    @Override
    public void initialize()
    {
        configurationReference =
            new DocumentReference(wikiDescriptorManager.getMainWikiId(), LDAP_USER_IMPORT, "WebHome");
    }

    @Override
    public List<String> getLDAPUserAttributes()
    {
        BaseObject object = getObject();
        return object != null
            ? Arrays.asList(object.getStringValue("ldapUserAttributes").split(XWikiLDAPConfig.DEFAULT_SEPARATOR))
            : Collections.EMPTY_LIST;
    }

    @Override
    public boolean getEnableSingleFieldSearch()
    {
        BaseObject object = getObject();
        return object != null && object.getIntValue("enableSingleFieldSearch") == 1;
    }

    @Override
    public boolean getAddOIDCObject()
    {
        BaseObject object = getObject();
        return object != null && object.getIntValue("addOIDCObject") == 1;
    }

    @Override
    public String getOIDCIssuer()
    {
        BaseObject object = getObject();
        return (object != null) ? object.getStringValue("OIDCIssuer") : StringUtils.EMPTY;
    }

    @Override
    public UserImportPolicy getUserImportPolicy()
    {
        BaseObject object = getObject();

        if (object != null) {
            String value = object.getStringValue("usersAllowedToImport");

            if ("localAdmin".equals(value)) {
                return UserImportPolicy.GLOBAL_AND_LOCAL_ADMINS;
            } else if ("groupEditor".equals(value)) {
                return UserImportPolicy.GROUP_EDITORS;
            }
        }

        return UserImportPolicy.GLOBAL_ADMINS;
    }

    @Override
    public String getUserPageNameFormatter()
    {
        BaseObject object = getObject();
        return (object != null) ? object.getStringValue("pageNameFormatter") : StringUtils.EMPTY;
    }

    @Override
    public int getMaxUserImportWizardResults()
    {
        BaseObject object = getObject();
        return (object != null) ? object.getIntValue("resultsNumber", DEFAULT_MAX_USER_IMPORT_WIZARD_RESULTS)
            : DEFAULT_MAX_USER_IMPORT_WIZARD_RESULTS;
    }

    @Override
    public boolean getTriggerGroupUpdate()
    {
        BaseObject object = getObject();
        return object != null && object.getIntValue("triggerGroupsUpdate") == 1;
    }

    @Override
    public boolean getForceUserGroupMembershipUpdate()
    {
        BaseObject object = getObject();
        return object != null && object.getIntValue("forceXWikiUsersGroupMembershipUpdate") == 1;
    }

    @Override
    public String getLDAPGroupImportSearchDN()
    {
        BaseObject object = getObject();
        return object != null ? object.getStringValue("ldapGroupImportSearchDN") : StringUtils.EMPTY;
    }

    @Override
    public String getLDAPGroupImportSearchFilter()
    {
        BaseObject object = getObject();
        return object != null ? object.getStringValue("ldapGroupImportSearchFilter") : StringUtils.EMPTY;
    }

    @Override
    public List<String> getLDAPGroupImportSearchAttributes()
    {
        BaseObject object = getObject();
        if (object != null) {
            String ldapGroupSearchAttributes = object.getStringValue("ldapGroupImportSearchAttributes");
            if (StringUtils.isNotBlank(ldapGroupSearchAttributes)) {
                return Arrays.asList(ldapGroupSearchAttributes.split(XWikiLDAPConfig.DEFAULT_SEPARATOR));
            }
        }

        return DEFAULT_LDAP_GROUP_SEARCH_ATTRIBUTES;
    }

    @Override
    public String getGroupPageNameFormat()
    {
        BaseObject object = getObject();
        if (object != null) {
            String pageName = object.getStringValue("groupPageNameFormat");
            if (StringUtils.isNotBlank(pageName)) {
                return pageName;
            }
        }

        return DEFAULT_GROUP_PAGE_NAME;
    }

    @Override
    public boolean getTriggerGroupImport()
    {
        BaseObject object = getObject();
        return object != null && object.getIntValue("triggerGroupImport") == 1;
    }

    private BaseObject getObject()
    {
        XWikiContext context = contextProvider.get();
        XWikiDocument importConfigDoc;
        try {
            importConfigDoc = context.getWiki().getDocument(configurationReference, context);
            return importConfigDoc.getXObject(CONFIGURATION_CLASS_REFERENCE);
        } catch (XWikiException e) {
            logger.warn("Failed to get the LDAP Import configuration document [{}].", configurationReference, e);
        }

        return null;
    }
}
