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

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xwiki.ldapuserimport.LDAPUserImportConfiguration;

/**
 * Provider for the {@link XWikiLDAPConfig}, which will set defaults coming from the
 * {@link LDAPUserImportConfiguration}.
 *
 * @version $Id$
 * @since 1.4
 */
@Component
@Singleton
public class XWikiLDAPConfigProvider implements Provider<XWikiLDAPConfig>
{
    /**
     * The hint used by the configuration source defined by the Active Directory application.
     */
    private static final String ACTIVE_DIRECTORY_HINT = "activedirectory";

    private static final String LDAP_FIELDS_MAPPING = "ldap_fields_mapping";

    private static final String LDAP_USER_PAGE_NAME = "ldap_userPageName";

    private static final String DEFAULT_LDAP_FIELDS_MAPPING = "first_name=givenName,last_name=sn,email=mail";

    private static final String LDAP_SSL = "ldap_ssl";

    private static final String LDAP_SSL_KEYSTORE = "ldap_ssl.keystore";

    private static final String LDAP_SSL_SECURE_PROVIDER = "ldap_ssl.secure_provider";

    private static final SpaceReference AD_CODE_SPACE_REFERENCE =
        new SpaceReference("xwiki", Arrays.asList("ActiveDirectory", "Code"));

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private ConfigurationSource configurationSource;

    @Inject
    @Named("context")
    private Provider<ComponentManager> componentManagerProvider;

    @Inject
    private LDAPUserImportConfiguration ldapUserImportConfiguration;

    @Inject
    private Logger logger;

    @Override
    public XWikiLDAPConfig get()
    {
        XWikiLDAPConfig configuration = new XWikiLDAPConfig(null, getConfigurationSource());
        setPageNameFormatter(configuration);
        setFieldMapping(configuration);
        try {
            setSSLProperties(configuration);
        } catch (XWikiException e) {
            logger.warn("Could not retrieve the SSL related configuration of the Active Directory application.");
        }
        return configuration;
    }

    private void setSSLProperties(XWikiLDAPConfig configuration) throws XWikiException
    {
        DocumentReference adConfigClassRef =
            new DocumentReference("ActiveDirectoryConfigClass", AD_CODE_SPACE_REFERENCE);
        DocumentReference adConfigRef = new DocumentReference("ActiveDirectoryConfig", AD_CODE_SPACE_REFERENCE);

        XWikiContext context = this.contextProvider.get();
        XWiki xwiki = context.getWiki();
        XWikiDocument adConfigDoc = xwiki.getDocument(adConfigRef, context);
        BaseObject adConfigObj = adConfigDoc.getXObject(adConfigClassRef);
        if (adConfigObj != null) {
            configuration.setFinalProperty(LDAP_SSL, adConfigObj.getStringValue(LDAP_SSL));
            configuration.setFinalProperty(LDAP_SSL_KEYSTORE, adConfigObj.getStringValue(LDAP_SSL_KEYSTORE));

            String provider = adConfigObj.getStringValue(LDAP_SSL_SECURE_PROVIDER);
            configuration.setFinalProperty(LDAP_SSL_SECURE_PROVIDER,
                StringUtils.isNoneBlank(provider) ? provider : null);
        }
    }

    private ConfigurationSource getConfigurationSource()
    {
        if (componentManagerProvider.get().hasComponent(ConfigurationSource.class, ACTIVE_DIRECTORY_HINT)) {
            try {
                return componentManagerProvider.get().getInstance(ConfigurationSource.class, ACTIVE_DIRECTORY_HINT);
            } catch (ComponentLookupException e) {
                logger.error("Failed to get [{}] configuration source. Using the default LDAP configuration source",
                    ACTIVE_DIRECTORY_HINT, e);
            }
        }
        return configurationSource;
    }

    private void setPageNameFormatter(XWikiLDAPConfig configuration)
    {
        String pageNameFormatter = ldapUserImportConfiguration.getUserPageNameFormatter();
        if (StringUtils.isNoneBlank(pageNameFormatter)) {
            configuration.setFinalProperty(LDAP_USER_PAGE_NAME, pageNameFormatter);
        }
    }

    private void setFieldMapping(XWikiLDAPConfig configuration)
    {
        if (StringUtils.isBlank(configuration.getLDAPParam(LDAP_FIELDS_MAPPING, null))) {
            configuration.setFinalProperty(LDAP_FIELDS_MAPPING, DEFAULT_LDAP_FIELDS_MAPPING);
        }
    }
}
