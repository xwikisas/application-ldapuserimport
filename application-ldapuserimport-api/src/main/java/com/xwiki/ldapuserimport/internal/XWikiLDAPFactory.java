package com.xwiki.ldapuserimport.internal;

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

import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.ldap.LDAPProfileXClass;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.contrib.ldap.XWikiLDAPConnection;
import org.xwiki.contrib.ldap.XWikiLDAPUtils;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;

import static com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper.CN;
import static com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper.LDAP_BASE_DN;

/**
 * Helper class for building XWikiLdapConnection and XWikiLdapUtils classes.
 *
 * @version $Id$
 * @since 1.7.7
 */
@Singleton
@Component(roles = XWikiLDAPFactory.class)
public class XWikiLDAPFactory
{
    /**
     * @param config the xwiki ldap configuration that should be used for instantiating a new connection.
     * @return a new XWikiLDAPConnection.
     */
    public XWikiLDAPConnection getLDAPConnection(XWikiLDAPConfig config)
    {
        return new XWikiLDAPConnection(config);
    }

    /**
     * @param connection the XWikiLdapConnection that will be passed to the ldap utils instance.
     * @param config the configuration that will be used to initialize the utils instance.
     * @return an instance of the XWikiLDAPUtils.
     */
    public XWikiLDAPUtils getLDAPUtils(XWikiLDAPConnection connection, XWikiLDAPConfig config)
    {
        XWikiLDAPUtils utils = new XWikiLDAPUtils(connection, config);
        utils.setUidAttributeName(config.getLDAPParam(XWikiLDAPConfig.PREF_LDAP_UID, CN));
        utils.setBaseDN(config.getLDAPParam(LDAP_BASE_DN, ""));
        return utils;
    }

    /**
     * @param context the current XWiki context.
     * @return an instance of the {@link LDAPProfileXClass} that helps with operations on the xwiki ldap object.
     * @throws XWikiException if there was an issue when constructing the object.
     */
    public LDAPProfileXClass getLDAPProfileXClass(XWikiContext context) throws XWikiException
    {
        return new LDAPProfileXClass(context);
    }
}
