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

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.contrib.ldap.PagedLDAPSearchResults;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.contrib.ldap.XWikiLDAPConnection;
import org.xwiki.contrib.ldap.XWikiLDAPException;
import org.xwiki.contrib.ldap.XWikiLDAPUtils;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.LocalDocumentReference;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.web.Utils;
import com.xwiki.ldapuserimport.LDAPUserImportManager;

/**
 * @version $Id$
 * @since 2.6
 */
@Component
@Singleton
public class DefaultLDAPUserImportManager implements LDAPUserImportManager, Initializable
{
    private static final String XWIKI = "XWiki";

    private static final String LDAP_UID_ATTR = "ldap_UID_attr";

    private static final String LDAP_BASE_DN = "ldap_base_DN";

    private static final String CN = "cn";

    private static final String FAILED_TO_GET_RESULTS = "Failed to get results";

    private static final LocalDocumentReference GROUP_CLASS_REFERENCE =
        new LocalDocumentReference(XWIKI, "XWikiGroups");

    private ConfigurationSource configurationSource = Utils.getComponent(ConfigurationSource.class, "ldapuserimport");

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    private Logger logger;

    @Inject
    private Provider<XWikiContext> contextProvider;

    private String uuidFieldName;

    private XWikiLDAPConfig configuration;

    /**
     * Get all the users that have the searched value contained in any of the provided fields value.
     */
    @Override
    public Map<String, Map<String, String>> getUsers(String singleField, String allFields, String searchInput)
    {
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
        String loginDN = configuration.getLDAPBindDN();
        String password = configuration.getLDAPBindPassword();

        try {
            connection.open(loginDN, password, contextProvider.get());
            String base = configuration.getLDAPParam(LDAP_BASE_DN, "");

            String tempAllFields;
            if (StringUtils.isNoneBlank(allFields)) {
                tempAllFields = allFields;
            } else {
                tempAllFields = uuidFieldName + ",givenName,mail,name,sn";
            }

            String[] allFieldsList = tempAllFields.split(",");

            StringBuilder filter;
            if (StringUtils.isNoneBlank(singleField)) {
                filter = getFilter(searchInput, new String[] {singleField});
            } else {
                filter = getFilter(searchInput, allFieldsList);
            }

            PagedLDAPSearchResults result =
                connection.searchPaginated(base, LDAPConnection.SCOPE_SUB, filter.toString(), allFieldsList, false);
            if (result.hasMore()) {
                return getUsers(allFieldsList, result);
            } else {
                logger.warn("There are no result for base dn: [{}], search scope: [{}], filter: [{}], fields: [{}]",
                    base, LDAPConnection.SCOPE_SUB, filter.toString(), tempAllFields);
                return null;
            }
        } catch (XWikiLDAPException e) {
            logger.error(e.getFullMessage());
        } catch (LDAPException e) {
            logger.warn("Failed to search for value [{}] in the fields [{}]", searchInput, allFields, e);
        } finally {
            connection.close();
        }
        return null;
    }

    /**
     * Filter pattern: (&({0}={1})(|({2}=*{3}*)({4}=*{5}*)({6}=*{7}*)...)).
     */
    private StringBuilder getFilter(String searchInput, String[] fieldsList)
    {
        String escapedSearchInput = XWikiLDAPConnection.escapeLDAPSearchFilter(searchInput);
        StringBuilder filter = new StringBuilder("(&");
        filter.append("(objectClass=*)(|");
        for (String filed : fieldsList) {
            filter.append("(");
            filter.append(XWikiLDAPConnection.escapeLDAPSearchFilter(filed));
            filter.append("=*");
            filter.append(escapedSearchInput);
            filter.append("*)");
        }
        filter.append("))");
        return filter;
    }

    private Map<String, Map<String, String>> getUsers(String[] fieldsList, PagedLDAPSearchResults result)
    {
        SortedMap<String, Map<String, String>> users = new TreeMap<>();
        LDAPEntry resultEntry = null;
        try {
            resultEntry = result.next();
            if (resultEntry != null) {
                do {
                    String uuidFieldValue = getAttributeValue(uuidFieldName, resultEntry);
                    Map<String, String> user = new HashMap<>();
                    for (String field : fieldsList) {
                        user.put(field, getAttributeValue(field, resultEntry));
                    }
                    user.put("exists", checkUser(uuidFieldValue));
                    users.put(uuidFieldValue, user);
                    resultEntry = result.hasMore() ? result.next() : null;
                } while (resultEntry != null && users.size() <= 20);
            } else {
                /*
                 * For some weird reason result.hasMore() can be true before the first call to next() even if nothing is
                 * found.
                 */
                logger.warn("The LDAP request returned no result (hasMore() is true but first next() call "
                    + "returned nothing)");
            }
        } catch (LDAPException e) {
            logger.warn(FAILED_TO_GET_RESULTS, e);
        }
        return users;
    }

    private String checkUser(String uidFieldValue)
    {
        XWikiContext xcontext = contextProvider.get();
        XWiki xwiki = xcontext.getWiki();
        // Apply a cleaning rule close to the one in platform.
        // TODO: Find the EXACT formula for this cleaning.
        DocumentReference userReference = new DocumentReference(xcontext.getMainXWiki(), XWIKI, uidFieldValue);
        return Boolean.toString(xwiki.exists(userReference, xcontext));
    }

    private String getAttributeValue(String fieldName, LDAPEntry resultEntry)
    {
        String value = "-";
        if (resultEntry.getAttribute(fieldName) != null) {
            value = resultEntry.getAttribute(fieldName).getStringValue();
        }
        return value;
    }

    @Override
    public void initialize() throws InitializationException
    {
        configuration = new XWikiLDAPConfig(null, this.configurationSource);
        uuidFieldName = configuration.getLDAPParam(LDAP_UID_ATTR, CN);
    }

    @Override
    public Map<String, String> importUsers(String[] usersList, String groupName)
    {
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
        XWikiLDAPUtils ldapUtils = new XWikiLDAPUtils(connection, configuration);
        String loginDN = configuration.getLDAPBindDN();
        String password = configuration.getLDAPBindPassword();
        try {
            connection.open(loginDN, password, contextProvider.get());

            SortedMap<String, String> users = new TreeMap<>();

            for (String user : usersList) {
                try {
                    // Make sure to create users in the main wiki.
                    XWikiContext mainContext = contextProvider.get().clone();
                    mainContext.setWikiId(mainContext.getMainXWiki());
                    XWikiDocument userDoc = ldapUtils.getUserProfileByUid(user, user, mainContext);
                    ldapUtils.syncUser(userDoc, null, loginDN, user, mainContext);
                    users.put(userDoc.getDocumentReference().toString(), userDoc.getURL("view", mainContext));
                } catch (XWikiException e) {
                    logger.warn("Failed to create user [{}] ", user, e);
                }
            }

            if (StringUtils.isNoneBlank(groupName)) {
                addUsersInGroup(groupName, users);
            }

            return users;
        } catch (XWikiException e) {
            logger.error(e.getFullMessage());
        } finally {
            connection.close();
        }
        return null;
    }

    private void addUsersInGroup(String groupName, Map<String, String> users) throws XWikiException
    {
        XWikiContext context = contextProvider.get();
        XWiki xwiki = context.getWiki();
        DocumentReference groupReference = documentReferenceResolver.resolve(groupName);
        XWikiDocument groupDocument = xwiki.getDocument(groupReference, context);
        for (Entry<String, String> user : users.entrySet()) {
            BaseObject memberObject = groupDocument.newXObject(GROUP_CLASS_REFERENCE, context);
            memberObject.setStringValue("member", user.getKey());
            xwiki.saveDocument(groupDocument, context);
        }
    }
}
