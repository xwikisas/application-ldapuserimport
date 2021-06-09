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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

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
import org.xwiki.contrib.ldap.PagedLDAPSearchResults;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.contrib.ldap.XWikiLDAPConnection;
import org.xwiki.contrib.ldap.XWikiLDAPException;
import org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute;
import org.xwiki.contrib.ldap.XWikiLDAPUtils;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xwiki.ldapuserimport.LDAPUserImportManager;

/**
 * @version $Id$
 * @since 2.6
 */
@Component
@Singleton
public class DefaultLDAPUserImportManager implements LDAPUserImportManager
{
    private static final String LDAP_FIELDS_MAPPING = "ldap_fields_mapping";

    private static final String UID = "uid";

    private static final String USER_PROFILE_KEY = "userProfile";

    private static final String USER_PROFILE_URL_KEY = "userProfileURL";

    private static final String EQUAL_STRING = "=";

    private static final String MAIN_WIKI_NAME = "xwiki";

    private static final String LDAP_USER_IMPORT = "LDAPUserImport";

    private static final String FIELDS_SEPARATOR = ",";

    private static final String XWIKI = "XWiki";

    private static final DocumentReference GLOBAL_PREFERENCES =
        new DocumentReference(MAIN_WIKI_NAME, XWIKI, "XWikiPreferences");

    private static final String LDAP_UID_ATTR = "ldap_UID_attr";

    private static final String LDAP_BASE_DN = "ldap_base_DN";

    private static final String CN = "cn";

    private static final String FAILED_TO_GET_RESULTS = "Failed to get results";

    private static final DocumentReference OIDC_CLASS =
        new DocumentReference(MAIN_WIKI_NAME, Arrays.asList(XWIKI, "OIDC"), "UserClass");

    private static final LocalDocumentReference GROUP_CLASS_REFERENCE =
        new LocalDocumentReference(XWIKI, "XWikiGroups");

    private static final LocalDocumentReference CONFIGURATION_REFERENCE =
        new LocalDocumentReference(LDAP_USER_IMPORT, "WebHome");

    private static final LocalDocumentReference CONFIGURATION_CLASS_REFERENCE =
        new LocalDocumentReference(LDAP_USER_IMPORT, "LDAPUserImportConfigClass");

    @Inject
    private ConfigurationSource configurationSource;

    @Inject
    @Named("context")
    private Provider<ComponentManager> componentManagerProvider;

    @Inject
    private ContextualAuthorizationManager contextualAuthorizationManager;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    private Logger logger;

    @Inject
    private Provider<XWikiContext> contextProvider;

    /**
     * Get all the users that have the searched value contained in any of the provided fields value.
     */
    @Override
    public Map<String, Map<String, String>> getUsers(String singleField, String allFields, String searchInput)
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());

        XWikiLDAPConfig configuration = getConfiguration();
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
        String loginDN = configuration.getLDAPBindDN();
        String password = configuration.getLDAPBindPassword();

        try {
            connection.open(loginDN, password, context);
            String base = configuration.getLDAPParam(LDAP_BASE_DN, "");

            String[] attributeNameTable = getAttributeNameTable(configuration);

            StringBuilder filter;
            if (StringUtils.isNoneBlank(singleField)) {
                filter = getFilter(searchInput, singleField);
            } else if (StringUtils.isNoneBlank(allFields)) {
                filter = getFilter(searchInput, allFields);
            } else {
                filter = getFilter(searchInput, String.join(FIELDS_SEPARATOR, attributeNameTable));
            }

            PagedLDAPSearchResults result = connection.searchPaginated(base, LDAPConnection.SCOPE_SUB,
                filter.toString(), attributeNameTable, false);
            if (result.hasMore()) {
                return getUsers(configuration, connection, result, context);
            } else {
                logger.warn("There are no result for base dn: [{}], search scope: [{}], filter: [{}], fields: [{}]",
                    base, LDAPConnection.SCOPE_SUB, filter.toString(), attributeNameTable);
                return null;
            }
        } catch (XWikiLDAPException e) {
            logger.error(e.getFullMessage());
        } catch (LDAPException e) {
            logger.warn("Failed to search for value [{}] in the fields [{}]", searchInput, allFields, e);
        } finally {
            connection.close();
            context.setWikiId(currentWikiId);
        }
        return null;
    }

    private XWikiLDAPConfig getConfiguration()
    {
        XWikiLDAPConfig configuration = new XWikiLDAPConfig(null, getConfigurationSource());
        setPageNameFormatter(configuration);
        if (StringUtils.isBlank(configuration.getLDAPParam(LDAP_FIELDS_MAPPING, null))) {
            configuration.setFinalProperty(LDAP_FIELDS_MAPPING, "first_name=givenName,last_name=sn,email=mail");
        }
        return configuration;
    }

    private Map<String, String> getFieldsMap(XWikiLDAPConfig configuration)
    {
        Map<String, String> fieldsMap = new HashMap<>();

        String uidFieldName = configuration.getLDAPParam(LDAP_UID_ATTR, CN);
        fieldsMap.put(uidFieldName, UID);
        for (String pair : configuration.getLDAPParam(LDAP_FIELDS_MAPPING, null).split(FIELDS_SEPARATOR)) {
            String[] parts = pair.split(EQUAL_STRING);
            // From first_name=givenName, store key=givenName and value=first_name.
            fieldsMap.put(parts[1], parts[0]);
        }
        return fieldsMap;
    }

    private String[] getAttributeNameTable(XWikiLDAPConfig configuration)
    {
        Set<String> attributesNameTable = new HashSet<>();

        // Make sure to add the UID field, to get its value in the PagedLDAPSearchResult.
        String uidFieldName = configuration.getLDAPParam(LDAP_UID_ATTR, CN);
        attributesNameTable.add(uidFieldName);

        // Make sure to also add all the mapped fields, to get their values in the PagedLDAPSearchResult.
        for (String pair : configuration.getLDAPParam(LDAP_FIELDS_MAPPING, null).split(FIELDS_SEPARATOR)) {
            String[] parts = pair.split(EQUAL_STRING);
            // From first_name=givenName, store key=givenName and value=first_name.
            attributesNameTable.add(parts[1]);
        }
        return attributesNameTable.toArray(new String[attributesNameTable.size()]);
    }

    /**
     * Filter pattern: (&({0}={1})(|({2}=*{3}*)({4}=*{5}*)({6}=*{7}*)...)).
     */
    private StringBuilder getFilter(String searchInput, String searchFields)
    {
        String escapedSearchInput = XWikiLDAPConnection.escapeLDAPSearchFilter(searchInput);
        StringBuilder filter = new StringBuilder("(&");
        filter.append("(objectClass=*)(|");
        for (String filed : Arrays.asList(searchFields.split(FIELDS_SEPARATOR))) {
            filter.append("(");
            filter.append(XWikiLDAPConnection.escapeLDAPSearchFilter(filed));
            filter.append("=*");
            filter.append(escapedSearchInput);
            filter.append("*)");
        }
        filter.append("))");
        return filter;
    }

    private Map<String, Map<String, String>> getUsers(XWikiLDAPConfig configuration, XWikiLDAPConnection connection,
        PagedLDAPSearchResults result, XWikiContext context)
    {
        XWikiLDAPUtils ldapUtils = new XWikiLDAPUtils(connection, configuration);
        String uidFieldName = configuration.getLDAPParam(LDAP_UID_ATTR, CN);
        ldapUtils.setUidAttributeName(uidFieldName);
        ldapUtils.setBaseDN(configuration.getLDAPParam(LDAP_BASE_DN, ""));
        SortedMap<String, Map<String, String>> allUsersMap = new TreeMap<>();
        LDAPEntry resultEntry = null;

        try {
            resultEntry = result.next();
            if (resultEntry != null) {
                do {
                    Map<String, String> user =
                        getUserDetails(connection, configuration, ldapUtils, context, uidFieldName, resultEntry);
                    if (user != null) {
                        allUsersMap.put(user.get(UID), user);
                    }
                    resultEntry = result.hasMore() ? result.next() : null;
                } while (resultEntry != null);
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
        int resultsNumber = getLDAPImportConfiguration().getIntValue("resultsNumber");
        if (resultsNumber == 0) {
            resultsNumber = 20;
        }
        SortedMap<String, Map<String, String>> limitedUsersMap = new TreeMap<>();
        for (String userId : allUsersMap.keySet()) {
            if (limitedUsersMap.size() < resultsNumber) {
                limitedUsersMap.put(userId, allUsersMap.get(userId));
            }
        }

        return limitedUsersMap;
    }

    private Map<String, String> getUserDetails(XWikiLDAPConnection connection, XWikiLDAPConfig configuration,
        XWikiLDAPUtils ldapUtils, XWikiContext context, String uidFieldName, LDAPEntry resultEntry)
    {
        String uidFieldValue = getAttributeValue(uidFieldName, resultEntry);
        if (StringUtils.isNoneBlank(uidFieldValue)) {
            List<XWikiLDAPSearchAttribute> searchAttributeList = new ArrayList<>();
            connection.ldapToXWikiAttribute(searchAttributeList, resultEntry.getAttributeSet());
            String userPageName = ldapUtils.getUserPageName(searchAttributeList, context);
            DocumentReference userReference = new DocumentReference(MAIN_WIKI_NAME, XWIKI, userPageName);
            return getUserDetails(configuration, searchAttributeList, userReference, context);
        }
        return null;
    }

    private Map<String, String> getUserDetails(XWikiLDAPConfig configuration, List<XWikiLDAPSearchAttribute> attributes,
        DocumentReference userReference, XWikiContext context)
    {
        Map<String, String> user = new HashMap<>();
        boolean userExists = context.getWiki().exists(userReference, context);
        if (userExists) {
            user.put(USER_PROFILE_URL_KEY, context.getWiki().getURL(userReference, context));
        }
        user.put(USER_PROFILE_KEY, userReference.toString());
        user.put("username", userReference.getName());
        user.put("exists", Boolean.toString(userExists));

        Map<String, String> fieldsMap = getFieldsMap(configuration);

        for (XWikiLDAPSearchAttribute attribute : attributes) {
            String value = attribute.value;
            String name = attribute.name;
            if (fieldsMap.containsKey(name)) {
                user.put(fieldsMap.get(name), value);
            } else {
                user.put(name, value);
            }
        }
        return user;
    }

    private String getAttributeValue(String fieldName, LDAPEntry resultEntry)
    {
        String value = "";
        if (resultEntry.getAttribute(fieldName) != null) {
            value = resultEntry.getAttribute(fieldName).getStringValue();
        }
        return value;
    }

    @Override
    public SortedMap<String, Map<String, String>> importUsers(String[] usersList, String groupName, boolean addOIDCObj)
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());

        XWikiLDAPConfig configuration = getConfiguration();
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
        XWikiLDAPUtils ldapUtils = new XWikiLDAPUtils(connection, configuration);
        ldapUtils.setUidAttributeName(configuration.getLDAPParam(LDAP_UID_ATTR, CN));
        ldapUtils.setBaseDN(configuration.getLDAPParam(LDAP_BASE_DN, ""));

        try {
            connection.open(configuration.getLDAPBindDN(), configuration.getLDAPBindPassword(), context);

            SortedMap<String, Map<String, String>> users = new TreeMap<>();

            boolean oIDCClassExists = context.getWiki().exists(OIDC_CLASS, context);
            String[] attributeNameTable = getAttributeNameTable(configuration);
            for (String user : usersList) {
                List<XWikiLDAPSearchAttribute> attributes =
                    ldapUtils.searchUserAttributesByUid(user, attributeNameTable);
                XWikiDocument userDoc =
                    ldapUtils.syncUser(null, attributes, ldapUtils.searchUserDNByUid(user), user, context);

                // Make sure to get the latest version of the document, after LDAP synchronization.
                userDoc = context.getWiki().getDocument(userDoc.getDocumentReference(), context);
                if (addOIDCObj && oIDCClassExists) {
                    addOIDCObject(userDoc, user, context);
                }

                Map<String, String> userMap =
                    getUserDetails(configuration, attributes, userDoc.getDocumentReference(), context);

                users.put(user, userMap);
            }

            if (StringUtils.isNoneBlank(groupName)) {
                addUsersInGroup(groupName, users);
            }

            return users;
        } catch (XWikiException e) {
            logger.error(e.getFullMessage());
        } finally {
            connection.close();
            context.setWikiId(currentWikiId);
        }
        return null;
    }

    private void setPageNameFormatter(XWikiLDAPConfig configuration)
    {
        String pageNameFormatter = getLDAPImportConfiguration().getStringValue("pageNameFormatter");
        if (StringUtils.isNoneBlank(pageNameFormatter)) {
            configuration.setFinalProperty("ldap_userPageName", pageNameFormatter);
        }
    }

    private BaseObject getLDAPImportConfiguration()
    {
        XWikiContext context = contextProvider.get();
        XWikiDocument importConfigDoc;
        try {
            importConfigDoc = context.getWiki().getDocument(CONFIGURATION_REFERENCE, context);
            BaseObject importConfigObj = importConfigDoc.getXObject(CONFIGURATION_CLASS_REFERENCE);
            return importConfigObj;
        } catch (XWikiException e) {
            logger.warn("Failed to get LDAP Import configuration document [{}].", CONFIGURATION_REFERENCE, e);
        }
        return null;
    }

    /**
     * This method handles the creation of the XWiki.OIDC.UserClass object in user profile. The subject property should
     * be populated according to a mapping between the LDAP user attribute and OIDC subject format. The default mapping
     * is (OIDC) subject = (LDAP) uid. Example: if the LDAP uid is sAMAccountName, then the value from this field will
     * be stored in the OIDC subject. TODO: Provide flexibility to accept other field/formatter for the mapping.
     * 
     * @param userDoc the new created user profile document
     * @param subject the user UID to be stored in the OIDC subject property
     * @param context the main wiki context, to make sure the users are updated on the main wiki
     */
    private void addOIDCObject(XWikiDocument userDoc, String subject, XWikiContext context)
    {
        try {
            BaseObject oIDCObj = userDoc.newXObject(OIDC_CLASS, context);
            oIDCObj.setStringValue("subject", subject);
            context.getWiki().saveDocument(userDoc, "OIDC user object added.", context);
        } catch (XWikiException e) {
            logger.warn("Failed to attach OIDC object of [{}] type to the [{}] user profile.", OIDC_CLASS, userDoc, e);
        }
    }

    private void addUsersInGroup(String groupName, SortedMap<String, Map<String, String>> users) throws XWikiException
    {
        XWikiContext context = contextProvider.get();
        DocumentReference groupReference = documentReferenceResolver.resolve(groupName);
        XWikiDocument groupDocument = context.getWiki().getDocument(groupReference, context);
        for (Entry<String, Map<String, String>> user : users.entrySet()) {
            BaseObject memberObject = groupDocument.newXObject(GROUP_CLASS_REFERENCE, context);
            memberObject.setStringValue("member", user.getValue().get(USER_PROFILE_KEY));
            context.getWiki().saveDocument(groupDocument, context);
        }
    }

    @Override
    public boolean hasImport()
    {
        String value = getLDAPImportConfiguration().getStringValue("usersAllowedToImport");
        boolean hasImport = false;

        // Check if the current user is global admin.
        if (value.equals("globalAdmin") || StringUtils.isAllEmpty(value)) {
            hasImport = contextualAuthorizationManager.hasAccess(Right.ADMIN, GLOBAL_PREFERENCES);
        }

        // Check if the current user is local admin.
        if (!hasImport && value.equals("localAdmin")) {
            hasImport = contextualAuthorizationManager.hasAccess(Right.ADMIN);
        }

        // Check if the current user has edit right on the current group.
        if (!hasImport && value.equals("groupEditor")) {
            hasImport = contextualAuthorizationManager.hasAccess(Right.EDIT);
        }
        return hasImport;
    }

    private ConfigurationSource getConfigurationSource()
    {
        String activeDirectoryHint = "activedirectory";
        if (componentManagerProvider.get().hasComponent(ConfigurationSource.class, activeDirectoryHint)) {
            try {
                return componentManagerProvider.get().getInstance(ConfigurationSource.class, activeDirectoryHint);
            } catch (ComponentLookupException e) {
                logger.error("Failed to get [{}] configuration source. Using the default LDAP configuration source",
                    activeDirectoryHint, e);
            }
        }
        return configurationSource;
    }
}
